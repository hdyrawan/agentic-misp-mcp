from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from agentic_misp_mcp.audit import sanitize_for_audit
from agentic_misp_mcp.policy.models import (
    ApprovalRedemptionError,
    ApprovalStatus,
    ApprovalStoreError,
    Role,
    StoredApprovalRecord,
)

TERMINAL_STATUSES = {
    ApprovalStatus.USED,
    ApprovalStatus.REJECTED,
    ApprovalStatus.EXPIRED,
}


class ApprovalStore(Protocol):
    def create(
        self,
        *,
        tool_name: str,
        operation_hash: str,
        proposed_arguments: dict[str, Any],
        role: str,
        ttl_seconds: int,
    ) -> StoredApprovalRecord: ...

    def get(self, request_id: str) -> StoredApprovalRecord | None: ...

    def list(self, status: ApprovalStatus | str | None = None) -> list[StoredApprovalRecord]: ...

    def approve(
        self, request_id: str, *, approved_by: str | None = None
    ) -> StoredApprovalRecord: ...

    def reject(self, request_id: str, *, reason: str) -> StoredApprovalRecord: ...

    def redeem(
        self, request_id: str, *, tool_name: str, operation_hash: str
    ) -> StoredApprovalRecord: ...

    def expire_stale(self, *, now: datetime | None = None) -> int: ...


class InMemoryApprovalStore:
    """Small approval store for tests and non-production unit checks."""

    def __init__(self) -> None:
        self.records: dict[str, StoredApprovalRecord] = {}

    def create(
        self,
        *,
        tool_name: str,
        operation_hash: str,
        proposed_arguments: dict[str, Any],
        role: str,
        ttl_seconds: int,
    ) -> StoredApprovalRecord:
        now = datetime.now(timezone.utc)  # noqa: UP017
        record = StoredApprovalRecord(
            request_id=str(uuid4()),
            tool_name=tool_name,
            operation_hash=operation_hash,
            proposed_arguments=_safe_proposed_arguments(proposed_arguments),
            role=Role(str(role)),
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self.records[record.request_id] = record
        return record

    def get(self, request_id: str) -> StoredApprovalRecord | None:
        record = self.records.get(request_id)
        return self._with_lazy_expiry(record) if record else None

    def list(self, status: ApprovalStatus | str | None = None) -> list[StoredApprovalRecord]:
        self.expire_stale()
        records = list(self.records.values())
        if status is not None:
            status_value = ApprovalStatus(str(status))
            records = [record for record in records if record.status is status_value]
        return sorted(records, key=lambda record: record.created_at)

    def approve(self, request_id: str, *, approved_by: str | None = None) -> StoredApprovalRecord:
        record = self._require_record(request_id)
        record = self._with_lazy_expiry(record)
        if record.status is not ApprovalStatus.PENDING:
            raise ApprovalStoreError(f"approval {request_id} is {record.status.value}")
        updated = record.model_copy(
            update={
                "status": ApprovalStatus.APPROVED,
                "approved_at": datetime.now(timezone.utc),  # noqa: UP017
                "approved_by": approved_by,
            }
        )
        self.records[request_id] = updated
        return updated

    def reject(self, request_id: str, *, reason: str) -> StoredApprovalRecord:
        record = self._require_record(request_id)
        record = self._with_lazy_expiry(record)
        if record.status in TERMINAL_STATUSES:
            raise ApprovalStoreError(f"approval {request_id} is {record.status.value}")
        updated = record.model_copy(
            update={
                "status": ApprovalStatus.REJECTED,
                "rejected_at": datetime.now(timezone.utc),  # noqa: UP017
                "rejected_reason": reason,
            }
        )
        self.records[request_id] = updated
        return updated

    def redeem(
        self, request_id: str, *, tool_name: str, operation_hash: str
    ) -> StoredApprovalRecord:
        record = self._require_record_for_redeem(request_id, tool_name, operation_hash)
        updated = record.model_copy(
            update={"status": ApprovalStatus.USED, "used_at": datetime.now(timezone.utc)}  # noqa: UP017
        )
        self.records[request_id] = updated
        return updated

    def expire_stale(self, *, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)  # noqa: UP017
        count = 0
        for request_id, record in list(self.records.items()):
            if (
                record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
                and record.expires_at <= now
            ):
                self.records[request_id] = record.model_copy(
                    update={"status": ApprovalStatus.EXPIRED}
                )
                count += 1
        return count

    def _with_lazy_expiry(self, record: StoredApprovalRecord) -> StoredApprovalRecord:
        if (
            record.status in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}
            and record.expires_at <= datetime.now(timezone.utc)  # noqa: UP017
        ):
            record = record.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self.records[record.request_id] = record
        return record

    def _require_record(self, request_id: str) -> StoredApprovalRecord:
        record = self.get(request_id)
        if record is None:
            raise ApprovalStoreError(f"approval {request_id} not found")
        return record

    def _require_record_for_redeem(
        self, request_id: str, tool_name: str, operation_hash: str
    ) -> StoredApprovalRecord:
        record = self.get(request_id)
        if record is None:
            raise ApprovalRedemptionError(ApprovalStatus.NOT_FOUND)
        status = _redemption_failure_status(
            record, tool_name=tool_name, operation_hash=operation_hash
        )
        if status is not None:
            raise ApprovalRedemptionError(status)
        return record


class SqliteApprovalStore:
    """SQLite-backed production approval store with atomic one-time redemption."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser()
        _enforce_safe_store_path(self.path)
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _enforce_safe_store_path(self.path)
        self._initialize()

    def create(
        self,
        *,
        tool_name: str,
        operation_hash: str,
        proposed_arguments: dict[str, Any],
        role: str,
        ttl_seconds: int,
    ) -> StoredApprovalRecord:
        now = datetime.now(timezone.utc)  # noqa: UP017
        record = StoredApprovalRecord(
            request_id=str(uuid4()),
            tool_name=tool_name,
            operation_hash=operation_hash,
            proposed_arguments=_safe_proposed_arguments(proposed_arguments),
            role=Role(str(role)),
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (
                    request_id, tool_name, operation_hash, proposed_arguments, role, status,
                    created_at, expires_at, approved_at, approved_by, used_at, rejected_at,
                    rejected_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _record_to_row(record),
            )
        return record

    def get(self, request_id: str) -> StoredApprovalRecord | None:
        self.expire_stale()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE request_id = ?", (request_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def list(self, status: ApprovalStatus | str | None = None) -> list[StoredApprovalRecord]:
        self.expire_stale()
        with self._connect() as conn:
            if status is None:
                rows = conn.execute("SELECT * FROM approvals ORDER BY created_at").fetchall()
            else:
                status_value = ApprovalStatus(str(status)).value
                rows = conn.execute(
                    "SELECT * FROM approvals WHERE status = ? ORDER BY created_at",
                    (status_value,),
                ).fetchall()
        return [_row_to_record(row) for row in rows]

    def approve(self, request_id: str, *, approved_by: str | None = None) -> StoredApprovalRecord:
        self.expire_stale()
        now = _format_dt(datetime.now(timezone.utc))  # noqa: UP017
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?, approved_at = ?, approved_by = ?
                WHERE request_id = ? AND status = ? AND expires_at > ?
                """,
                (
                    ApprovalStatus.APPROVED.value,
                    now,
                    approved_by,
                    request_id,
                    ApprovalStatus.PENDING.value,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                raise ApprovalStoreError(f"approval {request_id} cannot be approved")
        record = self.get(request_id)
        if record is None:
            raise ApprovalStoreError(f"approval {request_id} not found")
        return record

    def reject(self, request_id: str, *, reason: str) -> StoredApprovalRecord:
        self.expire_stale()
        now = _format_dt(datetime.now(timezone.utc))  # noqa: UP017
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?, rejected_at = ?, rejected_reason = ?
                WHERE request_id = ? AND status IN (?, ?)
                """,
                (
                    ApprovalStatus.REJECTED.value,
                    now,
                    reason,
                    request_id,
                    ApprovalStatus.PENDING.value,
                    ApprovalStatus.APPROVED.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ApprovalStoreError(f"approval {request_id} cannot be rejected")
        record = self.get(request_id)
        if record is None:
            raise ApprovalStoreError(f"approval {request_id} not found")
        return record

    def redeem(
        self, request_id: str, *, tool_name: str, operation_hash: str
    ) -> StoredApprovalRecord:
        self.expire_stale()
        now = _format_dt(datetime.now(timezone.utc))  # noqa: UP017
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?, used_at = ?
                WHERE request_id = ?
                  AND status = ?
                  AND tool_name = ?
                  AND operation_hash = ?
                  AND expires_at > ?
                """,
                (
                    ApprovalStatus.USED.value,
                    now,
                    request_id,
                    ApprovalStatus.APPROVED.value,
                    tool_name,
                    operation_hash,
                    now,
                ),
            )
            if cursor.rowcount == 1:
                row = conn.execute(
                    "SELECT * FROM approvals WHERE request_id = ?", (request_id,)
                ).fetchone()
                return _row_to_record(row)
            row = conn.execute(
                "SELECT * FROM approvals WHERE request_id = ?", (request_id,)
            ).fetchone()
        if row is None:
            raise ApprovalRedemptionError(ApprovalStatus.NOT_FOUND)
        status = _redemption_failure_status(
            _row_to_record(row), tool_name=tool_name, operation_hash=operation_hash
        )
        raise ApprovalRedemptionError(status or ApprovalStatus.NOT_YET_APPROVED)

    def expire_stale(self, *, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)  # noqa: UP017
        formatted = _format_dt(now)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE approvals
                SET status = ?
                WHERE status IN (?, ?) AND expires_at <= ?
                """,
                (
                    ApprovalStatus.EXPIRED.value,
                    ApprovalStatus.PENDING.value,
                    ApprovalStatus.APPROVED.value,
                    formatted,
                ),
            )
            return cursor.rowcount

    def prune(
        self, *, older_than_seconds: int, vacuum: bool = False, now: datetime | None = None
    ) -> int:
        """Delete old terminal (used/rejected/expired) records. Never touches pending/approved.

        Operator-CLI-only maintenance; not reachable through any MCP tool.
        """
        self.expire_stale(now=now)
        now = now or datetime.now(timezone.utc)  # noqa: UP017
        cutoff = _format_dt(now - timedelta(seconds=older_than_seconds))
        with self._connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM approvals
                WHERE (status = ? AND used_at IS NOT NULL AND used_at <= ?)
                   OR (status = ? AND rejected_at IS NOT NULL AND rejected_at <= ?)
                   OR (status = ? AND expires_at <= ?)
                """,
                (
                    ApprovalStatus.USED.value,
                    cutoff,
                    ApprovalStatus.REJECTED.value,
                    cutoff,
                    ApprovalStatus.EXPIRED.value,
                    cutoff,
                ),
            )
            deleted = cursor.rowcount
        if vacuum:
            # VACUUM cannot run inside a pending transaction, so use a fresh connection
            # after the delete above has already been committed.
            with self._connect() as conn:
                conn.execute("VACUUM")
        return deleted

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    request_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    operation_hash TEXT NOT NULL,
                    proposed_arguments TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    approved_at TEXT,
                    approved_by TEXT,
                    used_at TEXT,
                    rejected_at TEXT,
                    rejected_reason TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status)")
        os.chmod(self.path, 0o600)
        _enforce_safe_store_path(self.path)

    def _connect(self) -> sqlite3.Connection:
        _enforce_safe_store_path(self.path)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn


def _safe_proposed_arguments(proposed_arguments: dict[str, Any]) -> dict[str, Any]:
    sanitized = sanitize_for_audit(proposed_arguments)
    return sanitized if isinstance(sanitized, dict) else {}


def _record_to_row(record: StoredApprovalRecord) -> tuple[Any, ...]:
    return (
        record.request_id,
        record.tool_name,
        record.operation_hash,
        json.dumps(record.proposed_arguments, sort_keys=True, default=str),
        record.role.value,
        record.status.value,
        _format_dt(record.created_at),
        _format_dt(record.expires_at),
        _format_dt(record.approved_at),
        record.approved_by,
        _format_dt(record.used_at),
        _format_dt(record.rejected_at),
        record.rejected_reason,
    )


def _row_to_record(row: sqlite3.Row) -> StoredApprovalRecord:
    return StoredApprovalRecord(
        request_id=str(row["request_id"]),
        tool_name=str(row["tool_name"]),
        operation_hash=str(row["operation_hash"]),
        proposed_arguments=json.loads(str(row["proposed_arguments"])),
        role=Role(str(row["role"])),
        status=ApprovalStatus(str(row["status"])),
        created_at=_parse_dt(str(row["created_at"])),
        expires_at=_parse_dt(str(row["expires_at"])),
        approved_at=_parse_optional_dt(row["approved_at"]),
        approved_by=row["approved_by"],
        used_at=_parse_optional_dt(row["used_at"]),
        rejected_at=_parse_optional_dt(row["rejected_at"]),
        rejected_reason=row["rejected_reason"],
    )


def _redemption_failure_status(
    record: StoredApprovalRecord, *, tool_name: str, operation_hash: str
) -> ApprovalStatus | None:
    if record.tool_name != tool_name:
        return ApprovalStatus.WRONG_TOOL
    if record.operation_hash != operation_hash:
        return ApprovalStatus.HASH_MISMATCH
    if record.status is ApprovalStatus.USED:
        return ApprovalStatus.ALREADY_USED
    if record.status is ApprovalStatus.REJECTED:
        return ApprovalStatus.REJECTED
    if record.status is ApprovalStatus.EXPIRED or record.expires_at <= datetime.now(timezone.utc):  # noqa: UP017
        return ApprovalStatus.EXPIRED
    if record.status is ApprovalStatus.PENDING:
        return ApprovalStatus.NOT_YET_APPROVED
    if record.status is not ApprovalStatus.APPROVED:
        return ApprovalStatus.NOT_YET_APPROVED
    return None


def _format_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat()


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _parse_optional_dt(value: str | None) -> datetime | None:
    return _parse_dt(value) if value else None


def _enforce_safe_store_path(path: Path) -> None:
    parent = path.parent
    if parent.exists():
        parent_mode = stat.S_IMODE(parent.stat().st_mode)
        if parent_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ApprovalStoreError(
                f"approval store parent directory is group/world writable: {parent}"
            )
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ApprovalStoreError(f"approval store database is group/world writable: {path}")
