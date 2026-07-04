from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from agentic_misp_mcp.config_check import format_validation_error_lines, validate_audit_log_path
from agentic_misp_mcp.security.permissions import unsafe_permissions_reason
from agentic_misp_mcp.settings import Settings

LONG_APPROVAL_TTL_SECONDS = 14_400  # 4 hours; longer widens the operator review/replay window.
TEMP_PATH_PREFIXES = (
    str(Path(tempfile.gettempdir())),
    "/tmp",  # noqa: S108 - detecting temp paths, not using one
    "/var/tmp",  # noqa: S108
)


@dataclass
class DoctorCheck:
    level: str  # "PASS", "WARN", or "FAIL"
    message: str


@dataclass
class ConfigDoctorResult:
    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return any(check.level == "FAIL" for check in self.checks)

    def render(self) -> str:
        summary = "FAIL" if self.has_failures else "PASS"
        lines = [f"{check.level} {check.message}" for check in self.checks]
        return "\n".join([f"Config doctor: {summary}", *lines]) + "\n"


def run_config_doctor(settings: Settings) -> ConfigDoctorResult:
    """Validate operational-readiness combinations beyond basic `config-check`.

    Never connects to MISP and never prints secret values (`MISP_API_KEY`,
    `AGENTIC_MISP_MCP_APPROVAL_TOKEN`) — only their presence/absence.
    """
    result = ConfigDoctorResult()
    _check_tls(settings, result)
    _check_write_and_approval_mode(settings, result)
    _check_publish(settings, result)
    _check_approval_store(settings, result)
    _check_audit_log(settings, result)
    _check_allowlists(settings, result)
    _check_approval_ttl(settings, result)
    _check_temp_paths(settings, result)
    _check_approval_token(settings, result)
    return result


def _check_tls(settings: Settings, result: ConfigDoctorResult) -> None:
    if settings.misp_verify_tls:
        result.checks.append(DoctorCheck("PASS", "MISP_VERIFY_TLS is enabled."))
    else:
        result.checks.append(
            DoctorCheck(
                "WARN",
                "MISP_VERIFY_TLS is false; TLS verification is disabled. "
                "Lab-only; never use against a real MISP instance.",
            )
        )


def _check_write_and_approval_mode(settings: Settings, result: ConfigDoctorResult) -> None:
    if not settings.enable_write:
        result.checks.append(
            DoctorCheck("PASS", "AGENTIC_MISP_MCP_ENABLE_WRITE is false (read-only deployment).")
        )
        return
    if settings.approval_mode != "production":
        result.checks.append(
            DoctorCheck(
                "FAIL",
                "AGENTIC_MISP_MCP_ENABLE_WRITE is true but AGENTIC_MISP_MCP_APPROVAL_MODE is "
                f"'{settings.approval_mode}'. Write-enabled deployments require "
                "AGENTIC_MISP_MCP_APPROVAL_MODE=production; lab approval mode is not sufficient.",
            )
        )
        return
    result.checks.append(
        DoctorCheck(
            "PASS",
            "AGENTIC_MISP_MCP_ENABLE_WRITE is true with AGENTIC_MISP_MCP_APPROVAL_MODE=production.",
        )
    )


def _check_publish(settings: Settings, result: ConfigDoctorResult) -> None:
    if not settings.enable_publish:
        result.checks.append(
            DoctorCheck("PASS", "AGENTIC_MISP_MCP_ENABLE_PUBLISH is false (default kill switch).")
        )
        return
    if settings.policy_role not in {"curator", "admin"}:
        result.checks.append(
            DoctorCheck(
                "FAIL",
                "AGENTIC_MISP_MCP_ENABLE_PUBLISH is true but AGENTIC_MISP_MCP_ROLE is "
                f"'{settings.policy_role}'. Publish requires a curator or admin role.",
            )
        )
        return
    result.checks.append(
        DoctorCheck(
            "WARN",
            "AGENTIC_MISP_MCP_ENABLE_PUBLISH is true. Publish is high-risk and not reversible "
            "by this project (see docs/rollback.md); confirm this is an intentional, "
            "explicitly sign-off curator/admin publish deployment.",
        )
    )


def _check_approval_store(settings: Settings, result: ConfigDoctorResult) -> None:
    """Validate the approval store path without creating or modifying anything on disk.

    Deliberately does not construct a `SqliteApprovalStore` — that constructor creates the
    parent directory and an empty database as a side effect, which a read-only diagnostic
    command must not do. Checks permissions, then (if the file exists) opens it read-only to
    confirm it is a usable SQLite database, catching `sqlite3.Error` broadly so a corrupted or
    non-database file at the configured path produces a clean FAIL instead of a crash.
    """
    if settings.approval_mode != "production":
        result.checks.append(
            DoctorCheck(
                "PASS", "Approval store check skipped (AGENTIC_MISP_MCP_APPROVAL_MODE=lab)."
            )
        )
        return
    path = settings.approval_store_path.expanduser()
    reason = unsafe_permissions_reason(path, check_group=True)
    if reason:
        result.checks.append(
            DoctorCheck("FAIL", f"AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is unsafe: {reason}")
        )
        return
    if path.exists():
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                # A trivial constant query like `SELECT 1` never touches the database file's
                # schema, so it would not detect a corrupt/non-SQLite file at this path.
                # Reading sqlite_master forces SQLite to actually parse the file header/schema.
                connection.execute("SELECT count(*) FROM sqlite_master")
            finally:
                connection.close()
        except sqlite3.Error as exc:
            result.checks.append(
                DoctorCheck(
                    "FAIL",
                    f"AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is not a usable SQLite database: {exc}",
                )
            )
            return
    elif not os.access((ancestor := _nearest_existing_ancestor(path)), os.W_OK):
        result.checks.append(
            DoctorCheck(
                "FAIL",
                "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH does not exist yet and its nearest "
                f"existing ancestor directory is not writable: {ancestor}",
            )
        )
        return
    result.checks.append(
        DoctorCheck(
            "PASS",
            "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is writable with safe permissions.",
        )
    )


def _nearest_existing_ancestor(path: Path) -> Path:
    ancestor = path
    while not ancestor.exists() and ancestor != ancestor.parent:
        ancestor = ancestor.parent
    return ancestor


def _check_audit_log(settings: Settings, result: ConfigDoctorResult) -> None:
    error = validate_audit_log_path(settings.audit_log_path)
    if error:
        result.checks.append(
            DoctorCheck("FAIL", f"AGENTIC_MISP_MCP_AUDIT_LOG_PATH is unusable: {error}")
        )
        return
    unsafe = unsafe_permissions_reason(settings.audit_log_path, check_group=False)
    if unsafe:
        result.checks.append(
            DoctorCheck("FAIL", f"AGENTIC_MISP_MCP_AUDIT_LOG_PATH is unsafe: {unsafe}")
        )
        return
    result.checks.append(
        DoctorCheck("PASS", "AGENTIC_MISP_MCP_AUDIT_LOG_PATH is writable with safe permissions.")
    )


def _check_allowlists(settings: Settings, result: ConfigDoctorResult) -> None:
    if not (settings.enable_write and settings.approval_mode == "production"):
        result.checks.append(
            DoctorCheck("PASS", "Allowlist check skipped (not a production write deployment).")
        )
        return
    if settings.allowed_attribute_types or settings.allowed_attribute_categories:
        result.checks.append(
            DoctorCheck("PASS", "Attribute type/category allowlist is configured.")
        )
    else:
        result.checks.append(
            DoctorCheck(
                "WARN",
                "No AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES/_CATEGORIES configured for a "
                "production write deployment; consider adding an allowlist as defense in depth.",
            )
        )
    if settings.allowed_tags:
        result.checks.append(DoctorCheck("PASS", "Tag allowlist is configured."))
    else:
        result.checks.append(
            DoctorCheck(
                "WARN",
                "No AGENTIC_MISP_MCP_ALLOWED_TAGS configured for a production write "
                "deployment; consider adding an allowlist as defense in depth.",
            )
        )


def _check_approval_ttl(settings: Settings, result: ConfigDoctorResult) -> None:
    if settings.approval_ttl_seconds > LONG_APPROVAL_TTL_SECONDS:
        result.checks.append(
            DoctorCheck(
                "WARN",
                f"AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS={settings.approval_ttl_seconds} is "
                f"longer than {LONG_APPROVAL_TTL_SECONDS}s; consider a shorter TTL for tighter "
                "operator review windows.",
            )
        )
        return
    result.checks.append(
        DoctorCheck(
            "PASS",
            f"AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS={settings.approval_ttl_seconds} is within "
            "a reasonable review window.",
        )
    )


def _check_temp_paths(settings: Settings, result: ConfigDoctorResult) -> None:
    if _looks_like_temp_path(settings.audit_log_path):
        result.checks.append(
            DoctorCheck(
                "WARN",
                "AGENTIC_MISP_MCP_AUDIT_LOG_PATH points into a temporary directory; use a "
                "persistent path in production.",
            )
        )
    else:
        result.checks.append(
            DoctorCheck("PASS", "AGENTIC_MISP_MCP_AUDIT_LOG_PATH is not a temporary path.")
        )
    if settings.approval_mode == "production":
        if _looks_like_temp_path(settings.approval_store_path):
            result.checks.append(
                DoctorCheck(
                    "WARN",
                    "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH points into a temporary directory; "
                    "use a persistent path in production.",
                )
            )
        else:
            result.checks.append(
                DoctorCheck("PASS", "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is not a temporary path.")
            )


def _check_approval_token(settings: Settings, result: ConfigDoctorResult) -> None:
    if settings.approval_mode == "production" and settings.approval_token is not None:
        result.checks.append(
            DoctorCheck(
                "WARN",
                "AGENTIC_MISP_MCP_APPROVAL_TOKEN is set ([REDACTED]) while "
                "AGENTIC_MISP_MCP_APPROVAL_MODE=production. Production approval uses "
                "approval_request_id, not a shared token; this leftover value is not the "
                "production approval mechanism and can be removed.",
            )
        )
        return
    result.checks.append(DoctorCheck("PASS", "Approval token configuration looks appropriate."))


def _looks_like_temp_path(path: Path) -> bool:
    """Return True when `path` is under one of `TEMP_PATH_PREFIXES`.

    Compares path components (via `Path.parents`), not raw string prefixes, so a sibling
    directory that merely shares a string prefix (e.g. `/tmporary-data`) is not misclassified
    as living under `/tmp`.
    """
    resolved = path.expanduser()
    return any(
        resolved == Path(prefix) or Path(prefix) in resolved.parents
        for prefix in TEMP_PATH_PREFIXES
    )


def run_config_doctor_cli() -> int:
    try:
        settings = Settings()
    except ValidationError as exc:
        lines = "\n".join(format_validation_error_lines(exc))
        sys.stderr.write(f"Configuration error:\n{lines}\n")
        return 2
    result = run_config_doctor(settings)
    stream = sys.stderr if result.has_failures else sys.stdout
    stream.write(result.render())
    # Match config-check's exit-code convention (0 ok, 2 configuration is bad) so a pipeline
    # gate written for one command behaves the same for the other.
    return 2 if result.has_failures else 0
