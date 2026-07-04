from __future__ import annotations

import argparse
import json
import sys

from pydantic import ValidationError

from agentic_misp_mcp.config_check import format_validation_error_lines
from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore
from agentic_misp_mcp.policy.models import ApprovalStatus, ApprovalStoreError, StoredApprovalRecord
from agentic_misp_mcp.settings import Settings


def add_approvals_subparser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    approvals = subparsers.add_parser(
        "approvals",
        help="Administer production approval requests from the operator CLI.",
    )
    approval_commands = approvals.add_subparsers(dest="approvals_command", required=True)

    list_parser = approval_commands.add_parser("list", help="List approval requests.")
    list_parser.add_argument(
        "--status",
        choices=[status.value for status in ApprovalStatus if _is_lifecycle_status(status)],
        help="Filter by lifecycle status.",
    )

    show_parser = approval_commands.add_parser("show", help="Show one approval request.")
    show_parser.add_argument("request_id")

    approve_parser = approval_commands.add_parser("approve", help="Approve a pending request.")
    approve_parser.add_argument("request_id")
    approve_parser.add_argument("--approved-by", default=None)

    reject_parser = approval_commands.add_parser(
        "reject", help="Reject a pending or approved request."
    )
    reject_parser.add_argument("request_id")
    reject_parser.add_argument("--reason", required=True)

    prune_parser = approval_commands.add_parser(
        "prune",
        help=(
            "Delete old terminal (used/rejected/expired) approval records. Never removes "
            "pending or approved records. CLI-only; not exposed through any MCP tool."
        ),
    )
    prune_parser.add_argument(
        "--older-than",
        required=True,
        help="Age threshold for terminal records, e.g. 30d, 7d, 24h, or 3600s.",
    )
    prune_parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run SQLite VACUUM after deleting rows to reclaim disk space.",
    )


def handle_approvals_command(args: argparse.Namespace) -> int:
    try:
        settings = Settings()
        store = SqliteApprovalStore(settings.approval_store_path)
    except ValidationError as exc:
        lines = "\n".join(format_validation_error_lines(exc))
        sys.stderr.write(f"Configuration error:\n{lines}\n")
        return 2
    except ApprovalStoreError as exc:
        sys.stderr.write(f"Approval store error: {exc}\n")
        return 2

    try:
        if args.approvals_command == "list":
            rows = store.list(status=args.status)
            for record in rows:
                sys.stdout.write(_render_compact(record) + "\n")
            return 0
        if args.approvals_command == "show":
            record = store.get(args.request_id)
            if record is None:
                sys.stderr.write("Approval request not found\n")
                return 1
            sys.stdout.write(
                json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
            )
            return 0
        if args.approvals_command == "approve":
            record = store.approve(args.request_id, approved_by=args.approved_by)
            sys.stdout.write(_render_compact(record) + "\n")
            return 0
        if args.approvals_command == "reject":
            record = store.reject(args.request_id, reason=args.reason)
            sys.stdout.write(_render_compact(record) + "\n")
            return 0
        if args.approvals_command == "prune":
            try:
                older_than_seconds = parse_duration(args.older_than)
            except ValueError as exc:
                sys.stderr.write(f"Invalid --older-than value: {exc}\n")
                return 2
            deleted = store.prune(older_than_seconds=older_than_seconds, vacuum=args.vacuum)
            suffix = " (vacuumed)" if args.vacuum else ""
            sys.stdout.write(f"Pruned {deleted} approval record(s){suffix}\n")
            return 0
    except ApprovalStoreError as exc:
        sys.stderr.write(f"Approval store error: {exc}\n")
        return 1
    sys.stderr.write("Unknown approvals command\n")
    return 2


def parse_duration(value: str) -> int:
    """Parse a duration like '30d', '7d', '24h', or '3600s' into whole seconds.

    Supported suffixes: `s` (seconds), `h` (hours), `d` (days). Requires an explicit suffix
    so callers cannot accidentally pass a bare, ambiguous integer.
    """
    stripped = value.strip().lower()
    if len(stripped) < 2:
        raise ValueError(f"duration must include a unit suffix (s/h/d): {value!r}")
    suffix = stripped[-1]
    amount_text = stripped[:-1]
    multipliers = {"s": 1, "h": 3600, "d": 86400}
    if suffix not in multipliers:
        raise ValueError(f"unsupported duration suffix {suffix!r} in {value!r}; use s, h, or d")
    if not amount_text.isdigit():
        raise ValueError(f"invalid duration amount in {value!r}")
    amount = int(amount_text)
    if amount < 0:
        raise ValueError(f"duration must not be negative: {value!r}")
    return amount * multipliers[suffix]


def _is_lifecycle_status(status: ApprovalStatus) -> bool:
    return status in {
        ApprovalStatus.PENDING,
        ApprovalStatus.APPROVED,
        ApprovalStatus.USED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.EXPIRED,
    }


def _render_compact(record: StoredApprovalRecord) -> str:
    return (
        f"{record.request_id} {record.status.value} {record.tool_name} "
        f"expires={record.expires_at.isoformat()} hash={record.operation_hash}"
    )
