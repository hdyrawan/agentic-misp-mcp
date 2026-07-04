from __future__ import annotations

import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from agentic_misp_mcp.config_check import format_validation_error_lines, validate_audit_log_path
from agentic_misp_mcp.policy.approval_store import ApprovalStoreError, SqliteApprovalStore
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
    if settings.approval_mode != "production":
        result.checks.append(
            DoctorCheck(
                "PASS", "Approval store check skipped (AGENTIC_MISP_MCP_APPROVAL_MODE=lab)."
            )
        )
        return
    try:
        SqliteApprovalStore(settings.approval_store_path)
    except (ApprovalStoreError, OSError) as exc:
        result.checks.append(
            DoctorCheck(
                "FAIL",
                f"AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is unusable in production mode: {exc}",
            )
        )
        return
    result.checks.append(
        DoctorCheck(
            "PASS",
            "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH is writable with safe permissions.",
        )
    )


def _check_audit_log(settings: Settings, result: ConfigDoctorResult) -> None:
    error = validate_audit_log_path(settings.audit_log_path)
    if error:
        result.checks.append(
            DoctorCheck("FAIL", f"AGENTIC_MISP_MCP_AUDIT_LOG_PATH is unusable: {error}")
        )
        return
    unsafe = _unsafe_permissions_reason(settings.audit_log_path, check_group=False)
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
    resolved = str(path.expanduser())
    return any(resolved.startswith(prefix) for prefix in TEMP_PATH_PREFIXES)


def _unsafe_permissions_reason(path: Path, *, check_group: bool = True) -> str | None:
    """Flag world-writable paths as unsafe; group-writable only when `check_group` is set.

    Group-writable is common (and often intentional, for a shared service group) for audit
    log directories under a typical non-zero umask, so only the audit log check treats it as
    advisory rather than unsafe. The approval store is a stricter HITL security boundary and
    always checks group-writability too (see `policy/approval_store.py`).
    """
    bits = (stat.S_IWGRP | stat.S_IWOTH) if check_group else stat.S_IWOTH
    descriptor = "group/world" if check_group else "world"
    resolved = path.expanduser()
    parent = resolved.parent
    if parent.exists():
        parent_mode = stat.S_IMODE(parent.stat().st_mode)
        if parent_mode & bits:
            return f"parent directory is {descriptor} writable: {parent}"
    if resolved.exists():
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if mode & bits:
            return f"file is {descriptor} writable: {resolved}"
    return None


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
    return 1 if result.has_failures else 0
