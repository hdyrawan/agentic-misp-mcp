from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agentic_misp_mcp.policy.approval_store import ApprovalStoreError, SqliteApprovalStore
from agentic_misp_mcp.settings import Settings


@dataclass
class ConfigCheckResult:
    ok: bool
    lines: list[str] = field(default_factory=list)

    def render(self) -> str:
        status = "OK" if self.ok else "FAILED"
        return "\n".join([f"Configuration check: {status}", *self.lines]) + "\n"


def check_configuration() -> ConfigCheckResult:
    """Validate runtime configuration without connecting to MISP."""
    try:
        settings = Settings()
    except ValidationError as exc:
        return ConfigCheckResult(ok=False, lines=format_validation_error_lines(exc))

    lines = [
        f"OK MISP_URL={settings.misp_base_url}",
        "OK MISP_API_KEY is set ([REDACTED])",
        f"OK MISP_VERIFY_TLS={str(settings.misp_verify_tls).lower()}",
        f"OK MISP_TIMEOUT_SECONDS={settings.misp_timeout_seconds:g}",
        f"OK MISP_DEFAULT_LIMIT={settings.misp_default_limit}",
        f"OK MISP_MAX_LIMIT={settings.misp_max_limit}",
        f"OK MISP_EVENT_ATTRIBUTE_LIMIT={settings.misp_event_attribute_limit}",
        f"OK MISP_RELATED_EVENT_LIMIT={settings.misp_related_event_limit}",
        f"OK AGENTIC_MISP_MCP_LOG_LEVEL={settings.log_level}",
        f"OK AGENTIC_MISP_MCP_ROLE={settings.policy_role}",
        f"OK AGENTIC_MISP_MCP_ENABLE_WRITE={str(settings.enable_write).lower()}",
        f"OK AGENTIC_MISP_MCP_REQUIRE_APPROVAL={str(settings.require_approval).lower()}",
        f"OK AGENTIC_MISP_MCP_APPROVAL_MODE={settings.approval_mode}",
        f"OK AGENTIC_MISP_MCP_APPROVAL_STORE_PATH={settings.approval_store_path}",
        f"OK AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS={settings.approval_ttl_seconds}",
        f"OK AGENTIC_MISP_MCP_ENABLE_PUBLISH={str(settings.enable_publish).lower()}",
        "OK AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES="
        f"{','.join(settings.allowed_attribute_types) or 'not set'}",
        "OK AGENTIC_MISP_MCP_ALLOWED_TAGS="
        f"{','.join(settings.allowed_tags) or 'not set'}",
        "OK AGENTIC_MISP_MCP_APPROVAL_TOKEN="
        f"{'set ([REDACTED])' if settings.approval_token else 'not set'}",
        f"OK AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES={settings.max_response_bytes}",
        "OK AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND="
        f"{str(settings.allow_insecure_http_bind).lower()}",
    ]

    if settings.approval_mode == "production":
        try:
            SqliteApprovalStore(settings.approval_store_path)
        except ApprovalStoreError as exc:
            lines.append(f"ERROR AGENTIC_MISP_MCP_APPROVAL_STORE_PATH: {exc}")
            return ConfigCheckResult(ok=False, lines=lines)

    audit_error = validate_audit_log_path(settings.audit_log_path)
    if audit_error:
        lines.append(f"ERROR AGENTIC_MISP_MCP_AUDIT_LOG_PATH: {audit_error}")
        return ConfigCheckResult(ok=False, lines=lines)

    lines.append(f"OK AGENTIC_MISP_MCP_AUDIT_LOG_PATH={settings.audit_log_path}")
    return ConfigCheckResult(ok=True, lines=lines)


def validate_audit_log_path(path: Path) -> str | None:
    """Return an error string when the audit log parent is unusable."""
    parent = path.expanduser().parent
    try:
        if parent.exists() and not parent.is_dir():
            return f"parent exists but is not a directory: {parent}"
        parent.mkdir(parents=True, exist_ok=True)
        probe = parent / ".agentic-misp-mcp-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError as exc:
        return f"parent directory is not writable or cannot be created: {exc}"
    return None


def format_validation_error_lines(exc: ValidationError) -> list[str]:
    lines: list[str] = []
    for error in exc.errors(include_url=False):
        env_name = _env_name_for_error(dict(error))
        message = str(error.get("msg", "invalid value"))
        lines.append(f"ERROR {env_name}: {message}")
    return lines


def _env_name_for_error(error: dict[str, Any]) -> str:
    loc = error.get("loc") or ()
    if not loc:
        return "configuration"
    first = str(loc[0])
    return FIELD_TO_ENV.get(first, first)


FIELD_TO_ENV = {
    "misp_url": "MISP_URL",
    "MISP_URL": "MISP_URL",
    "misp_api_key": "MISP_API_KEY",
    "MISP_API_KEY": "MISP_API_KEY",
    "misp_verify_tls": "MISP_VERIFY_TLS",
    "MISP_VERIFY_TLS": "MISP_VERIFY_TLS",
    "misp_timeout_seconds": "MISP_TIMEOUT_SECONDS",
    "MISP_TIMEOUT_SECONDS": "MISP_TIMEOUT_SECONDS",
    "misp_default_limit": "MISP_DEFAULT_LIMIT",
    "MISP_DEFAULT_LIMIT": "MISP_DEFAULT_LIMIT",
    "misp_max_limit": "MISP_MAX_LIMIT",
    "MISP_MAX_LIMIT": "MISP_MAX_LIMIT",
    "misp_event_attribute_limit": "MISP_EVENT_ATTRIBUTE_LIMIT",
    "MISP_EVENT_ATTRIBUTE_LIMIT": "MISP_EVENT_ATTRIBUTE_LIMIT",
    "misp_related_event_limit": "MISP_RELATED_EVENT_LIMIT",
    "MISP_RELATED_EVENT_LIMIT": "MISP_RELATED_EVENT_LIMIT",
    "audit_log_path": "AGENTIC_MISP_MCP_AUDIT_LOG_PATH",
    "AGENTIC_MISP_MCP_AUDIT_LOG_PATH": "AGENTIC_MISP_MCP_AUDIT_LOG_PATH",
    "log_level": "AGENTIC_MISP_MCP_LOG_LEVEL",
    "AGENTIC_MISP_MCP_LOG_LEVEL": "AGENTIC_MISP_MCP_LOG_LEVEL",
    "policy_role": "AGENTIC_MISP_MCP_ROLE",
    "AGENTIC_MISP_MCP_ROLE": "AGENTIC_MISP_MCP_ROLE",
    "enable_write": "AGENTIC_MISP_MCP_ENABLE_WRITE",
    "AGENTIC_MISP_MCP_ENABLE_WRITE": "AGENTIC_MISP_MCP_ENABLE_WRITE",
    "require_approval": "AGENTIC_MISP_MCP_REQUIRE_APPROVAL",
    "AGENTIC_MISP_MCP_REQUIRE_APPROVAL": "AGENTIC_MISP_MCP_REQUIRE_APPROVAL",
    "approval_token": "AGENTIC_MISP_MCP_APPROVAL_TOKEN",
    "AGENTIC_MISP_MCP_APPROVAL_TOKEN": "AGENTIC_MISP_MCP_APPROVAL_TOKEN",
    "approval_mode": "AGENTIC_MISP_MCP_APPROVAL_MODE",
    "AGENTIC_MISP_MCP_APPROVAL_MODE": "AGENTIC_MISP_MCP_APPROVAL_MODE",
    "approval_store_path": "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH",
    "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH": "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH",
    "approval_ttl_seconds": "AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS",
    "AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS": "AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS",
    "enable_publish": "AGENTIC_MISP_MCP_ENABLE_PUBLISH",
    "AGENTIC_MISP_MCP_ENABLE_PUBLISH": "AGENTIC_MISP_MCP_ENABLE_PUBLISH",
    "allowed_attribute_types": "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES",
    "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES": "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES",
    "allowed_attribute_categories": "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES",
    "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES": "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES",
    "allowed_tags": "AGENTIC_MISP_MCP_ALLOWED_TAGS",
    "AGENTIC_MISP_MCP_ALLOWED_TAGS": "AGENTIC_MISP_MCP_ALLOWED_TAGS",
    "max_response_bytes": "AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES",
    "AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES": "AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES",
    "allow_insecure_http_bind": "AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND",
    "AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND": "AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND",
}
