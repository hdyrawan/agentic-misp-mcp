from __future__ import annotations

import ipaddress

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.config_check import validate_audit_log_path
from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.tools.registry import register_tools


class StartupConfigurationError(RuntimeError):
    """Raised when runtime configuration is invalid before server startup."""


def create_server(settings: Settings | None = None):
    """Create and configure the FastMCP server."""
    from fastmcp import FastMCP

    resolved_settings = settings or Settings()
    audit_error = validate_audit_log_path(resolved_settings.audit_log_path)
    if audit_error:
        raise StartupConfigurationError(f"Invalid AGENTIC_MISP_MCP_AUDIT_LOG_PATH: {audit_error}")

    mcp = FastMCP("agentic-misp-mcp")
    client = MISPClient(resolved_settings)
    audit_logger = AuditLogger(resolved_settings.audit_log_path)
    register_tools(mcp, client=client, settings=resolved_settings, audit_logger=audit_logger)
    return mcp


def _is_loopback_host(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip()).is_loopback
    except ValueError:
        return False


def validate_http_bind_allowed(settings: Settings, host: str) -> None:
    if not _is_loopback_host(host) and not settings.allow_insecure_http_bind:
        raise StartupConfigurationError(
            f"Refusing to bind unauthenticated HTTP transport to non-loopback host {host!r} "
            "(e.g. 0.0.0.0, ::, or a LAN address). HTTP mode has no built-in auth/TLS; use "
            "127.0.0.1 or set AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true only behind an "
            "authenticated TLS-terminating gateway."
        )


def run_server(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:
    settings = Settings()
    if transport == "http":
        validate_http_bind_allowed(settings, host)
    mcp = create_server(settings)
    if transport == "http":
        # HTTP mode is intentionally minimal/experimental for v0.1. FastMCP transport
        # keyword support can differ by version, so surface a clear runtime error.
        try:
            mcp.run(transport="http", host=host, port=port)
        except TypeError as exc:
            raise StartupConfigurationError(
                "HTTP transport is experimental and is not supported by this installed "
                "FastMCP runtime with --host/--port options. Use --transport stdio."
            ) from exc
        return
    mcp.run(transport="stdio")
