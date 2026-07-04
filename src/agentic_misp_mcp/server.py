from __future__ import annotations

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.tools.registry import register_tools


def create_server(settings: Settings | None = None):
    """Create and configure the FastMCP server."""
    from fastmcp import FastMCP

    resolved_settings = settings or Settings()
    mcp = FastMCP("agentic-misp-mcp")
    client = MISPClient(resolved_settings)
    audit_logger = AuditLogger(resolved_settings.audit_log_path)
    register_tools(mcp, client=client, settings=resolved_settings, audit_logger=audit_logger)
    return mcp


def run_server(transport: str = "stdio") -> None:
    mcp = create_server()
    if transport == "http":
        # FastMCP HTTP transport support differs by version. Try the straightforward path
        # without adding v0.1-specific HTTP server configuration.
        mcp.run(transport="http")
        return
    mcp.run(transport="stdio")
