from __future__ import annotations

from typing import Any

from agentic_misp_mcp.audit import AuditLogger, audit_call
from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow
from agentic_misp_mcp.workflows.search_ioc import search_ioc_workflow
from agentic_misp_mcp.workflows.summarize_event import summarize_event_workflow

ALLOWED_TOOL_NAMES = {
    "search_ioc",
    "investigate_ioc",
    "summarize_event",
    "check_warninglists",
    "generate_ioc_report",
}


def _register(mcp: Any, name: str, func: Any) -> None:
    registered = getattr(mcp, "_agentic_tool_names", set())
    registered.add(name)
    mcp._agentic_tool_names = registered
    decorator = mcp.tool(name=name) if callable(getattr(mcp, "tool", None)) else None
    if decorator is None:
        raise TypeError("MCP object does not provide a tool() registration method")
    decorator(func)


def register_tools(
    mcp: Any,
    *,
    client: MISPClient,
    settings: Settings,
    audit_logger: AuditLogger,
) -> None:
    """Register only approved v0.1 tools through the shared audit wrapper."""

    async def search_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Search MISP for an IOC and return normalized attribute matches."""
        return await audit_call(
            audit_logger,
            "search_ioc",
            {"value": value, "limit": limit},
            lambda: search_ioc_workflow(client, settings, value, limit),
        )

    async def investigate_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Investigate an IOC using MISP matches, related events, tags, and warninglists."""
        return await audit_call(
            audit_logger,
            "investigate_ioc",
            {"value": value, "limit": limit},
            lambda: investigate_ioc_workflow(client, settings, value, limit),
        )

    async def summarize_event(event_id: int) -> dict[str, object]:
        """Summarize a MISP event without returning full raw event JSON."""
        return await audit_call(
            audit_logger,
            "summarize_event",
            {"event_id": event_id},
            lambda: summarize_event_workflow(client, settings, event_id),
        )

    async def check_warninglists(value: str) -> dict[str, object]:
        """Check an IOC against MISP warninglists when available."""
        return await audit_call(
            audit_logger,
            "check_warninglists",
            {"value": value},
            lambda: check_warninglists_workflow(client, value),
        )

    async def generate_ioc_report(value: str) -> dict[str, object]:
        """Generate a deterministic analyst report for an IOC."""
        return await audit_call(
            audit_logger,
            "generate_ioc_report",
            {"value": value},
            lambda: generate_ioc_report_workflow(client, settings, value),
        )

    _register(mcp, "search_ioc", search_ioc)
    _register(mcp, "investigate_ioc", investigate_ioc)
    _register(mcp, "summarize_event", summarize_event)
    _register(mcp, "check_warninglists", check_warninglists)
    _register(mcp, "generate_ioc_report", generate_ioc_report)
