from __future__ import annotations

from typing import Any

from agentic_misp_mcp.audit import AuditLogger, audit_call
from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow
from agentic_misp_mcp.workflows.explain_event_context import explain_event_context_workflow
from agentic_misp_mcp.workflows.extract_event_iocs import extract_event_iocs_workflow
from agentic_misp_mcp.workflows.find_events_by_tag import find_events_by_tag_workflow
from agentic_misp_mcp.workflows.find_related_iocs import find_related_iocs_workflow
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow
from agentic_misp_mcp.workflows.pivot_ioc import pivot_ioc_workflow
from agentic_misp_mcp.workflows.search_ioc import search_ioc_workflow
from agentic_misp_mcp.workflows.summarize_event import summarize_event_workflow

ALLOWED_TOOL_NAMES = {
    "search_ioc",
    "investigate_ioc",
    "summarize_event",
    "check_warninglists",
    "generate_ioc_report",
    "pivot_ioc",
    "find_related_iocs",
    "extract_event_iocs",
    "explain_event_context",
    "find_events_by_tag",
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
    """Register only approved v0.1/Phase 2/Phase 3 tools through the shared audit wrapper."""

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

    async def pivot_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Pivot from an IOC to related events and indicators useful for hunting."""
        return await audit_call(
            audit_logger,
            "pivot_ioc",
            {"value": value, "limit": limit},
            lambda: pivot_ioc_workflow(client, settings, value, limit),
        )

    async def find_related_iocs(value: str, limit: int = 20) -> dict[str, object]:
        """Return a focused, ranked list of IOCs related to the given IOC."""
        return await audit_call(
            audit_logger,
            "find_related_iocs",
            {"value": value, "limit": limit},
            lambda: find_related_iocs_workflow(client, settings, value, limit),
        )

    async def extract_event_iocs(event_id: int, limit: int = 100) -> dict[str, object]:
        """Extract supported IOC types from a MISP event, grouped and deduplicated."""
        return await audit_call(
            audit_logger,
            "extract_event_iocs",
            {"event_id": event_id, "limit": limit},
            lambda: extract_event_iocs_workflow(client, settings, event_id, limit),
        )

    async def explain_event_context(event_id: int) -> dict[str, object]:
        """Explain what a MISP event represents in deterministic, analyst-friendly language."""
        return await audit_call(
            audit_logger,
            "explain_event_context",
            {"event_id": event_id},
            lambda: explain_event_context_workflow(client, settings, event_id),
        )

    async def find_events_by_tag(tag: str, limit: int = 20) -> dict[str, object]:
        """Find MISP events associated with a tag."""
        return await audit_call(
            audit_logger,
            "find_events_by_tag",
            {"tag": tag, "limit": limit},
            lambda: find_events_by_tag_workflow(client, settings, tag, limit),
        )

    _register(mcp, "search_ioc", search_ioc)
    _register(mcp, "investigate_ioc", investigate_ioc)
    _register(mcp, "summarize_event", summarize_event)
    _register(mcp, "check_warninglists", check_warninglists)
    _register(mcp, "generate_ioc_report", generate_ioc_report)
    _register(mcp, "pivot_ioc", pivot_ioc)
    _register(mcp, "find_related_iocs", find_related_iocs)
    _register(mcp, "extract_event_iocs", extract_event_iocs)
    _register(mcp, "explain_event_context", explain_event_context)
    _register(mcp, "find_events_by_tag", find_events_by_tag)
