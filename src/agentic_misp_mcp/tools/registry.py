from __future__ import annotations

from typing import Any

from agentic_misp_mcp.audit import AuditLogger, audit_call
from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.policy import Action, PolicyEngine, enforce_policy
from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore
from agentic_misp_mcp.policy.guardrails import (
    enforce_attribute_guardrails,
    enforce_tag_guardrails,
)
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow
from agentic_misp_mcp.workflows.controlled_write import (
    add_sighting_with_approval_workflow,
    propose_attribute_workflow,
    propose_event_workflow,
    publish_event_with_approval_workflow,
    submit_ioc_with_approval_workflow,
    tag_event_with_approval_workflow,
)
from agentic_misp_mcp.workflows.explain_event_context import explain_event_context_workflow
from agentic_misp_mcp.workflows.extract_event_iocs import extract_event_iocs_workflow
from agentic_misp_mcp.workflows.find_events_by_tag import find_events_by_tag_workflow
from agentic_misp_mcp.workflows.find_related_iocs import find_related_iocs_workflow
from agentic_misp_mcp.workflows.generate_event_report import generate_event_report_workflow
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow
from agentic_misp_mcp.workflows.generate_markdown_event_report import (
    generate_markdown_event_report_workflow,
)
from agentic_misp_mcp.workflows.generate_markdown_ioc_report import (
    generate_markdown_ioc_report_workflow,
)
from agentic_misp_mcp.workflows.get_ioc_sightings import get_ioc_sightings_workflow
from agentic_misp_mcp.workflows.get_misp_status import get_misp_status_workflow
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow
from agentic_misp_mcp.workflows.pivot_ioc import pivot_ioc_workflow
from agentic_misp_mcp.workflows.search_events import search_events_workflow
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
    "generate_event_report",
    "generate_markdown_ioc_report",
    "generate_markdown_event_report",
    "get_ioc_sightings",
    "search_events",
    "get_misp_status",
    "propose_event",
    "propose_attribute",
    "submit_ioc_with_approval",
    "add_sighting_with_approval",
    "tag_event_with_approval",
    "publish_event_with_approval",
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
    """Register only approved v0.1-Phase 8 tools through the shared audit wrapper."""

    policy_engine = PolicyEngine.from_settings(settings)
    approval_store = (
        SqliteApprovalStore(settings.approval_store_path)
        if settings.approval_mode == "production"
        else None
    )

    async def _audit_read_tool(
        audit: AuditLogger, tool_name: str, arguments: dict[str, object], call: Any
    ) -> Any:
        decision = policy_engine.decide(tool_name=tool_name, action=Action.READ)
        enforce_policy(decision)
        return await audit_call(audit, tool_name, arguments, call, policy_decision=decision)

    async def _audit_write_tool(
        tool_name: str,
        action: Action,
        arguments: dict[str, object],
        make_call: Any,
    ) -> Any:
        """Evaluate policy for a controlled write tool and audit the outcome.

        Unlike `_audit_read_tool`, a disallowed decision does not raise. Write tools always
        return a structured blocked/proposal/pending_approval/executed result so that no
        write ever happens silently and every outcome (including blocks) is audited.
        """
        decision = policy_engine.decide(tool_name=tool_name, action=action)
        return await audit_call(
            audit_logger,
            tool_name,
            arguments,
            lambda: make_call(decision),
            policy_decision=decision,
        )

    async def search_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Search MISP for an IOC and return normalized attribute matches."""
        return await _audit_read_tool(
            audit_logger,
            "search_ioc",
            {"value": value, "limit": limit},
            lambda: search_ioc_workflow(client, settings, value, limit),
        )

    async def investigate_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Investigate an IOC using MISP matches, related events, tags, and warninglists."""
        return await _audit_read_tool(
            audit_logger,
            "investigate_ioc",
            {"value": value, "limit": limit},
            lambda: investigate_ioc_workflow(client, settings, value, limit),
        )

    async def summarize_event(event_id: int) -> dict[str, object]:
        """Summarize a MISP event without returning full raw event JSON."""
        return await _audit_read_tool(
            audit_logger,
            "summarize_event",
            {"event_id": event_id},
            lambda: summarize_event_workflow(client, settings, event_id),
        )

    async def check_warninglists(value: str) -> dict[str, object]:
        """Check an IOC against MISP warninglists when available."""
        return await _audit_read_tool(
            audit_logger,
            "check_warninglists",
            {"value": value},
            lambda: check_warninglists_workflow(client, value),
        )

    async def generate_ioc_report(value: str) -> dict[str, object]:
        """Generate a deterministic analyst report for an IOC."""
        return await _audit_read_tool(
            audit_logger,
            "generate_ioc_report",
            {"value": value},
            lambda: generate_ioc_report_workflow(client, settings, value),
        )

    async def pivot_ioc(value: str, limit: int = 20) -> dict[str, object]:
        """Pivot from an IOC to related events and indicators useful for hunting."""
        return await _audit_read_tool(
            audit_logger,
            "pivot_ioc",
            {"value": value, "limit": limit},
            lambda: pivot_ioc_workflow(client, settings, value, limit),
        )

    async def find_related_iocs(value: str, limit: int = 20) -> dict[str, object]:
        """Return a focused, ranked list of IOCs related to the given IOC."""
        return await _audit_read_tool(
            audit_logger,
            "find_related_iocs",
            {"value": value, "limit": limit},
            lambda: find_related_iocs_workflow(client, settings, value, limit),
        )

    async def extract_event_iocs(event_id: int, limit: int = 100) -> dict[str, object]:
        """Extract supported IOC types from a MISP event, grouped and deduplicated."""
        return await _audit_read_tool(
            audit_logger,
            "extract_event_iocs",
            {"event_id": event_id, "limit": limit},
            lambda: extract_event_iocs_workflow(client, settings, event_id, limit),
        )

    async def explain_event_context(event_id: int) -> dict[str, object]:
        """Explain what a MISP event represents in deterministic, analyst-friendly language."""
        return await _audit_read_tool(
            audit_logger,
            "explain_event_context",
            {"event_id": event_id},
            lambda: explain_event_context_workflow(client, settings, event_id),
        )

    async def find_events_by_tag(tag: str, limit: int = 20) -> dict[str, object]:
        """Find MISP events associated with a tag."""
        return await _audit_read_tool(
            audit_logger,
            "find_events_by_tag",
            {"tag": tag, "limit": limit},
            lambda: find_events_by_tag_workflow(client, settings, tag, limit),
        )

    async def get_ioc_sightings(value: str, limit: int = 50) -> dict[str, object]:
        """Return bounded sighting summaries for an IOC."""
        return await _audit_read_tool(
            audit_logger,
            "get_ioc_sightings",
            {"value": value, "limit": limit},
            lambda: get_ioc_sightings_workflow(client, settings, value, limit),
        )

    async def search_events(
        date_from: str | None = None,
        date_to: str | None = None,
        published: bool | None = None,
        org: str | None = None,
        limit: int = 20,
    ) -> dict[str, object]:
        """Discover MISP events by bounded date, publication state, and org filters."""
        return await _audit_read_tool(
            audit_logger,
            "search_events",
            {
                "date_from": date_from,
                "date_to": date_to,
                "published": published,
                "org": org,
                "limit": limit,
            },
            lambda: search_events_workflow(
                client,
                settings,
                date_from=date_from,
                date_to=date_to,
                published=published,
                org=org,
                limit=limit,
            ),
        )

    async def get_misp_status() -> dict[str, object]:
        """Return MISP version and warninglist read capability status."""
        return await _audit_read_tool(
            audit_logger,
            "get_misp_status",
            {},
            lambda: get_misp_status_workflow(client),
        )

    async def generate_event_report(event_id: int) -> dict[str, object]:
        """Generate a deterministic, structured analyst report for a MISP event."""
        return await _audit_read_tool(
            audit_logger,
            "generate_event_report",
            {"event_id": event_id},
            lambda: generate_event_report_workflow(client, settings, event_id),
        )

    async def generate_markdown_ioc_report(value: str) -> str:
        """Generate a Markdown-formatted IOC report suitable for SOC documentation."""
        return await _audit_read_tool(
            audit_logger,
            "generate_markdown_ioc_report",
            {"value": value},
            lambda: generate_markdown_ioc_report_workflow(client, settings, value),
        )

    async def generate_markdown_event_report(event_id: int) -> str:
        """Generate a Markdown-formatted MISP event report suitable for SOC escalation."""
        return await _audit_read_tool(
            audit_logger,
            "generate_markdown_event_report",
            {"event_id": event_id},
            lambda: generate_markdown_event_report_workflow(client, settings, event_id),
        )

    async def propose_event(
        info: str,
        distribution: int = 0,
        threat_level_id: int = 4,
        analysis: int = 0,
        tags: list[str] | None = None,
    ) -> dict[str, object]:
        """Build a MISP event creation proposal. Never writes to MISP."""
        return await _audit_write_tool(
            "propose_event",
            Action.WRITE,
            {
                "info": info,
                "distribution": distribution,
                "threat_level_id": threat_level_id,
                "analysis": analysis,
                "tags": tags or [],
            },
            lambda decision: propose_event_workflow(
                decision,
                info=info,
                distribution=distribution,
                threat_level_id=threat_level_id,
                analysis=analysis,
                tags=tags,
            ),
        )

    async def propose_attribute(
        event_id: int,
        type: str,
        value: str,
        category: str | None = None,
        comment: str | None = None,
        to_ids: bool | None = None,
    ) -> dict[str, object]:
        """Build an attribute creation proposal for an existing event. Never writes to MISP."""
        return await _audit_write_tool(
            "propose_attribute",
            Action.WRITE,
            {
                "event_id": event_id,
                "type": type,
                "value": value,
                "category": category,
                "comment": comment,
                "to_ids": to_ids,
            },
            lambda decision: propose_attribute_workflow(
                decision,
                event_id=event_id,
                type=type,
                value=value,
                category=category,
                comment=comment,
                to_ids=to_ids,
            ),
        )

    async def submit_ioc_with_approval(
        event_id: int,
        type: str,
        value: str,
        category: str | None = None,
        comment: str | None = None,
        to_ids: bool | None = None,
        approved: bool = False,
        approval_token: str | None = None,
        approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Submit an IOC (attribute) to MISP only when write is enabled, role permits write,
        and approval (when required) has been explicitly given. Otherwise returns a
        blocked/proposal result."""
        return await _audit_write_tool(
            "submit_ioc_with_approval",
            Action.WRITE,
            {
                "event_id": event_id,
                "type": type,
                "value": value,
                "category": category,
                "comment": comment,
                "to_ids": to_ids,
                "approved": approved,
                "approval_token": approval_token,
                "approval_request_id": approval_request_id,
            },
            lambda decision: submit_ioc_with_approval_workflow(
                client,
                decision,
                event_id=event_id,
                type=type,
                value=value,
                category=category,
                comment=comment,
                to_ids=to_ids,
                approved=approved,
                approval_token=approval_token,
                expected_approval_token=settings.approval_token,
                approval_mode=settings.approval_mode,
                approval_request_id=approval_request_id,
                approval_store=approval_store,
                approval_ttl_seconds=settings.approval_ttl_seconds,
                guardrail=enforce_attribute_guardrails(
                    attribute_type=type,
                    category=category,
                    allowed_types=settings.allowed_attribute_types,
                    allowed_categories=settings.allowed_attribute_categories,
                ),
            ),
        )

    async def add_sighting_with_approval(
        value: str | None = None,
        event_id: int | None = None,
        attribute_id: str | None = None,
        sighting_type: str = "0",
        source: str | None = None,
        approved: bool = False,
        approval_token: str | None = None,
        approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Add a sighting to MISP only when policy and approval allow. Otherwise returns a
        blocked/proposal result."""
        return await _audit_write_tool(
            "add_sighting_with_approval",
            Action.WRITE,
            {
                "value": value,
                "event_id": event_id,
                "attribute_id": attribute_id,
                "sighting_type": sighting_type,
                "source": source,
                "approved": approved,
                "approval_token": approval_token,
                "approval_request_id": approval_request_id,
            },
            lambda decision: add_sighting_with_approval_workflow(
                client,
                decision,
                value=value,
                event_id=event_id,
                attribute_id=attribute_id,
                sighting_type=sighting_type,
                source=source,
                approved=approved,
                approval_token=approval_token,
                expected_approval_token=settings.approval_token,
                approval_mode=settings.approval_mode,
                approval_request_id=approval_request_id,
                approval_store=approval_store,
                approval_ttl_seconds=settings.approval_ttl_seconds,
            ),
        )

    async def tag_event_with_approval(
        event_id: int,
        tag: str,
        approved: bool = False,
        approval_token: str | None = None,
        approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Tag a MISP event only when policy and approval allow. Otherwise returns a
        blocked/proposal result."""
        return await _audit_write_tool(
            "tag_event_with_approval",
            Action.WRITE,
            {
                "event_id": event_id,
                "tag": tag,
                "approved": approved,
                "approval_token": approval_token,
                "approval_request_id": approval_request_id,
            },
            lambda decision: tag_event_with_approval_workflow(
                client,
                decision,
                event_id=event_id,
                tag=tag,
                approved=approved,
                approval_token=approval_token,
                expected_approval_token=settings.approval_token,
                approval_mode=settings.approval_mode,
                approval_request_id=approval_request_id,
                approval_store=approval_store,
                approval_ttl_seconds=settings.approval_ttl_seconds,
                guardrail=enforce_tag_guardrails(tag=tag, allowed_tags=settings.allowed_tags),
            ),
        )

    async def publish_event_with_approval(
        event_id: int,
        approved: bool = False,
        approval_token: str | None = None,
        approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Publish a MISP event only when policy and approval allow. Requires curator/
        admin-like permission and is always high-risk and approval-gated. Otherwise returns
        a blocked/proposal result."""
        return await _audit_write_tool(
            "publish_event_with_approval",
            Action.PUBLISH,
            {
                "event_id": event_id,
                "approved": approved,
                "approval_token": approval_token,
                "approval_request_id": approval_request_id,
            },
            lambda decision: publish_event_with_approval_workflow(
                client,
                decision,
                event_id=event_id,
                approved=approved,
                approval_token=approval_token,
                expected_approval_token=settings.approval_token,
                approval_mode=settings.approval_mode,
                approval_request_id=approval_request_id,
                approval_store=approval_store,
                approval_ttl_seconds=settings.approval_ttl_seconds,
            ),
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
    _register(mcp, "generate_event_report", generate_event_report)
    _register(mcp, "generate_markdown_ioc_report", generate_markdown_ioc_report)
    _register(mcp, "generate_markdown_event_report", generate_markdown_event_report)
    _register(mcp, "get_ioc_sightings", get_ioc_sightings)
    _register(mcp, "search_events", search_events)
    _register(mcp, "get_misp_status", get_misp_status)
    _register(mcp, "propose_event", propose_event)
    _register(mcp, "propose_attribute", propose_attribute)
    _register(mcp, "submit_ioc_with_approval", submit_ioc_with_approval)
    _register(mcp, "add_sighting_with_approval", add_sighting_with_approval)
    _register(mcp, "tag_event_with_approval", tag_event_with_approval)
    _register(mcp, "publish_event_with_approval", publish_event_with_approval)
