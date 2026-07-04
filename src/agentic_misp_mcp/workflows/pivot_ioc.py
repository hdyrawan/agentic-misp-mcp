from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import (
    build_event_references,
    collect_tags,
    expand_related_events,
    select_related_event_ids,
)
from agentic_misp_mcp.workflows.investigation_engine import classify_tags, extract_related_iocs


async def pivot_ioc_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)

    related_event_ids = select_related_event_ids(
        event_ids=[match.event_id for match in matches], limit=settings.misp_related_event_limit
    )
    related_events = await expand_related_events(client, settings, related_event_ids)

    tags = collect_tags(matches=matches, related_events=related_events)
    context = classify_tags(tags)
    related_iocs = extract_related_iocs(
        primary_ioc=ioc.value, related_events=related_events, max_iocs=resolved_limit
    )

    pivot_summary = _build_pivot_summary(
        source_match_count=len(matches),
        related_event_count=len(related_events),
        related_ioc_count=len(related_iocs),
    )
    recommended_pivots = _build_recommended_pivots(context=context, related_iocs=related_iocs)
    raw_references = build_event_references(
        settings=settings, event_ids=[match.event_id for match in matches]
    )

    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "source_match_count": len(matches),
        "related_event_count": len(related_events),
        "related_events": related_events,
        "related_iocs": related_iocs,
        "context": context,
        "pivot_summary": pivot_summary,
        "recommended_pivots": recommended_pivots,
        "raw_references": raw_references,
    }


def _build_pivot_summary(
    *, source_match_count: int, related_event_count: int, related_ioc_count: int
) -> str:
    if source_match_count == 0:
        return "IOC was not found in MISP; no pivot events are available."
    return (
        f"Found {source_match_count} MISP match(es) across {related_event_count} related "
        f"event(s), yielding {related_ioc_count} related indicator(s) for pivoting."
    )


def _build_recommended_pivots(
    *, context: dict[str, list[str]], related_iocs: list[dict[str, Any]]
) -> list[str]:
    pivots: list[str] = []
    if related_iocs:
        pivots.append("Pivot on extracted related IOCs to expand the hunt.")
    if context["possible_malware_families"]:
        pivots.append(
            "Search MISP for other events tagged with the identified malware family/families."
        )
    if context["possible_threat_actors"]:
        pivots.append("Search MISP for other events attributed to the identified threat actor(s).")
    if context["possible_campaigns"]:
        pivots.append("Search MISP for other events linked to the identified campaign(s).")
    if context["mitre_attack"]:
        pivots.append("Cross-reference identified MITRE ATT&CK techniques with detection coverage.")
    if not pivots:
        pivots.append("No further pivot context available; corroborate with external telemetry.")
    return pivots
