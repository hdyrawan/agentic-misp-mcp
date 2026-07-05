from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow
from agentic_misp_mcp.workflows.event_context import (
    build_event_references,
    collect_tags,
    expand_related_events,
    select_related_event_ids,
)
from agentic_misp_mcp.workflows.investigation_engine import build_investigation_enrichment


async def investigate_ioc_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)

    related_event_ids = select_related_event_ids(
        event_ids=[match.event_id for match in matches], limit=settings.misp_related_event_limit
    )
    related_events = await expand_related_events(client, settings, related_event_ids)

    warninglists = await check_warninglists_workflow(client, ioc.value)
    tags = collect_tags(matches=matches, related_events=related_events)
    enrichment = build_investigation_enrichment(
        primary_ioc=ioc.value,
        matches=matches,
        related_events=related_events,
        warninglists=warninglists,
        tags=tags,
        settings=settings,
    )
    assessment_summary = _build_assessment_summary(
        seen_in_misp=bool(matches),
        warninglists=warninglists,
        verdict=enrichment["verdict"],
        confidence_score=enrichment["confidence_score"],
    )
    raw_references = build_event_references(
        settings=settings, event_ids=[match.event_id for match in matches]
    )

    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "verdict": enrichment["verdict"],
        "verdict_reason": enrichment["verdict_reason"],
        "confidence": enrichment["confidence"],
        "confidence_score": enrichment["confidence_score"],
        "confidence_reasons": enrichment["confidence_reasons"],
        "match_count": len(matches),
        "freshness": enrichment["freshness"],
        "related_events": related_events,
        "related_iocs": enrichment["related_iocs"],
        "warninglists": {
            "status": warninglists.get("status"),
            "hit": bool(warninglists.get("hit")),
            "matches": warninglists.get("matches") or [],
        },
        "context": enrichment["context"],
        "assessment_summary": assessment_summary,
        "recommended_next_steps": enrichment["recommended_next_steps"],
        "raw_references": raw_references,
    }


def _build_assessment_summary(
    *,
    seen_in_misp: bool,
    warninglists: dict[str, object],
    verdict: str,
    confidence_score: int,
) -> str:
    summary = "IOC was found in MISP." if seen_in_misp else "IOC was not found in MISP."
    if warninglists.get("hit"):
        summary += " It also appears on a warninglist, so it may be benign/common infrastructure."
    summary += f" Deterministic verdict: {verdict} (score {confidence_score}/100)."
    return summary
