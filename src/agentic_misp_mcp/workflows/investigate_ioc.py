from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow
from agentic_misp_mcp.workflows.investigation_engine import build_investigation_enrichment


async def investigate_ioc_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)

    related_event_ids = _select_related_event_ids(
        matches=[match.event_id for match in matches], limit=settings.misp_related_event_limit
    )
    related_events = await _expand_related_events(client, settings, related_event_ids)

    warninglists = await check_warninglists_workflow(client, ioc.value)
    tags = _collect_tags(matches=matches, related_events=related_events)
    enrichment = build_investigation_enrichment(
        primary_ioc=ioc.value,
        matches=matches,
        related_events=related_events,
        warninglists=warninglists,
        tags=tags,
    )
    assessment_summary = _build_assessment_summary(
        seen_in_misp=bool(matches),
        warninglists=warninglists,
        verdict=enrichment["verdict"],
        confidence_score=enrichment["confidence_score"],
    )
    raw_references = _build_raw_references(settings=settings, matches=matches)

    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "verdict": enrichment["verdict"],
        "verdict_reason": enrichment["verdict_reason"],
        "confidence": enrichment["confidence"],
        "confidence_score": enrichment["confidence_score"],
        "confidence_reasons": enrichment["confidence_reasons"],
        "match_count": len(matches),
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


def _select_related_event_ids(matches: list[int | None], limit: int) -> list[int]:
    related_event_ids: list[int] = []
    for event_id in matches:
        if event_id is not None and event_id not in related_event_ids:
            related_event_ids.append(event_id)
    return related_event_ids[:limit]


async def _expand_related_events(
    client: MISPClient, settings: Settings, related_event_ids: list[int]
) -> list[dict[str, Any]]:
    related_events: list[dict[str, Any]] = []
    for event_id in related_event_ids:
        try:
            event = await client.get_event(
                event_id, attribute_limit=settings.misp_event_attribute_limit
            )
        except Exception as exc:  # noqa: BLE001 - preserve investigation with partial event context.
            related_events.append({"id": event_id, "status": "error", "message": str(exc)})
            continue
        related_events.append(
            {
                "id": event.id,
                "info": event.info,
                "date": event.date,
                "threat_level_id": event.threat_level_id,
                "analysis": event.analysis,
                "tags": event.tags,
                "attribute_count": event.attribute_count,
                "attributes_returned": len(event.attributes),
                "attribute_limit": settings.misp_event_attribute_limit,
                "attributes_by_type": event.attributes_by_type,
                "key_attributes": [item.model_dump(exclude_none=True) for item in event.attributes],
            }
        )
    return related_events


def _collect_tags(matches: list[Any], related_events: list[dict[str, Any]]) -> list[str]:
    tags = {tag for match in matches for tag in match.tags}
    for event in related_events:
        for tag in event.get("tags") or []:
            tags.add(str(tag))
        for attribute in event.get("key_attributes") or []:
            if isinstance(attribute, dict):
                for tag in attribute.get("tags") or []:
                    tags.add(str(tag))
    return sorted(tags)


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


def _build_raw_references(*, settings: Settings, matches: list[Any]) -> list[dict[str, object]]:
    base_url = settings.misp_base_url
    event_ids = sorted({match.event_id for match in matches if match.event_id is not None})
    return [
        {"type": "event", "id": event_id, "url": f"{base_url}/events/view/{event_id}"}
        for event_id in event_ids
    ]
