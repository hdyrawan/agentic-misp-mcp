from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow


async def investigate_ioc_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)

    related_event_ids: list[int] = []
    for match in matches:
        if match.event_id is not None and match.event_id not in related_event_ids:
            related_event_ids.append(match.event_id)
    related_event_ids = related_event_ids[: settings.misp_related_event_limit]

    related_events = []
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

    warninglists = await check_warninglists_workflow(client, ioc.value)
    tags = sorted({tag for match in matches for tag in match.tags})
    assessment = _build_assessment(bool(matches), warninglists, len(related_events))

    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "limit": resolved_limit,
        "match_count": len(matches),
        "matches": [match.model_dump(exclude_none=True) for match in matches],
        "related_events_returned": len(related_events),
        "related_event_limit": settings.misp_related_event_limit,
        "related_events": related_events,
        "warninglists": warninglists,
        "tags": tags,
        "assessment": assessment,
        "recommended_next_steps": _next_steps(bool(matches), bool(warninglists.get("hit"))),
    }


def _build_assessment(
    seen_in_misp: bool, warninglists: dict[str, object], related_event_count: int
) -> dict[str, object]:
    warninglist_hit = bool(warninglists.get("hit"))
    if warninglists.get("status") == "not_available":
        confidence = "medium" if seen_in_misp else "low"
    elif warninglist_hit and not seen_in_misp:
        confidence = "low"
    elif seen_in_misp and not warninglist_hit:
        confidence = "medium" if related_event_count else "low"
    else:
        confidence = "low"
    summary = "IOC was found in MISP." if seen_in_misp else "IOC was not found in MISP."
    if warninglist_hit:
        summary += " It also appears on a warninglist, so it may be benign/common infrastructure."
    return {
        "seen_in_misp": seen_in_misp,
        "likely_noise": warninglist_hit,
        "confidence": confidence,
        "summary": summary,
    }


def _next_steps(seen_in_misp: bool, warninglist_hit: bool) -> list[str]:
    steps = []
    if seen_in_misp:
        steps.append("Review related MISP events and tags for campaign, malware, or actor context.")
    else:
        steps.append("Corroborate the IOC with external telemetry before escalating.")
    if warninglist_hit:
        steps.append("Validate whether the IOC is expected/common infrastructure before alerting.")
    else:
        steps.append("Check sightings or local telemetry for recent activity involving this IOC.")
    return steps
