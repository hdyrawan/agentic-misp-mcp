from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.security.sanitization import safe_error_message
from agentic_misp_mcp.settings import Settings

THREAT_LEVEL_LABELS = {
    "1": "High",
    "2": "Medium",
    "3": "Low",
    "4": "Undefined",
}
ANALYSIS_LABELS = {
    "0": "Initial",
    "1": "Ongoing",
    "2": "Completed",
}


def select_related_event_ids(*, event_ids: list[int | None], limit: int) -> list[int]:
    """Deduplicate and bound a list of event ids, preserving first-seen order."""
    related_event_ids: list[int] = []
    for event_id in event_ids:
        if event_id is not None and event_id not in related_event_ids:
            related_event_ids.append(event_id)
    return related_event_ids[:limit]


async def expand_related_events(
    client: MISPClient, settings: Settings, related_event_ids: list[int]
) -> list[dict[str, Any]]:
    """Fetch bounded event summaries for a list of event ids.

    Individual event fetch failures are captured as an error entry so callers can
    keep partial investigation context instead of aborting the whole workflow.
    """
    related_events: list[dict[str, Any]] = []
    for event_id in related_event_ids:
        try:
            event = await client.get_event(
                event_id, attribute_limit=settings.misp_event_attribute_limit
            )
        except Exception as exc:  # noqa: BLE001 - preserve partial context on per-event failure.
            related_events.append(
                {"id": event_id, "status": "error", "message": safe_error_message(exc)}
            )
            continue
        related_events.append(
            {
                "id": event.id,
                "info": event.info,
                "date": event.date,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "publish_timestamp": (
                    event.publish_timestamp.isoformat() if event.publish_timestamp else None
                ),
                "published": event.published,
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


def collect_tags(*, matches: list[Any], related_events: list[dict[str, Any]]) -> list[str]:
    tags = {tag for match in matches for tag in match.tags}
    for event in related_events:
        for tag in event.get("tags") or []:
            tags.add(str(tag))
        for attribute in event.get("key_attributes") or []:
            if isinstance(attribute, dict):
                for tag in attribute.get("tags") or []:
                    tags.add(str(tag))
    return sorted(tags)


def build_event_references(
    *, settings: Settings, event_ids: list[int | None]
) -> list[dict[str, object]]:
    """Bounded, read-only pointers into the MISP UI for the given event ids.

    These are plain reference URLs, not a raw-API proxy: no event JSON is fetched
    or returned here.
    """
    base_url = settings.misp_base_url
    unique_ids = sorted({event_id for event_id in event_ids if event_id is not None})
    return [
        {"type": "event", "id": event_id, "url": f"{base_url}/events/view/{event_id}"}
        for event_id in unique_ids
    ]
