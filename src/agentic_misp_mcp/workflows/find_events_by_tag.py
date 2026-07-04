from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings

MAX_TAG_LENGTH = 256


def _validate_tag(tag: str) -> str:
    cleaned = tag.strip()
    if not cleaned:
        raise ValueError("Tag must not be blank")
    if len(cleaned) > MAX_TAG_LENGTH:
        raise ValueError(f"Tag must be <= {MAX_TAG_LENGTH} characters")
    return cleaned


async def find_events_by_tag_workflow(
    client: MISPClient, settings: Settings, tag: str, limit: int | None = 20
) -> dict[str, object]:
    cleaned_tag = _validate_tag(tag)
    resolved_limit = settings.clamp_limit(limit)
    events = await client.search_events_by_tag(cleaned_tag, resolved_limit)

    return {
        "tag": cleaned_tag,
        "event_count": len(events),
        "events": [
            {
                "event_id": event.id,
                "info": event.info,
                "date": event.date,
                "threat_level": event.threat_level_id,
                "analysis": event.analysis,
                "attribute_count": event.attribute_count,
                "tags": event.tags,
            }
            for event in events
        ],
        "limit": resolved_limit,
    }
