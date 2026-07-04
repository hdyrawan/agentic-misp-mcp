from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings


async def summarize_event_workflow(
    client: MISPClient, settings: Settings, event_id: int
) -> dict[str, object]:
    event = await client.get_event(event_id, attribute_limit=settings.misp_event_attribute_limit)
    return {
        "event": {
            "id": event.id,
            "info": event.info,
            "date": event.date,
            "threat_level_id": event.threat_level_id,
            "analysis": event.analysis,
            "distribution": event.distribution,
            "tags": event.tags,
        },
        "attribute_count": event.attribute_count,
        "attributes_returned": len(event.attributes),
        "attribute_limit": settings.misp_event_attribute_limit,
        "attributes_by_type": event.attributes_by_type,
        "key_attributes": [
            attribute.model_dump(exclude_none=True) for attribute in event.attributes
        ],
    }
