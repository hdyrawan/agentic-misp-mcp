from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import build_event_references
from agentic_misp_mcp.workflows.investigation_engine import classify_tags
from agentic_misp_mcp.workflows.ioc_extraction import extract_iocs_by_type


async def extract_event_iocs_workflow(
    client: MISPClient, settings: Settings, event_id: int, limit: int | None = 100
) -> dict[str, object]:
    resolved_limit = settings.clamp_limit(limit)
    event = await client.get_event(event_id, attribute_limit=resolved_limit)

    iocs_by_type = extract_iocs_by_type(event.attributes)
    ioc_count = sum(len(values) for values in iocs_by_type.values())
    notable_tags = classify_tags(event.tags)["notable_tags"]
    raw_references = build_event_references(settings=settings, event_ids=[event.id])

    return {
        "event_id": event.id,
        "event_info": event.info,
        "ioc_count": ioc_count,
        "iocs_by_type": iocs_by_type,
        "notable_tags": notable_tags,
        "raw_references": raw_references,
    }
