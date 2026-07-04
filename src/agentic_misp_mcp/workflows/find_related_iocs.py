from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import expand_related_events, select_related_event_ids
from agentic_misp_mcp.workflows.pivoting import rank_related_iocs


async def find_related_iocs_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)

    related_event_ids = select_related_event_ids(
        event_ids=[match.event_id for match in matches], limit=settings.misp_related_event_limit
    )
    related_events = await expand_related_events(client, settings, related_event_ids)

    related_iocs = rank_related_iocs(
        primary_ioc=ioc.value, related_events=related_events, limit=resolved_limit
    )

    return {
        "source_ioc": {"value": ioc.value, "type": ioc.type.value},
        "related_iocs": related_iocs,
        "count": len(related_iocs),
        "limit": resolved_limit,
    }
