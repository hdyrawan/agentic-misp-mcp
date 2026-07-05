from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.find_events_by_tag import _event_summary


async def search_events_workflow(
    client: MISPClient,
    settings: Settings,
    date_from: str | None = None,
    date_to: str | None = None,
    published: bool | None = None,
    org: str | None = None,
    limit: int | None = 20,
) -> dict[str, object]:
    resolved_limit = settings.clamp_limit(limit)
    cleaned_org = org.strip() if isinstance(org, str) and org.strip() else None
    events = await client.search_events(
        date_from=date_from,
        date_to=date_to,
        published=published,
        org=cleaned_org,
        limit=resolved_limit,
    )

    return {
        "filters": {
            "date_from": date_from,
            "date_to": date_to,
            "published": published,
            "org": cleaned_org,
        },
        "event_count": len(events),
        "events": [_event_summary(event) for event in events],
        "limit": resolved_limit,
    }
