from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.feed_health import summarize_feed


async def list_feeds_workflow(
    client: MISPClient,
    settings: Settings,
    limit: int | None = 50,
    enabled: bool | None = None,
) -> dict[str, object]:
    resolved_limit = settings.clamp_limit(limit)
    feeds = await client.list_feeds(resolved_limit, enabled=enabled)
    return {
        "feed_count": len(feeds),
        "feeds": [summarize_feed(feed) for feed in feeds],
        "filters": {"enabled": enabled},
        "limit": resolved_limit,
    }
