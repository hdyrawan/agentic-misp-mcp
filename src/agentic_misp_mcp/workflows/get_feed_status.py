from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.feed_health import feed_status


async def get_feed_status_workflow(
    client: MISPClient, settings: Settings, feed_id: int | str
) -> dict[str, object]:
    raw = await client.get_feed(feed_id)
    return feed_status(raw, settings)
