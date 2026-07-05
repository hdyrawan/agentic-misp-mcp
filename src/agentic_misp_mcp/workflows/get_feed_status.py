from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.feed_health import feed_status


async def get_feed_status_workflow(
    client: MISPClient, settings: Settings, feed_id: int
) -> dict[str, object]:
    # feed_id lands in the request path (/feeds/view/<id>); require a positive integer
    # here rather than trusting the tool-layer annotation alone.
    if isinstance(feed_id, bool) or not isinstance(feed_id, int) or feed_id <= 0:
        raise ValueError("feed_id must be a positive integer")
    raw = await client.get_feed(feed_id)
    return feed_status(raw, settings)
