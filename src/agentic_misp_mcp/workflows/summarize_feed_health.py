from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.feed_health import FEED_HEALTH_LABELS, feed_status


async def summarize_feed_health_workflow(
    client: MISPClient, settings: Settings, limit: int | None = 100
) -> dict[str, object]:
    resolved_limit = settings.clamp_limit(limit)
    feeds = await client.list_feeds(resolved_limit, enabled=None)
    groups: dict[str, list[dict[str, object]]] = {label: [] for label in FEED_HEALTH_LABELS}
    malformed_count = 0
    for feed in feeds:
        try:
            status = feed_status(feed, settings)
        except Exception:
            malformed_count += 1
            groups["error"].append(
                {
                    "feed_id": None,
                    "name": None,
                    "health_label": "error",
                    "warnings": ["feed metadata could not be parsed"],
                }
            )
            continue
        label = str(status.get("health_label") or "unknown")
        if label not in groups:
            label = "unknown"
        groups[label].append(
            {
                "feed_id": status.get("feed_id"),
                "name": status.get("name"),
                "provider": status.get("provider"),
                "enabled": status.get("enabled"),
                "age_days_since_fetch": status.get("age_days_since_fetch"),
                "age_days_since_cache": status.get("age_days_since_cache"),
                "warnings": status.get("warnings", []),
            }
        )

    return {
        "feed_count": len(feeds),
        "malformed_count": malformed_count,
        "groups": groups,
        "counts": {label: len(items) for label, items in groups.items()},
        "limit": resolved_limit,
    }
