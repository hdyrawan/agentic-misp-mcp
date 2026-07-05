from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_misp_mcp.workflows.feed_health import feed_status, redact_feed_url
from agentic_misp_mcp.workflows.get_feed_status import get_feed_status_workflow
from agentic_misp_mcp.workflows.list_feeds import list_feeds_workflow
from agentic_misp_mcp.workflows.propose_feed_changes import propose_feed_changes_workflow
from agentic_misp_mcp.workflows.summarize_feed_health import summarize_feed_health_workflow


def _epoch_days_ago(days: int) -> str:
    return str(int((datetime.now(UTC) - timedelta(days=days)).timestamp()))


class FakeFeedClient:
    def __init__(self):
        self.mutations = []
        self.list_args = None

    async def list_feeds(self, limit, enabled=None):
        self.list_args = (limit, enabled)
        feeds = [
            {
                "Feed": {
                    "id": "1",
                    "name": "fresh",
                    "provider": "provider-a",
                    "url": "https://example.test/feed.csv?token=secret&safe=1",
                    "enabled": "1",
                    "last_fetched": _epoch_days_ago(1),
                    "cache_timestamp": _epoch_days_ago(1),
                    "headers": {"Authorization": "Bearer secret"},
                }
            },
            {
                "Feed": {
                    "id": "2",
                    "name": "stale",
                    "enabled": True,
                    "last_fetched": _epoch_days_ago(60),
                }
            },
            {"Feed": {"id": "3", "name": "disabled", "enabled": False}},
            {"Feed": {"id": "4", "name": "never", "enabled": True}},
            {
                "Feed": {
                    "id": "5",
                    "name": "cache stale",
                    "enabled": True,
                    "last_fetched": _epoch_days_ago(1),
                    "cache_timestamp": _epoch_days_ago(60),
                }
            },
            {"Feed": {"id": "6", "name": "error", "enabled": True, "last_error": "boom"}},
        ]
        if enabled is not None:
            feeds = [feed for feed in feeds if bool(feed["Feed"].get("enabled")) is enabled]
        return feeds[:limit]

    async def get_feed(self, feed_id):
        for feed in await self.list_feeds(100):
            if feed["Feed"]["id"] == str(feed_id):
                return feed
        return {"Feed": {"id": str(feed_id), "enabled": True}}


@pytest.mark.asyncio
async def test_list_feeds_is_bounded_and_redacts_sensitive_url(settings):
    client = FakeFeedClient()
    result = await list_feeds_workflow(client, settings, limit=2, enabled=True)

    assert client.list_args == (2, True)
    assert result["feed_count"] == 2
    assert result["feeds"][0]["url"] == "https://example.test/feed.csv?token=%5BREDACTED%5D&safe=1"
    assert "secret" not in str(result)


@pytest.mark.asyncio
async def test_get_feed_status_redacts_sensitive_metadata_and_labels(settings):
    result = await get_feed_status_workflow(FakeFeedClient(), settings, feed_id=1)

    assert result["health_label"] == "healthy"
    assert result["age_days_since_fetch"] is not None
    assert result["metadata"]["headers"] == "[REDACTED]"
    assert "secret" not in str(result)


@pytest.mark.asyncio
async def test_summarize_feed_health_groups_labels(settings):
    result = await summarize_feed_health_workflow(FakeFeedClient(), settings, limit=100)

    assert result["feed_count"] == 6
    assert result["counts"]["healthy"] == 1
    assert result["counts"]["stale"] == 1
    assert result["counts"]["disabled"] == 1
    assert result["counts"]["never_fetched"] == 1
    assert result["counts"]["cache_stale"] == 1
    assert result["counts"]["error"] == 1


def test_feed_status_missing_timestamps_is_never_fetched(settings):
    result = feed_status({"Feed": {"id": "7", "name": "missing", "enabled": True}}, settings)

    assert result["health_label"] == "never_fetched"
    assert result["age_days_since_fetch"] is None
    assert result["warnings"] == ["feed has no usable fetch timestamp"]


def test_redact_feed_url_handles_credentials_and_query_secrets():
    redacted = redact_feed_url("https://user:pass@example.test/feed?authkey=abc&foo=bar")

    assert redacted.startswith("https://")
    assert "@example.test/feed" in redacted
    assert "foo=bar" in redacted
    assert "pass" not in redacted
    assert "abc" not in redacted


@pytest.mark.asyncio
async def test_propose_feed_changes_is_dry_run_only():
    result = await propose_feed_changes_workflow(goal="improve lookup")

    assert result["status"] == "proposal_only"
    assert result["requires_operator_approval"] is True
    assert result["mutates_misp"] is False
    assert {item["action"] for item in result["proposals"]} == {
        "improve_lookup_coverage",
        "reduce_stale_feeds",
        "review_disabled_feeds",
        "optimize_feed_hygiene",
    }
