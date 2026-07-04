from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPEventSummary
from agentic_misp_mcp.workflows.find_events_by_tag import find_events_by_tag_workflow


class FakeClient:
    async def search_events_by_tag(self, tag, limit):
        assert tag == "malware:family=test"
        return [
            MISPEventSummary(
                id=1,
                info="event one",
                date="2026-01-01",
                threat_level_id="2",
                analysis="1",
                attribute_count=5,
                tags=["malware:family=test", "tlp:amber"],
            ),
            MISPEventSummary(
                id=2,
                info="event two",
                date="2026-01-02",
                threat_level_id="1",
                analysis="2",
                attribute_count=9,
                tags=["malware:family=test"],
            ),
        ][:limit]


class NoResultsClient:
    async def search_events_by_tag(self, tag, limit):
        return []


@pytest.mark.asyncio
async def test_find_events_by_tag_returns_bounded_event_summaries(settings):
    result = await find_events_by_tag_workflow(FakeClient(), settings, "malware:family=test", 20)

    assert result["tag"] == "malware:family=test"
    assert result["event_count"] == 2
    assert result["events"][0] == {
        "event_id": 1,
        "info": "event one",
        "date": "2026-01-01",
        "threat_level": "2",
        "analysis": "1",
        "attribute_count": 5,
        "tags": ["malware:family=test", "tlp:amber"],
    }
    assert "Event" not in result
    assert "raw" not in result


@pytest.mark.asyncio
async def test_find_events_by_tag_handles_no_results(settings):
    result = await find_events_by_tag_workflow(NoResultsClient(), settings, "unused-tag", 20)

    assert result["event_count"] == 0
    assert result["events"] == []


@pytest.mark.asyncio
async def test_find_events_by_tag_validates_blank_tag(settings):
    with pytest.raises(ValueError, match="must not be blank"):
        await find_events_by_tag_workflow(FakeClient(), settings, "   ", 20)


@pytest.mark.asyncio
async def test_find_events_by_tag_respects_limit(settings):
    result = await find_events_by_tag_workflow(FakeClient(), settings, "malware:family=test", 1)

    assert result["limit"] == 1
    assert len(result["events"]) == 1
