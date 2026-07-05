from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentic_misp_mcp.models.misp import MISPEventSummary, MISPSightingReadSummary
from agentic_misp_mcp.workflows.get_ioc_sightings import get_ioc_sightings_workflow
from agentic_misp_mcp.workflows.get_misp_status import get_misp_status_workflow
from agentic_misp_mcp.workflows.search_events import search_events_workflow


class FakeClient:
    def __init__(self):
        self.sighting_limit = None
        self.event_kwargs = None

    async def search_sightings(self, value, limit):
        self.sighting_limit = limit
        return [
            MISPSightingReadSummary(
                event_id=1,
                attribute_id="10",
                type="0",
                source="sensor-a",
                date_sighting=datetime(2026, 7, 5, tzinfo=UTC),
            ),
            MISPSightingReadSummary(
                event_id=2,
                attribute_id="11",
                type="1",
                source="sensor-b",
                date_sighting=datetime(2026, 7, 4, tzinfo=UTC),
            ),
        ]

    async def search_events(self, **kwargs):
        self.event_kwargs = kwargs
        return [
            MISPEventSummary(
                id=42,
                info="recent event",
                date="2026-07-05",
                threat_level_id="2",
                analysis="1",
                attribute_count=3,
                tags=["tlp:amber"],
            )
        ]

    async def get_version(self):
        return "2.5.42"

    async def probe_warninglists_available(self):
        return True


@pytest.mark.asyncio
async def test_get_ioc_sightings_returns_bounded_summary(settings):
    settings.misp_max_limit = 1
    client = FakeClient()

    result = await get_ioc_sightings_workflow(client, settings, "1.2.3.4", 50)

    assert client.sighting_limit == 1
    assert result["ioc"] == {"value": "1.2.3.4", "type": "ipv4"}
    assert result["sighting_count"] == 2
    assert result["newest_sighting_at"] == "2026-07-05T00:00:00+00:00"
    assert result["oldest_sighting_at"] == "2026-07-04T00:00:00+00:00"
    assert result["sightings"][0] == {
        "event_id": 1,
        "attribute_id": "10",
        "type": "0",
        "source": "sensor-a",
        "date_sighting": "2026-07-05T00:00:00+00:00",
    }
    assert result["limit"] == 1


@pytest.mark.asyncio
async def test_get_ioc_sightings_handles_empty_results(settings):
    class EmptyClient(FakeClient):
        async def search_sightings(self, value, limit):
            return []

    result = await get_ioc_sightings_workflow(EmptyClient(), settings, "example.org", 50)

    assert result["sighting_count"] == 0
    assert result["newest_sighting_at"] is None
    assert result["oldest_sighting_at"] is None
    assert result["sightings"] == []


@pytest.mark.asyncio
async def test_search_events_uses_filters_and_event_summary_shape(settings):
    client = FakeClient()

    result = await search_events_workflow(
        client,
        settings,
        date_from="2026-07-01",
        date_to="2026-07-05",
        published=True,
        org=" CIRCL ",
        limit=20,
    )

    assert client.event_kwargs == {
        "date_from": "2026-07-01",
        "date_to": "2026-07-05",
        "published": True,
        "org": "CIRCL",
        "limit": 20,
    }
    assert result["event_count"] == 1
    assert result["events"] == [
        {
            "event_id": 42,
            "info": "recent event",
            "date": "2026-07-05",
            "threat_level": "2",
            "analysis": "1",
            "attribute_count": 3,
            "tags": ["tlp:amber"],
        }
    ]


@pytest.mark.asyncio
async def test_get_misp_status_reports_baseline_and_warninglists():
    result = await get_misp_status_workflow(FakeClient())

    assert result == {
        "misp_version": "2.5.42",
        "tested_baseline": "2.5.42",
        "version_tested": True,
        "warninglists_available": True,
    }
