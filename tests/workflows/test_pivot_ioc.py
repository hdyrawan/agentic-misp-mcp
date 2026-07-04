from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.pivot_ioc import pivot_ioc_workflow


class FakeClient:
    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(event_id=1, type="ip-dst", value=value, tags=["tlp:amber"]),
            MISPAttributeSummary(event_id=2, type="ip-dst", value=value),
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info=f"event {event_id}",
            date="2026-01-01",
            threat_level_id="2",
            tags=["misp-galaxy:threat-actor=example"],
            attribute_count=2,
            attributes_by_type={"domain": 1, "sha256": 1},
            attributes=[
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value=f"c2-{event_id}.example.test",
                ),
                MISPAttributeSummary(
                    event_id=event_id,
                    type="sha256",
                    category="Payload delivery",
                    value=f"{'a' * 63}{event_id % 10}",
                ),
            ],
        )


class NoMatchClient:
    async def search_attributes(self, value, limit):
        return []

    async def get_event(self, event_id, attribute_limit):
        raise AssertionError("get_event should not be called when there are no matches")


@pytest.mark.asyncio
async def test_pivot_ioc_no_matches(settings):
    result = await pivot_ioc_workflow(NoMatchClient(), settings, "9.9.9.9", 20)

    assert result["source_match_count"] == 0
    assert result["related_event_count"] == 0
    assert result["related_events"] == []
    assert result["related_iocs"] == []
    assert result["raw_references"] == []
    assert "not found in MISP" in result["pivot_summary"]


@pytest.mark.asyncio
async def test_pivot_ioc_with_related_events_and_iocs(settings):
    result = await pivot_ioc_workflow(FakeClient(), settings, "1.2.3.4", 20)

    assert result["ioc"] == {"value": "1.2.3.4", "type": "ipv4"}
    assert result["source_match_count"] == 2
    assert result["related_event_count"] == 2
    assert len(result["related_iocs"]) == 4
    assert {ioc["type"] for ioc in result["related_iocs"]} == {"domain", "sha256"}
    assert result["context"]["possible_threat_actors"] == ["example"]
    assert "Pivot on extracted related IOCs to expand the hunt." in result["recommended_pivots"]
    assert result["raw_references"] == [
        {"type": "event", "id": 1, "url": f"{settings.misp_base_url}/events/view/1"},
        {"type": "event", "id": 2, "url": f"{settings.misp_base_url}/events/view/2"},
    ]
    assert "Event" not in result
    assert "raw" not in result


@pytest.mark.asyncio
async def test_pivot_ioc_respects_limit(settings):
    result = await pivot_ioc_workflow(FakeClient(), settings, "1.2.3.4", 2)

    assert len(result["related_iocs"]) <= 2
