from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.find_related_iocs import find_related_iocs_workflow


class FakeClient:
    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(event_id=1, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=2, type="ip-dst", value=value),
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info=f"event {event_id}",
            attribute_count=3,
            attributes_by_type={"domain": 1, "sha256": 1, "ip-dst": 1},
            attributes=[
                # "shared.example.test" appears in both events -> higher event coverage.
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value="shared.example.test",
                ),
                MISPAttributeSummary(
                    event_id=event_id,
                    type="sha256",
                    category="Payload delivery",
                    value=f"{'a' * 63}{event_id % 10}",
                ),
                # Excluded: same value as the source IOC.
                MISPAttributeSummary(
                    event_id=event_id,
                    type="ip-dst",
                    category="Network activity",
                    value="1.2.3.4",
                ),
            ],
        )


class NoMatchClient:
    async def search_attributes(self, value, limit):
        return []


@pytest.mark.asyncio
async def test_find_related_iocs_no_matches(settings):
    result = await find_related_iocs_workflow(NoMatchClient(), settings, "9.9.9.9", 20)

    assert result["related_iocs"] == []
    assert result["count"] == 0


@pytest.mark.asyncio
async def test_find_related_iocs_deduplicates_and_excludes_source(settings):
    result = await find_related_iocs_workflow(FakeClient(), settings, "1.2.3.4", 20)

    values = [ioc["value"] for ioc in result["related_iocs"]]
    assert "1.2.3.4" not in values
    assert values.count("shared.example.test") == 1

    shared = next(ioc for ioc in result["related_iocs"] if ioc["value"] == "shared.example.test")
    assert sorted(shared["source_event_ids"]) == [1, 2]
    assert shared["relationship"] == "same_event"


@pytest.mark.asyncio
async def test_find_related_iocs_ranks_by_coverage_and_type(settings):
    result = await find_related_iocs_workflow(FakeClient(), settings, "1.2.3.4", 20)

    # "shared.example.test" (2 events) must outrank single-event hashes.
    assert result["related_iocs"][0]["value"] == "shared.example.test"
    scores = [ioc["score"] for ioc in result["related_iocs"]]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_find_related_iocs_respects_limit(settings):
    result = await find_related_iocs_workflow(FakeClient(), settings, "1.2.3.4", 1)

    assert result["limit"] == 1
    assert result["count"] == 1
    assert len(result["related_iocs"]) == 1
