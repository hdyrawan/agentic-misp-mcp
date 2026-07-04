from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow


class FakeClient:
    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(event_id=1, type="ip-dst", value=value, tags=["tlp:amber"]),
            MISPAttributeSummary(event_id=2, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=3, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=4, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=5, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=6, type="ip-dst", value=value),
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info=f"event {event_id}",
            attribute_count=999,
            attributes=[],
        )

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


@pytest.mark.asyncio
async def test_investigate_ioc_respects_related_event_limit(settings):
    result = await investigate_ioc_workflow(FakeClient(), settings, "1.2.3.4", 20)

    assert result["match_count"] == 6
    assert result["related_events_returned"] == settings.misp_related_event_limit
    assert result["tags"] == ["tlp:amber"]
    assert result["assessment"]["seen_in_misp"] is True
    assert "raw" not in result
