from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.summarize_event import summarize_event_workflow


class FakeClient:
    async def get_event(self, event_id, attribute_limit):
        assert event_id == 42
        assert attribute_limit == 50
        return MISPEventSummary(
            id=42,
            info="event",
            attribute_count=200,
            attributes_by_type={"ip-dst": 200},
            attributes=[MISPAttributeSummary(type="ip-dst", value="1.2.3.4")],
        )


@pytest.mark.asyncio
async def test_summarize_event_does_not_return_raw_json(settings):
    result = await summarize_event_workflow(FakeClient(), settings, 42)

    assert result["event"]["id"] == 42
    assert result["attribute_count"] == 200
    assert result["attributes_returned"] == 1
    assert "Event" not in result
    assert "raw" not in result
