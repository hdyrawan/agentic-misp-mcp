from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow


class FakeClient:
    async def search_attributes(self, value, limit):
        return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="event", attribute_count=1)

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


@pytest.mark.asyncio
async def test_generate_ioc_report(settings):
    result = await generate_ioc_report_workflow(FakeClient(), settings, "1.2.3.4")

    assert result["title"] == "IOC report: 1.2.3.4"
    assert result["confidence"] in {"low", "medium", "high"}
    assert result["misp_findings"][0]["title"] == "MISP matches"
