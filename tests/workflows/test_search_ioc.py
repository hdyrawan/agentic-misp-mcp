from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary
from agentic_misp_mcp.workflows.search_ioc import search_ioc_workflow


class FakeClient:
    async def search_attributes(self, value, limit):
        assert value == "1.2.3.4"
        assert limit == 20
        return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]


@pytest.mark.asyncio
async def test_search_ioc(settings):
    result = await search_ioc_workflow(FakeClient(), settings, "1.2.3.4", 20)

    assert result["ioc"] == {"value": "1.2.3.4", "type": "ipv4"}
    assert result["match_count"] == 1
    assert result["matches"][0]["event_id"] == 1
