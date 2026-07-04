from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import parse_warninglist_response
from agentic_misp_mcp.workflows.check_warninglists import check_warninglists_workflow


class FakeClient:
    async def check_warninglists(self, value):
        return parse_warninglist_response({"matches": [{"name": "common"}]})


@pytest.mark.asyncio
async def test_check_warninglists_workflow_hit():
    result = await check_warninglists_workflow(FakeClient(), " 1.2.3.4 ")

    assert result["value"] == "1.2.3.4"
    assert result["status"] == "available"
    assert result["hit"] is True


def test_unknown_warninglist_shape_is_not_available():
    result = parse_warninglist_response("unexpected")

    assert result.status == "not_available"
    assert result.hit is False
