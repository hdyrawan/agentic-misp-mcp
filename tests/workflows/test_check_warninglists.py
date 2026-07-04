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


def test_misp_2_5_42_value_keyed_hit_shape_is_recognized():
    """Real `/warninglists/checkValue` positive-hit shape observed against MISP `2.5.42`
    during v0.2.0-rc.1 live lab validation: a dict keyed by the queried value, mapping to a
    list of match objects. Previously fell through to `not_available`."""
    result = parse_warninglist_response(
        {
            "10.1.2.3": [
                {"id": "88", "name": "List of RFC 1918 CIDR blocks", "matched": "10.0.0.0/8"}
            ]
        }
    )

    assert result.status == "available"
    assert result.hit is True
    assert result.matches == [
        {"id": "88", "name": "List of RFC 1918 CIDR blocks", "matched": "10.0.0.0/8"}
    ]


def test_misp_2_5_42_empty_list_miss_shape_is_recognized():
    result = parse_warninglist_response([])

    assert result.status == "available"
    assert result.hit is False
