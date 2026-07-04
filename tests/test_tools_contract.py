from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary
from agentic_misp_mcp.tools.registry import ALLOWED_TOOL_NAMES, register_tools


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, name):
        def decorator(func):
            self.tools[name] = func
            return func

        return decorator


class FakeClient:
    async def search_attributes(self, value, limit):
        return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]

    async def get_event(self, event_id, attribute_limit):
        raise AssertionError("not needed")

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


@pytest.mark.asyncio
async def test_only_v01_tools_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    assert set(mcp.tools) == ALLOWED_TOOL_NAMES
    assert "raw_misp_api" not in mcp.tools

    result = await mcp.tools["search_ioc"]("1.2.3.4", 20)

    assert result["match_count"] == 1
    record = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert record["tool"] == "search_ioc"
    assert record["success"] is True
