from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
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
        return MISPEventSummary(
            id=event_id,
            info="event",
            attribute_count=1,
            attributes=[MISPAttributeSummary(event_id=event_id, type="ip-dst", value="1.2.3.4")],
        )

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)

    async def search_events_by_tag(self, tag, limit):
        return [MISPEventSummary(id=1, info="event", attribute_count=1, tags=[tag])]


@pytest.mark.asyncio
async def test_exactly_thirteen_tools_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    assert len(ALLOWED_TOOL_NAMES) == 13
    assert set(mcp.tools) == ALLOWED_TOOL_NAMES

    result = await mcp.tools["search_ioc"]("1.2.3.4", 20)

    assert result["match_count"] == 1
    record = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert record["tool"] == "search_ioc"
    assert record["success"] is True


@pytest.mark.asyncio
async def test_no_write_admin_or_raw_proxy_tools_exist(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    forbidden_substrings = (
        "raw",
        "proxy",
        "create",
        "delete",
        "publish",
        "tag_event",
        "sighting",
        "admin",
    )
    for name in mcp.tools:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden_substrings), name


@pytest.mark.asyncio
async def test_all_phase_3_tools_are_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    calls = {
        "pivot_ioc": lambda: mcp.tools["pivot_ioc"]("1.2.3.4", 20),
        "find_related_iocs": lambda: mcp.tools["find_related_iocs"]("1.2.3.4", 20),
        "extract_event_iocs": lambda: mcp.tools["extract_event_iocs"](1, 100),
        "explain_event_context": lambda: mcp.tools["explain_event_context"](1),
        "find_events_by_tag": lambda: mcp.tools["find_events_by_tag"]("tag", 20),
    }
    for call in calls.values():
        result = await call()
        assert isinstance(result, dict)

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    audited_tools = {json.loads(line)["tool"] for line in lines}
    assert audited_tools == set(calls)
    assert all(json.loads(line)["success"] is True for line in lines)


@pytest.mark.asyncio
async def test_all_phase_4_report_tools_are_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    calls = {
        "generate_event_report": lambda: mcp.tools["generate_event_report"](1),
        "generate_markdown_ioc_report": lambda: mcp.tools["generate_markdown_ioc_report"](
            "1.2.3.4"
        ),
        "generate_markdown_event_report": lambda: mcp.tools["generate_markdown_event_report"](1),
    }
    results = {}
    for name, call in calls.items():
        results[name] = await call()

    assert isinstance(results["generate_event_report"], dict)
    assert isinstance(results["generate_markdown_ioc_report"], str)
    assert isinstance(results["generate_markdown_event_report"], str)

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    audited_tools = {json.loads(line)["tool"] for line in lines}
    assert audited_tools == set(calls)
    assert all(json.loads(line)["success"] is True for line in lines)


@pytest.mark.asyncio
async def test_existing_v01_and_phase_2_tools_still_registered(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    for name in (
        "search_ioc",
        "investigate_ioc",
        "summarize_event",
        "check_warninglists",
        "generate_ioc_report",
    ):
        assert name in mcp.tools
