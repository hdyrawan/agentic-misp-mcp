from __future__ import annotations

import json
from inspect import signature

import pytest

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPEventSummary,
    MISPSightingReadSummary,
)
from agentic_misp_mcp.tools.registry import ALLOWED_TOOL_NAMES, register_tools
from agentic_misp_mcp.workflows.controlled_write import REQUIRED_ROLE_BY_TOOL


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

    async def search_sightings(self, value, limit):
        return [MISPSightingReadSummary(event_id=1, attribute_id="2", type="0", source="test")]

    async def search_events(
        self, *, date_from=None, date_to=None, published=None, org=None, limit=20
    ):
        return [MISPEventSummary(id=1, info="event", attribute_count=1)]

    async def get_version(self):
        return "2.5.42"

    async def probe_warninglists_available(self):
        return True

    async def list_feeds(self, limit, enabled=None):
        return [
            {"Feed": {"id": "1", "name": "feed", "enabled": True, "last_fetched": "1783209600"}}
        ]

    async def get_feed(self, feed_id):
        return {"Feed": {"id": str(feed_id), "name": "feed", "enabled": True}}


@pytest.mark.asyncio
async def test_exactly_twenty_five_tools_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    assert len(ALLOWED_TOOL_NAMES) == 25
    assert set(mcp.tools) == ALLOWED_TOOL_NAMES

    result = await mcp.tools["search_ioc"]("1.2.3.4", 20)

    assert result["match_count"] == 1
    record = json.loads((tmp_path / "audit.jsonl").read_text().strip())
    assert record["tool"] == "search_ioc"
    assert record["success"] is True
    assert record["policy"] == {
        "action": "read",
        "allowed": True,
        "approval_required": False,
        "role": "read_only",
    }


@pytest.mark.asyncio
async def test_no_raw_proxy_or_admin_tools_exist(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    # No raw MISP API proxy, and no user/org/server/settings-style admin tools. The six
    # Phase 8 controlled write tools (propose_event, propose_attribute,
    # submit_ioc_with_approval, add_sighting_with_approval, tag_event_with_approval,
    # publish_event_with_approval) are intentionally allowed here.
    forbidden_substrings = (
        "raw",
        "proxy",
        "admin",
        "organisation",
        "organization",
        "server",
        "setting",
        "authkey",
        "auth_key",
        "dangerous",
    )
    for name in mcp.tools:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden_substrings), name


@pytest.mark.asyncio
async def test_no_shell_filesystem_or_secret_passthrough_tools(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    forbidden_tool_terms = (
        "shell",
        "command",
        "exec",
        "filesystem",
        "file_system",
        "read_file",
        "write_file",
        "path",
        "upload",
        "download",
    )
    forbidden_parameter_terms = (
        "api_key",
        "apikey",
        "authkey",
        "auth_key",
        "authorization",
        "bearer",
        "credential",
        "header",
        "password",
        "secret",
        "token",
    )

    assert len(mcp.tools) == 25
    for name, func in mcp.tools.items():
        lowered_name = name.lower()
        assert not any(term in lowered_name for term in forbidden_tool_terms), name

        for parameter_name in signature(func).parameters:
            if parameter_name == "approval_token":
                continue
            lowered_parameter = parameter_name.lower()
            assert not any(term in lowered_parameter for term in forbidden_parameter_terms), (
                name,
                parameter_name,
            )


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
async def test_m3_feed_observability_tools_are_registered_and_audited(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    calls = {
        "list_feeds": lambda: mcp.tools["list_feeds"](50, True),
        "get_feed_status": lambda: mcp.tools["get_feed_status"](1),
        "summarize_feed_health": lambda: mcp.tools["summarize_feed_health"](100),
    }
    results = {}
    for name, call in calls.items():
        results[name] = await call()

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    records = [json.loads(line) for line in lines]
    assert {record["tool"] for record in records} == set(calls)
    assert all(record["policy"]["action"] == "read" for record in records)
    assert all(record["policy"]["role"] == "read_only" for record in records)
    assert all(record["success"] is True for record in records)


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


@pytest.mark.asyncio
async def test_write_tool_count_unchanged_at_six(settings, tmp_path):
    """v0.2.0-beta.2 adds config doctor and approvals prune as CLI-only operator commands.
    Neither is an MCP tool, so the write-tool surface must stay exactly the same six tools
    it has been since Phase 8."""
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    assert set(REQUIRED_ROLE_BY_TOOL) == {
        "propose_event",
        "propose_attribute",
        "submit_ioc_with_approval",
        "add_sighting_with_approval",
        "tag_event_with_approval",
        "publish_event_with_approval",
    }
    assert len(REQUIRED_ROLE_BY_TOOL) == 6
    for name in REQUIRED_ROLE_BY_TOOL:
        assert name in mcp.tools


@pytest.mark.asyncio
async def test_no_config_doctor_or_approvals_prune_mcp_tools_exist(settings, tmp_path):
    """Config doctor and approvals prune are operator-CLI-only (see cli.py/cli_approvals.py)
    and must never be reachable as MCP tools."""
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    for name in mcp.tools:
        lowered = name.lower()
        assert "doctor" not in lowered
        assert "prune" not in lowered
        assert "vacuum" not in lowered
    assert len(mcp.tools) == 25


@pytest.mark.asyncio
async def test_no_feed_admin_or_raw_feed_proxy_tools_exist(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    forbidden = {
        "enable_feed",
        "disable_feed",
        "fetch_feed",
        "cache_feed",
        "edit_feed",
        "delete_feed",
        "raw_feed",
        "feed_proxy",
    }
    for name in mcp.tools:
        assert name not in forbidden


@pytest.mark.asyncio
async def test_read_tool_dict_responses_carry_envelope_fields(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    search_result = await mcp.tools["search_ioc"]("1.2.3.4", 20)
    investigate_result = await mcp.tools["investigate_ioc"]("1.2.3.4", 20)
    warninglist_result = await mcp.tools["check_warninglists"]("1.2.3.4")

    for tool_name, result in (
        ("search_ioc", search_result),
        ("investigate_ioc", investigate_result),
        ("check_warninglists", warninglist_result),
    ):
        assert result["tool_name"] == tool_name
        assert result["schema_version"] == 1


@pytest.mark.asyncio
async def test_markdown_read_tools_stay_plain_strings(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    result = await mcp.tools["generate_markdown_ioc_report"]("1.2.3.4")

    assert isinstance(result, str)
    assert "Intel freshness" in result


@pytest.mark.asyncio
async def test_investigate_and_pivot_responses_include_freshness_block(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    investigate_result = await mcp.tools["investigate_ioc"]("1.2.3.4", 20)
    pivot_result = await mcp.tools["pivot_ioc"]("1.2.3.4", 20)
    report_result = await mcp.tools["generate_ioc_report"]("1.2.3.4")

    for result in (investigate_result, pivot_result, report_result):
        freshness = result["freshness"]
        assert freshness["label"] in {"fresh", "aging", "stale", "expired", "unknown"}
        assert set(freshness["thresholds_days"]) == {"fresh", "aging", "stale"}
        assert 0.0 <= freshness["age_weight"] <= 1.0
