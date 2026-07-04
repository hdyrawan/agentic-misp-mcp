from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPPublishResult,
    MISPSightingSummary,
    MISPTagResult,
)
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.tools.registry import ALLOWED_TOOL_NAMES, register_tools

ORIGINAL_13_TOOLS = {
    "search_ioc",
    "investigate_ioc",
    "summarize_event",
    "check_warninglists",
    "generate_ioc_report",
    "pivot_ioc",
    "find_related_iocs",
    "extract_event_iocs",
    "explain_event_context",
    "find_events_by_tag",
    "generate_event_report",
    "generate_markdown_ioc_report",
    "generate_markdown_event_report",
}

NEW_PHASE_8_TOOLS = {
    "propose_event",
    "propose_attribute",
    "submit_ioc_with_approval",
    "add_sighting_with_approval",
    "tag_event_with_approval",
    "publish_event_with_approval",
}


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, name):
        def decorator(func):
            self.tools[name] = func
            return func

        return decorator


class FakeWriteClient:
    def __init__(self):
        self.calls = []

    async def add_attribute(self, event_id, payload):
        self.calls.append(("add_attribute", event_id, payload))
        return MISPAttributeSummary(event_id=event_id, type=payload["type"], value=payload["value"])

    async def add_sighting(self, payload):
        self.calls.append(("add_sighting", payload))
        return MISPSightingSummary(value=payload.get("value"), event_id=payload.get("event_id"))

    async def tag_event(self, event_id, tag):
        self.calls.append(("tag_event", event_id, tag))
        return MISPTagResult(event_id=event_id, tag=tag, saved=True, message="ok")

    async def publish_event(self, event_id):
        self.calls.append(("publish_event", event_id))
        return MISPPublishResult(event_id=event_id, published=True, message="ok")


def _settings(monkeypatch, tmp_path, **overrides):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "test-secret-key")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    return Settings()


def _register(monkeypatch, tmp_path, client=None, **env_overrides):
    settings = _settings(monkeypatch, tmp_path, **env_overrides)
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=client or FakeWriteClient(), settings=settings, audit_logger=audit)
    return mcp, audit, settings


@pytest.mark.asyncio
async def test_tool_count_exactly_nineteen(monkeypatch, tmp_path):
    mcp, _, _ = _register(monkeypatch, tmp_path)

    assert len(ALLOWED_TOOL_NAMES) == 19
    assert set(mcp.tools) == ALLOWED_TOOL_NAMES
    assert ORIGINAL_13_TOOLS | NEW_PHASE_8_TOOLS == ALLOWED_TOOL_NAMES


@pytest.mark.asyncio
async def test_original_thirteen_tools_remain_registered(monkeypatch, tmp_path):
    mcp, _, _ = _register(monkeypatch, tmp_path)

    assert ORIGINAL_13_TOOLS.issubset(set(mcp.tools))


def test_no_raw_api_proxy_tool_exists():
    for name in ALLOWED_TOOL_NAMES:
        lowered = name.lower()
        assert "raw" not in lowered
        assert "proxy" not in lowered


def test_no_admin_user_org_server_settings_tools_exist():
    forbidden = (
        "admin",
        "user",
        "organisation",
        "organization",
        "server",
        "setting",
        "authkey",
        "auth_key",
        "role",
        "dangerous",
    )
    for name in ALLOWED_TOOL_NAMES:
        lowered = name.lower()
        assert not any(term in lowered for term in forbidden), name


@pytest.mark.asyncio
async def test_default_read_only_blocks_all_write_tools(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(monkeypatch, tmp_path, client=client)

    results = {
        "propose_event": await mcp.tools["propose_event"]("test event"),
        "propose_attribute": await mcp.tools["propose_attribute"](1, "ip-dst", "1.2.3.4"),
        "submit_ioc_with_approval": await mcp.tools["submit_ioc_with_approval"](
            1, "ip-dst", "1.2.3.4"
        ),
        "add_sighting_with_approval": await mcp.tools["add_sighting_with_approval"](
            value="1.2.3.4"
        ),
        "tag_event_with_approval": await mcp.tools["tag_event_with_approval"](1, "tlp:amber"),
        "publish_event_with_approval": await mcp.tools["publish_event_with_approval"](1),
    }

    for name, result in results.items():
        assert result["status"] == "blocked", name
        assert result["policy"]["allowed"] is False

    assert client.calls == []

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == len(results)
    for line in lines:
        record = json.loads(line)
        assert record["success"] is False
        assert record["outcome"] == "blocked"
        assert record["allowed"] is False
        assert record["role"] == "read_only"


@pytest.mark.asyncio
async def test_blocked_submit_ioc_audit_record_is_not_success(monkeypatch, tmp_path):
    """Read-only + write-disabled blocks must be audited as blocked, not success."""
    client = FakeWriteClient()
    mcp, _, _ = _register(monkeypatch, tmp_path, client=client)

    result = await mcp.tools["submit_ioc_with_approval"](
        1, "ip-dst", "1.2.3.4", approval_token="super-secret-token"
    )

    assert result["status"] == "blocked"
    assert result["policy"]["allowed"] is False
    assert client.calls == []

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])

    assert record["tool"] == "submit_ioc_with_approval"
    assert record["action"] == "write"
    assert record["allowed"] is False
    assert record["role"] == "read_only"
    assert record["success"] is False
    assert record.get("outcome") == "blocked"
    assert record["arguments"]["approval_token"] == "[REDACTED]"
    assert "super-secret-token" not in (tmp_path / "audit.jsonl").read_text()


@pytest.mark.asyncio
async def test_write_disabled_blocks_write_even_with_admin_role(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="admin",
        AGENTIC_MISP_MCP_ENABLE_WRITE="false",
    )

    result = await mcp.tools["publish_event_with_approval"](1, approved=True)

    assert result["status"] == "blocked"
    assert "AGENTIC_MISP_MCP_ENABLE_WRITE" in result["policy"]["reason"]
    assert client.calls == []


@pytest.mark.asyncio
async def test_analyst_write_can_propose_and_submit_ioc_only_with_approval(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_REQUIRE_APPROVAL="true",
    )

    proposal = await mcp.tools["propose_attribute"](1, "ip-dst", "1.2.3.4")
    assert proposal["status"] == "proposal"
    assert proposal["proposed_payload"]["value"] == "1.2.3.4"
    assert client.calls == []

    pending = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4")
    assert pending["status"] == "pending_approval"
    assert pending["approval"]["tool_name"] == "submit_ioc_with_approval"
    assert client.calls == []

    executed = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4", approved=True)
    assert executed["status"] == "executed"
    assert client.calls == [("add_attribute", 1, {"type": "ip-dst", "value": "1.2.3.4"})]


@pytest.mark.asyncio
async def test_analyst_write_cannot_publish(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["publish_event_with_approval"](1, approved=True)

    assert result["status"] == "blocked"
    assert client.calls == []


@pytest.mark.asyncio
async def test_curator_and_admin_can_publish_only_with_approval(monkeypatch, tmp_path):
    for role in ("curator", "admin"):
        client = FakeWriteClient()
        mcp, _, _ = _register(
            monkeypatch,
            tmp_path,
            client=client,
            AGENTIC_MISP_MCP_ROLE=role,
            AGENTIC_MISP_MCP_ENABLE_WRITE="true",
            AGENTIC_MISP_MCP_REQUIRE_APPROVAL="true",
        )

        pending = await mcp.tools["publish_event_with_approval"](1)
        assert pending["status"] == "pending_approval", role
        assert client.calls == []

        executed = await mcp.tools["publish_event_with_approval"](1, approved=True)
        assert executed["status"] == "executed", role
        assert client.calls == [("publish_event", 1)]


@pytest.mark.asyncio
async def test_approval_required_path_returns_proposal_when_approval_missing(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["tag_event_with_approval"](1, "tlp:amber")

    assert result["status"] == "pending_approval"
    assert result["approval"]["reason"]
    assert client.calls == []


@pytest.mark.asyncio
async def test_approved_path_calls_mocked_misp_write_method(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["add_sighting_with_approval"](value="1.2.3.4", approved=True)

    assert result["status"] == "executed"
    assert client.calls == [("add_sighting", {"type": "0", "value": "1.2.3.4"})]


@pytest.mark.asyncio
async def test_no_secret_leakage_in_audit(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4", approved=True)
    await mcp.tools["tag_event_with_approval"](1, "tlp:amber")

    log_text = (tmp_path / "audit.jsonl").read_text()
    assert "test-secret-key" not in log_text


@pytest.mark.asyncio
async def test_approval_token_branches_when_configured(monkeypatch, tmp_path):
    client = FakeWriteClient()
    token = "human-approved-token"
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_REQUIRE_APPROVAL="true",
        AGENTIC_MISP_MCP_APPROVAL_TOKEN=token,
    )

    pending = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4")
    assert pending["status"] == "pending_approval"

    missing = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4", approved=True)
    assert missing["status"] == "blocked"
    assert "token" in missing["policy"]["reason"]

    wrong = await mcp.tools["submit_ioc_with_approval"](
        1, "ip-dst", "1.2.3.4", approved=True, approval_token="wrong-token"
    )
    assert wrong["status"] == "blocked"

    executed = await mcp.tools["submit_ioc_with_approval"](
        1, "ip-dst", "1.2.3.4", approved=True, approval_token=token
    )
    assert executed["status"] == "executed"
    assert client.calls == [("add_attribute", 1, {"type": "ip-dst", "value": "1.2.3.4"})]

    audit_text = (tmp_path / "audit.jsonl").read_text()
    assert token not in audit_text
    assert "wrong-token" not in audit_text
    assert '"approval_token": "[REDACTED]"' in audit_text
