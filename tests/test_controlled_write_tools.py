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


class FakeRejectingWriteClient(FakeWriteClient):
    """MISP answers with HTTP 200 but rejects the operation itself (e.g. an unknown tag
    name, or a publish that MISP silently refuses) — the `saved`/`published` shape found
    during live lab validation on 2026-07-04."""

    async def tag_event(self, event_id, tag):
        self.calls.append(("tag_event", event_id, tag))
        return MISPTagResult(event_id=event_id, tag=tag, saved=False, message="Invalid Tag.")

    async def publish_event(self, event_id):
        self.calls.append(("publish_event", event_id))
        return MISPPublishResult(event_id=event_id, published=False, message="Job queued")


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
            AGENTIC_MISP_MCP_ENABLE_PUBLISH="true",
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
async def test_tag_event_reports_failed_when_misp_rejects_the_tag(monkeypatch, tmp_path):
    """MISP can answer HTTP 200 with `saved: false` (e.g. an unknown tag name) without
    raising. The tool must not report `executed` for a write that never actually applied."""
    client = FakeRejectingWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["tag_event_with_approval"](1, "not-a-real-tag", approved=True)

    assert result["status"] == "failed"
    assert result["result"]["saved"] is False
    assert client.calls == [("tag_event", 1, "not-a-real-tag")]


@pytest.mark.asyncio
async def test_publish_event_reports_failed_when_misp_does_not_publish(monkeypatch, tmp_path):
    client = FakeRejectingWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="curator",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_ENABLE_PUBLISH="true",
    )

    result = await mcp.tools["publish_event_with_approval"](1, approved=True)

    assert result["status"] == "failed"
    assert result["result"]["published"] is False
    assert client.calls == [("publish_event", 1)]


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


@pytest.mark.asyncio
async def test_publish_disabled_by_default_even_for_curator(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="curator",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["publish_event_with_approval"](1, approved=True)

    assert result["status"] == "blocked"
    assert "AGENTIC_MISP_MCP_ENABLE_PUBLISH" in result["policy"]["reason"]
    assert client.calls == []


@pytest.mark.asyncio
async def test_production_mode_requires_request_id_even_when_approval_requirement_disabled(
    monkeypatch, tmp_path
):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_REQUIRE_APPROVAL="false",
        AGENTIC_MISP_MCP_APPROVAL_MODE="production",
        AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=str(tmp_path / "approvals.sqlite3"),
    )

    result = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4", approved=True)

    assert result["status"] == "blocked"
    assert result["approval_status"] == "not_found"
    assert "approval_request_id" in result["policy"]["reason"]
    assert client.calls == []


@pytest.mark.asyncio
async def test_production_mode_requires_approved_request_id_and_blocks_replay(
    monkeypatch, tmp_path
):
    client = FakeWriteClient()
    mcp, _, settings = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_APPROVAL_MODE="production",
        AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=str(tmp_path / "approvals.sqlite3"),
    )

    blocked = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4", approved=True)
    assert blocked["status"] == "blocked"
    assert blocked["approval_status"] == "not_found"
    assert client.calls == []

    pending = await mcp.tools["submit_ioc_with_approval"](1, "ip-dst", "1.2.3.4")
    assert pending["status"] == "pending_approval"
    request_id = pending["approval_request_id"]

    from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore

    store = SqliteApprovalStore(settings.approval_store_path)
    store.approve(request_id, approved_by="operator")

    changed = await mcp.tools["submit_ioc_with_approval"](
        1,
        "ip-dst",
        "5.6.7.8",
        approval_request_id=request_id,
    )
    assert changed["status"] == "blocked"
    assert changed["approval_status"] == "hash_mismatch"
    assert client.calls == []

    executed = await mcp.tools["submit_ioc_with_approval"](
        1,
        "ip-dst",
        "1.2.3.4",
        approval_request_id=request_id,
    )
    assert executed["status"] == "executed"
    assert executed["approval_status"] == "used"
    assert client.calls == [("add_attribute", 1, {"type": "ip-dst", "value": "1.2.3.4"})]

    replay = await mcp.tools["submit_ioc_with_approval"](
        1,
        "ip-dst",
        "1.2.3.4",
        approval_request_id=request_id,
    )
    assert replay["status"] == "blocked"
    assert replay["approval_status"] == "already_used"
    assert len(client.calls) == 1

    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert records[-1]["outcome"] == "blocked"
    assert records[-1]["approval_request_id"] == request_id
    assert records[-1]["approval_status"] == "already_used"


@pytest.mark.asyncio
async def test_production_mode_rejected_and_wrong_tool_requests_do_not_write(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, settings = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_APPROVAL_MODE="production",
        AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=str(tmp_path / "approvals.sqlite3"),
    )
    from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore

    store = SqliteApprovalStore(settings.approval_store_path)
    pending = await mcp.tools["tag_event_with_approval"](1, "tlp:amber")
    store.reject(pending["approval_request_id"], reason="no")
    rejected = await mcp.tools["tag_event_with_approval"](
        1, "tlp:amber", approval_request_id=pending["approval_request_id"]
    )
    assert rejected["status"] == "blocked"
    assert rejected["approval_status"] == "rejected"

    pending = await mcp.tools["tag_event_with_approval"](1, "tlp:amber")
    store.approve(pending["approval_request_id"])
    wrong_tool = await mcp.tools["add_sighting_with_approval"](
        value="1.2.3.4", approval_request_id=pending["approval_request_id"]
    )
    assert wrong_tool["status"] == "blocked"
    assert wrong_tool["approval_status"] == "wrong_tool"
    assert client.calls == []


@pytest.mark.asyncio
async def test_allowlists_block_before_approval_record_creation(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, settings = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_APPROVAL_MODE="production",
        AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=str(tmp_path / "approvals.sqlite3"),
        AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES="ip-dst",
        AGENTIC_MISP_MCP_ALLOWED_TAGS="tlp:*",
    )

    bad_type = await mcp.tools["submit_ioc_with_approval"](1, "url", "http://example.test")
    assert bad_type["status"] == "blocked"

    bad_tag = await mcp.tools["tag_event_with_approval"](1, "private:tag")
    assert bad_tag["status"] == "blocked"

    from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore

    assert SqliteApprovalStore(settings.approval_store_path).list() == []
    assert client.calls == []


@pytest.mark.asyncio
async def test_production_expired_approval_cannot_execute(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, settings = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
        AGENTIC_MISP_MCP_APPROVAL_MODE="production",
        AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=str(tmp_path / "approvals.sqlite3"),
        AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS="1",
    )
    from datetime import datetime, timedelta, timezone

    from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore

    pending = await mcp.tools["add_sighting_with_approval"](value="1.2.3.4")
    store = SqliteApprovalStore(settings.approval_store_path)
    store.approve(pending["approval_request_id"])
    store.expire_stale(now=datetime.now(timezone.utc) + timedelta(seconds=2))  # noqa: UP017

    result = await mcp.tools["add_sighting_with_approval"](
        value="1.2.3.4", approval_request_id=pending["approval_request_id"]
    )

    assert result["status"] == "blocked"
    assert result["approval_status"] == "expired"
    assert client.calls == []


@pytest.mark.asyncio
async def test_propose_event_invalid_payload_never_calls_misp_and_audits_as_invalid(
    monkeypatch, tmp_path
):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["propose_event"]("   ", distribution=0, threat_level_id=4, analysis=0)

    assert result["status"] == "invalid"
    assert result["validation_errors"]
    assert "proposed_payload" not in result
    assert client.calls == []

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["success"] is False
    assert record["outcome"] == "invalid"


@pytest.mark.asyncio
async def test_propose_attribute_invalid_payload_never_calls_misp_and_audits_as_invalid(
    monkeypatch, tmp_path
):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["propose_attribute"](1, "not-a-real-type", "1.2.3.4")

    assert result["status"] == "invalid"
    assert any("not a recognized/supported" in error for error in result["validation_errors"])
    assert "proposed_payload" not in result
    assert client.calls == []

    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["success"] is False
    assert record["outcome"] == "invalid"


@pytest.mark.asyncio
async def test_propose_attribute_invalid_event_id_never_calls_misp(monkeypatch, tmp_path):
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["propose_attribute"](-1, "ip-dst", "1.2.3.4")

    assert result["status"] == "invalid"
    assert client.calls == []


@pytest.mark.asyncio
async def test_propose_event_valid_payload_still_returns_proposal(monkeypatch, tmp_path):
    """Regression guard: valid payloads must still pass through unaffected by the new
    validation layer."""
    client = FakeWriteClient()
    mcp, _, _ = _register(
        monkeypatch,
        tmp_path,
        client=client,
        AGENTIC_MISP_MCP_ROLE="analyst_write",
        AGENTIC_MISP_MCP_ENABLE_WRITE="true",
    )

    result = await mcp.tools["propose_event"]("legit event")

    assert result["status"] == "proposal"
    assert result["proposed_payload"]["info"] == "legit event"
    assert client.calls == []
