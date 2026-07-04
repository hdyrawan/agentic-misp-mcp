from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.audit import AuditLogger, audit_call


@pytest.mark.asyncio
async def test_audit_success_writes_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)

    result = await audit_call(logger, "tool", {"value": "1.2.3.4"}, lambda: _ok())

    assert result == "ok"
    record = json.loads(path.read_text().strip())
    assert record["tool"] == "tool"
    assert record["success"] is True
    assert record["arguments"]["value"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_audit_failure_redacts_secret(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)

    with pytest.raises(RuntimeError):
        await audit_call(
            logger,
            "tool",
            {"misp_api_key": "super-secret", "headers": {"Authorization": "super-secret"}},
            lambda: _fail(),
        )

    text = path.read_text()
    assert "super-secret" not in text
    record = json.loads(text.strip())
    assert record["success"] is False
    assert record["error_type"] == "RuntimeError"


async def _ok():
    return "ok"


async def _fail():
    raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_audit_blocked_policy_decision_is_not_success(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    policy_decision = {
        "role": "read_only",
        "action": "write",
        "allowed": False,
        "approval_required": False,
    }

    result = await audit_call(
        logger,
        "submit_ioc_with_approval",
        {"approval_token": "super-secret-token"},
        lambda: _ok(),
        policy_decision=policy_decision,
    )

    assert result == "ok"
    record = json.loads(path.read_text().strip())
    assert record["action"] == "write"
    assert record["allowed"] is False
    assert record["role"] == "read_only"
    assert record["success"] is False
    assert record["outcome"] == "blocked"
    assert record["arguments"]["approval_token"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_audit_allowed_policy_decision_still_reports_success(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    policy_decision = {
        "role": "analyst_write",
        "action": "write",
        "allowed": True,
        "approval_required": False,
    }

    await audit_call(
        logger, "submit_ioc_with_approval", {}, lambda: _ok(), policy_decision=policy_decision
    )

    record = json.loads(path.read_text().strip())
    assert record["success"] is True
    assert record["outcome"] == "success"


@pytest.mark.asyncio
async def test_audit_tool_reported_failure_is_not_success(tmp_path):
    """A controlled-write tool can return normally (no exception) with `status: "failed"`
    when MISP itself rejected the operation (e.g. `saved`/`published` false on HTTP 200).
    The audit record must not claim `success: true`/`outcome: "success"` for that call."""
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    policy_decision = {
        "role": "curator",
        "action": "write",
        "allowed": True,
        "approval_required": True,
    }

    async def _tool_failed():
        return {"tool_name": "tag_event_with_approval", "status": "failed", "result": {}}

    result = await audit_call(
        logger,
        "tag_event_with_approval",
        {"event_id": 1, "tag": "not-a-real-tag"},
        _tool_failed,
        policy_decision=policy_decision,
    )

    assert result["status"] == "failed"
    record = json.loads(path.read_text().strip())
    assert record["success"] is False
    assert record["outcome"] == "failed"


@pytest.mark.asyncio
async def test_audit_failure_sanitizes_sensitive_exception_content(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    secret = "fixture-misp-api-key"
    approval = "fixture-approval-token"

    async def fail_with_sensitive_message():
        raise RuntimeError(
            "backend failed authorization: Bearer bearer-secret "
            f"MISP_API_KEY={secret} approval_token={approval} "
            "headers={'Authorization': 'auth-header-secret', 'Cookie': 'cookie-secret'} "
            "authkey=authkey-secret password=password-secret"
        )

    with pytest.raises(RuntimeError):
        await audit_call(logger, "tool", {"value": "1.2.3.4"}, fail_with_sensitive_message)

    text = path.read_text()
    for leaked in (
        secret,
        approval,
        "bearer-secret",
        "auth-header-secret",
        "cookie-secret",
        "authkey-secret",
        "password-secret",
    ):
        assert leaked not in text
    record = json.loads(text.strip())
    assert record["error_message"].startswith("RuntimeError:")
    assert "[REDACTED]" in record["error_message"]


@pytest.mark.asyncio
async def test_audit_failure_truncates_long_error_message(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)

    async def fail_with_long_message():
        raise RuntimeError("x" * 2000)

    with pytest.raises(RuntimeError):
        await audit_call(logger, "tool", {}, fail_with_long_message)

    record = json.loads(path.read_text().strip())
    assert len(record["error_message"]) <= 530
    assert "[truncated]" in record["error_message"]
