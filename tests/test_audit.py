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
