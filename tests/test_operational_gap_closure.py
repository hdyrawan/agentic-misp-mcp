from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.audit import AuditLogger
from agentic_misp_mcp.exceptions import MISPRateLimitError, MISPResponseTooLargeError
from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.tools.registry import register_tools

"""Closes v0.2.0-beta.1's open live-validation gaps with mocked/controlled coverage:
HTTP 429, large-result truncation, positive warninglist hit, and warninglist not_available —
each exercised through the full registered-tool + audit path, not just the client layer.
"""


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self, name):
        def decorator(func):
            self.tools[name] = func
            return func

        return decorator


class RateLimitedClient:
    async def search_attributes(self, value, limit):
        raise MISPRateLimitError("MISP rate limit reached")


class TooLargeClient:
    async def search_attributes(self, value, limit):
        raise MISPResponseTooLargeError("MISP response exceeded configured limit of 5242880 bytes")


class WarninglistHitClient:
    async def check_warninglists(self, value):
        return WarninglistCheckResult(
            status="available",
            hit=True,
            matches=[{"name": "common-web-crawlers", "list_id": "1"}],
        )


class WarninglistNotAvailableClient:
    async def check_warninglists(self, value):
        return WarninglistCheckResult(
            status="not_available", message="MISP warninglist check endpoint not available"
        )


def _read_audit_lines(tmp_path) -> list[dict]:
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


@pytest.mark.asyncio
async def test_rate_limit_429_propagates_cleanly_with_no_secret_leak_in_audit(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=RateLimitedClient(), settings=settings, audit_logger=audit)

    with pytest.raises(MISPRateLimitError):
        await mcp.tools["search_ioc"]("1.2.3.4", 20)

    records = _read_audit_lines(tmp_path)
    assert len(records) == 1
    record = records[0]
    assert record["success"] is False
    assert record["outcome"] == "error"
    assert record["error_type"] == "MISPRateLimitError"
    assert "rate limit" in record["error_message"].lower()
    assert settings.misp_api_key not in json.dumps(record)
    assert "Authorization" not in json.dumps(record)


@pytest.mark.asyncio
async def test_large_response_is_bounded_and_audit_stays_small(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=TooLargeClient(), settings=settings, audit_logger=audit)

    with pytest.raises(MISPResponseTooLargeError):
        await mcp.tools["search_ioc"]("1.2.3.4", 20)

    records = _read_audit_lines(tmp_path)
    assert len(records) == 1
    record = records[0]
    assert record["success"] is False
    assert record["outcome"] == "error"
    assert record["error_type"] == "MISPResponseTooLargeError"
    # The audit record itself must stay small even though the underlying MISP response was
    # oversized: only a bounded, safe error summary is ever written, never the raw body.
    assert len(json.dumps(record)) < 2048


@pytest.mark.asyncio
async def test_positive_warninglist_hit_surfaces_through_registered_tool(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=WarninglistHitClient(), settings=settings, audit_logger=audit)

    result = await mcp.tools["check_warninglists"]("1.2.3.4")

    assert result["status"] == "available"
    assert result["hit"] is True
    assert result["matches"] == [{"name": "common-web-crawlers", "list_id": "1"}]
    assert "benign" in result["recommended_handling"].lower()

    records = _read_audit_lines(tmp_path)
    assert records[0]["success"] is True
    assert records[0]["outcome"] == "success"


@pytest.mark.asyncio
async def test_warninglist_not_available_surfaces_through_registered_tool(settings, tmp_path):
    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(
        mcp, client=WarninglistNotAvailableClient(), settings=settings, audit_logger=audit
    )

    result = await mcp.tools["check_warninglists"]("1.2.3.4")

    assert result["status"] == "not_available"
    assert result["hit"] is False
    assert "unavailable" in result["recommended_handling"].lower()

    records = _read_audit_lines(tmp_path)
    assert records[0]["success"] is True
    assert records[0]["outcome"] == "success"


@pytest.mark.asyncio
async def test_investigate_ioc_propagates_rate_limit_without_crash(settings, tmp_path):
    """investigate_ioc fans out to several client calls; a 429 from any of them should
    still surface as a clean typed error, not an unhandled crash or partial silent result."""

    class InvestigateRateLimitedClient:
        async def search_attributes(self, value, limit):
            raise MISPRateLimitError("MISP rate limit reached")

        async def check_warninglists(self, value):
            return WarninglistCheckResult(status="available", hit=False)

        async def get_event(self, event_id, attribute_limit):
            return MISPEventSummary(id=event_id, info="event", attribute_count=0)

        async def search_events_by_tag(self, tag, limit):
            return []

    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(
        mcp, client=InvestigateRateLimitedClient(), settings=settings, audit_logger=audit
    )

    with pytest.raises(MISPRateLimitError):
        await mcp.tools["investigate_ioc"]("1.2.3.4", 20)

    records = _read_audit_lines(tmp_path)
    assert records[-1]["outcome"] == "error"
    assert records[-1]["error_type"] == "MISPRateLimitError"


@pytest.mark.asyncio
async def test_search_ioc_still_succeeds_under_normal_conditions(settings, tmp_path):
    """Baseline: registering the same tools with a healthy client still works, so the gap
    tests above are exercising failure handling, not a broken registration path."""

    class HealthyClient:
        async def search_attributes(self, value, limit):
            return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]

    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=HealthyClient(), settings=settings, audit_logger=audit)

    result = await mcp.tools["search_ioc"]("1.2.3.4", 20)

    assert result["match_count"] == 1
