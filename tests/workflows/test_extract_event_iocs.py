from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.extract_event_iocs import extract_event_iocs_workflow

ALL_ATTRIBUTES = [
    MISPAttributeSummary(type="ip-dst", value="1.2.3.4"),
    MISPAttributeSummary(type="ip-src", value="1.2.3.4"),
    MISPAttributeSummary(type="domain", value="evil.example.test"),
    MISPAttributeSummary(type="hostname", value="host.example.test"),
    MISPAttributeSummary(type="url", value="http://evil.example.test/x"),
    MISPAttributeSummary(type="md5", value="a" * 32),
    MISPAttributeSummary(type="sha1", value="b" * 40),
    MISPAttributeSummary(type="sha256", value="c" * 64),
    MISPAttributeSummary(type="filename|sha256", value=f"payload.exe|{'d' * 64}"),
    MISPAttributeSummary(type="email-src", value="bad@example.test"),
    MISPAttributeSummary(type="comment", value="not an ioc"),
]


class FakeClient:
    """Mimics the real client's attribute_limit slicing behavior."""

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info="malware event",
            tags=["tlp:amber"],
            attribute_count=len(ALL_ATTRIBUTES),
            attributes_by_type={},
            attributes=[
                attr.model_copy(update={"event_id": event_id})
                for attr in ALL_ATTRIBUTES[:attribute_limit]
            ],
        )


class EmptyEventClient:
    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="empty event", attribute_count=0)


@pytest.mark.asyncio
async def test_extract_event_iocs_extracts_and_groups_supported_types(settings):
    result = await extract_event_iocs_workflow(FakeClient(), settings, 42, 100)

    assert result["event_id"] == 42
    assert result["iocs_by_type"]["ip"] == ["1.2.3.4"]
    assert result["iocs_by_type"]["domain"] == ["evil.example.test", "host.example.test"]
    assert result["iocs_by_type"]["url"] == ["http://evil.example.test/x"]
    assert result["iocs_by_type"]["md5"] == ["a" * 32]
    assert result["iocs_by_type"]["sha1"] == ["b" * 40]
    assert sorted(result["iocs_by_type"]["sha256"]) == sorted(["c" * 64, "d" * 64])
    assert result["iocs_by_type"]["email"] == ["bad@example.test"]
    assert result["ioc_count"] == sum(len(v) for v in result["iocs_by_type"].values())
    assert "Event" not in result
    assert "raw" not in result


@pytest.mark.asyncio
async def test_extract_event_iocs_deduplicates_ip_types(settings):
    result = await extract_event_iocs_workflow(FakeClient(), settings, 42, 100)

    assert result["iocs_by_type"]["ip"] == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_extract_event_iocs_handles_empty_event(settings):
    result = await extract_event_iocs_workflow(EmptyEventClient(), settings, 7, 100)

    assert result["ioc_count"] == 0
    for values in result["iocs_by_type"].values():
        assert values == []


@pytest.mark.asyncio
async def test_extract_event_iocs_respects_limit(settings):
    result = await extract_event_iocs_workflow(FakeClient(), settings, 42, 3)

    assert result["ioc_count"] <= 3
