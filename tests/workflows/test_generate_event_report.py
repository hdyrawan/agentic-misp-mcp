from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.generate_event_report import generate_event_report_workflow

ALL_ATTRIBUTES = [
    MISPAttributeSummary(type="domain", value=f"c2-{i}.example.test") for i in range(60)
]


class FakeClient:
    """A large event: more attributes exist than any single fetch will return."""

    async def get_event(self, event_id, attribute_limit):
        sliced = [
            attr.model_copy(update={"event_id": event_id})
            for attr in ALL_ATTRIBUTES[:attribute_limit]
        ]
        return MISPEventSummary(
            id=event_id,
            info="large phishing event",
            date="2026-01-01",
            threat_level_id="2",
            analysis="1",
            distribution="1",
            tags=["misp-galaxy:threat-actor=example-actor", "tlp:amber"],
            attribute_count=500,
            attributes_by_type={"domain": 500},
            attributes=sliced,
        )


class EmptyEventClient:
    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="empty event")


@pytest.mark.asyncio
async def test_generate_event_report_with_iocs_and_tags(settings):
    result = await generate_event_report_workflow(FakeClient(), settings, 42)

    assert result["report_type"] == "event_report"
    assert result["title"] == "MISP event report: 42"
    assert result["event"] == {
        "event_id": 42,
        "info": "large phishing event",
        "date": "2026-01-01",
        "threat_level": "Medium",
        "analysis_status": "Ongoing",
        "distribution": "1",
    }
    assert isinstance(result["executive_summary"], str) and result["executive_summary"]
    assert isinstance(result["technical_summary"], str) and result["technical_summary"]
    assert result["attribute_summary"] == {"domain": 500}
    assert result["context"]["possible_threat_actors"] == ["example-actor"]
    assert result["context"]["notable_tags"] == ["tlp:amber"]
    assert result["recommended_actions"]
    assert result["raw_references"] == [
        {"type": "event", "id": 42, "url": f"{settings.misp_base_url}/events/view/42"}
    ]
    assert "Event" not in result
    assert "raw" not in result


@pytest.mark.asyncio
async def test_generate_event_report_bounded_output(settings):
    result = await generate_event_report_workflow(FakeClient(), settings, 42)

    ioc_summary = result["ioc_summary"]
    assert ioc_summary["ioc_count"] == len(ioc_summary["iocs_by_type"]["domain"])
    assert ioc_summary["ioc_count"] <= 100
    # The underlying event reports far more attributes than we ever pull or return.
    assert ioc_summary["ioc_count"] < result["attribute_summary"]["domain"]


@pytest.mark.asyncio
async def test_generate_event_report_handles_no_attributes(settings):
    result = await generate_event_report_workflow(EmptyEventClient(), settings, 7)

    assert result["ioc_summary"]["ioc_count"] == 0
    for values in result["ioc_summary"]["iocs_by_type"].values():
        assert values == []
    assert result["context"] == {
        "possible_malware_families": [],
        "possible_threat_actors": [],
        "possible_campaigns": [],
        "mitre_attack": [],
        "notable_tags": [],
    }
    assert any("no recorded attributes" in limitation for limitation in result["limitations"])
    assert result["executive_summary"]
    assert result["technical_summary"]
    assert result["recommended_actions"]
