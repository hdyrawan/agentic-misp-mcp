from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow
from agentic_misp_mcp.workflows.investigation_engine import VALID_CONFIDENCE, VALID_VERDICTS


class FakeClient:
    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(
                event_id=1,
                type="ip-dst",
                value=value,
                to_ids=True,
                tags=["malware:family=test"],
            )
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info="event",
            date="2026-01-01",
            threat_level_id="1",
            attribute_count=2,
            attributes_by_type={"ip-dst": 1, "domain": 1},
            attributes=[
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value="c2.example.test",
                )
            ],
        )

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


@pytest.mark.asyncio
async def test_generate_ioc_report_uses_stabilized_verdict_and_confidence_schema(settings):
    result = await generate_ioc_report_workflow(FakeClient(), settings, "1.2.3.4")

    assert result["title"] == "IOC report: 1.2.3.4"
    assert result["verdict"] in VALID_VERDICTS
    assert result["confidence"] in VALID_CONFIDENCE
    assert result["verdict"] == "suspicious"
    assert result["confidence"] == "low"
    assert isinstance(result["verdict_reason"], str) and result["verdict_reason"]
    assert result["confidence_score"] > 0
    assert result["misp_findings"][0]["title"] == "MISP matches"
    assert result["context"]["possible_malware_families"] == ["test"]
    assert result["related_iocs"] == [
        {
            "type": "domain",
            "value": "c2.example.test",
            "event_ids": [1],
            "categories": ["Network activity"],
            "tags": [],
        }
    ]
    assert result["raw_references"] == [
        {"type": "event", "id": 1, "url": f"{settings.misp_base_url}/events/view/1"}
    ]
    assert "recommended_actions" in result
