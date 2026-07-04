from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.event_context import expand_related_events
from agentic_misp_mcp.workflows.explain_event_context import explain_event_context_workflow


class FakeClient:
    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info="Targeted phishing campaign",
            date="2026-01-01",
            threat_level_id="1",
            analysis="2",
            distribution="1",
            tags=[
                "misp-galaxy:threat-actor=example-actor",
                "misp-galaxy:ransomware=example-ransomware",
                "misp-galaxy:campaign=example-campaign",
                "misp-galaxy:mitre-attack-pattern=T1566",
                "tlp:amber",
            ],
            attribute_count=2,
            attributes_by_type={"domain": 1, "sha256": 1},
            attributes=[
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value="c2.example.test",
                ),
                MISPAttributeSummary(
                    event_id=event_id,
                    type="sha256",
                    category="Payload delivery",
                    value="a" * 64,
                ),
            ],
        )


class MinimalEventClient:
    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="bare event")


@pytest.mark.asyncio
async def test_explain_event_context_summarizes_metadata_and_context(settings):
    result = await explain_event_context_workflow(FakeClient(), settings, 99)

    assert result["event_id"] == 99
    assert result["event_info"] == "Targeted phishing campaign"
    assert result["event_date"] == "2026-01-01"
    assert result["threat_level"] == "High"
    assert result["analysis_status"] == "Completed"
    assert result["attribute_summary"] == {"domain": 1, "sha256": 1}
    assert result["context"]["possible_threat_actors"] == ["example-actor"]
    assert result["context"]["possible_malware_families"] == ["example-ransomware"]
    assert result["context"]["possible_campaigns"] == ["example-campaign"]
    assert result["context"]["mitre_attack"] == ["T1566"]
    assert result["context"]["notable_tags"] == ["tlp:amber"]
    assert {ioc["value"] for ioc in result["key_iocs"]} == {"c2.example.test", "a" * 64}
    assert "raw" not in result
    assert "Event" not in result


@pytest.mark.asyncio
async def test_explain_event_context_produces_deterministic_explanation(settings):
    result_a = await explain_event_context_workflow(FakeClient(), settings, 99)
    result_b = await explain_event_context_workflow(FakeClient(), settings, 99)

    assert result_a["explanation"] == result_b["explanation"]
    assert "Targeted phishing campaign" in result_a["explanation"]
    assert "example-actor" in result_a["explanation"]
    assert result_a["recommended_next_steps"]


@pytest.mark.asyncio
async def test_explain_event_context_handles_minimal_event(settings):
    result = await explain_event_context_workflow(MinimalEventClient(), settings, 1)

    assert result["context"] == {
        "possible_malware_families": [],
        "possible_threat_actors": [],
        "possible_campaigns": [],
        "mitre_attack": [],
        "notable_tags": [],
    }
    assert result["key_iocs"] == []
    assert isinstance(result["explanation"], str) and result["explanation"]


class SensitiveFailureClient:
    async def get_event(self, event_id, attribute_limit):
        raise RuntimeError(
            "MISP backend failed Authorization=Bearer leaked-token "
            "MISP_API_KEY=leaked-key approval_token=leaked-approval"
        )


@pytest.mark.asyncio
async def test_related_event_error_message_is_sanitized(settings):
    result = await expand_related_events(SensitiveFailureClient(), settings, [42])

    message = result[0]["message"]
    assert result[0]["status"] == "error"
    assert "leaked-token" not in message
    assert "leaked-key" not in message
    assert "leaked-approval" not in message
    assert "[REDACTED]" in message
