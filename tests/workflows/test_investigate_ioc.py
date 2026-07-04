from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow
from agentic_misp_mcp.workflows.investigation_engine import VALID_CONFIDENCE, VALID_VERDICTS


class FakeClient:
    """Multiple MISP matches with malicious tags and rich related-event context."""

    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(
                event_id=1,
                type="ip-dst",
                value=value,
                to_ids=True,
                tags=["tlp:amber", "malware:family=test"],
            ),
            MISPAttributeSummary(event_id=2, type="ip-dst", value=value, to_ids=True),
            MISPAttributeSummary(event_id=3, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=4, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=5, type="ip-dst", value=value),
            MISPAttributeSummary(event_id=6, type="ip-dst", value=value),
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info=f"event {event_id}",
            date=f"2026-01-0{min(event_id, 9)}",
            threat_level_id="2",
            tags=["misp-galaxy:threat-actor=example"],
            attribute_count=999,
            attributes_by_type={"ip-dst": 1, "domain": 1, "sha256": 1},
            attributes=[
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value=f"c2-{event_id}.example.test",
                    tags=["malware:infrastructure"],
                ),
                MISPAttributeSummary(
                    event_id=event_id,
                    type="sha256",
                    category="Payload delivery",
                    value=f"{'a' * 63}{event_id % 10}",
                ),
            ],
        )

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


class WarninglistClient(FakeClient):
    """A single, weakly-tagged match that also hits a warninglist."""

    async def search_attributes(self, value, limit):
        return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]

    async def check_warninglists(self, value):
        return WarninglistCheckResult(
            status="available", hit=True, matches=[{"name": "common-infra"}]
        )


class WeakHitClient:
    """A single match with a malicious tag but no other corroborating signal."""

    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(
                event_id=1,
                type="ip-dst",
                value=value,
                tags=["malware:family=weak"],
            )
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="event", attribute_count=0)

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


class NoHitClient:
    """No MISP matches at all."""

    async def search_attributes(self, value, limit):
        return []

    async def get_event(self, event_id, attribute_limit):
        raise AssertionError("get_event should not be called when there are no matches")

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


@pytest.mark.asyncio
async def test_investigate_ioc_multiple_malicious_hits_are_likely_malicious(settings):
    result = await investigate_ioc_workflow(FakeClient(), settings, "1.2.3.4", 20)

    assert result["match_count"] == 6
    assert len(result["related_events"]) == settings.misp_related_event_limit
    assert result["context"]["possible_malware_families"] == ["infrastructure", "test"]
    assert result["context"]["possible_threat_actors"] == ["example"]
    assert result["context"]["notable_tags"] == ["tlp:amber"]
    assert result["confidence_score"] >= 75
    assert result["verdict"] == "likely_malicious"
    assert result["confidence"] == "high"
    assert len(result["related_iocs"]) == 10
    assert result["related_iocs"][0]["type"] == "domain"
    assert (
        "Pivot on extracted related IOCs for additional campaign context."
        in result["recommended_next_steps"]
    )
    assert result["raw_references"] == [
        {
            "type": "event",
            "id": event_id,
            "url": f"{settings.misp_base_url}/events/view/{event_id}",
        }
        for event_id in range(1, 7)
    ]
    assert "matches" not in result
    assert "scoring" not in result
    assert "assessment" not in result


@pytest.mark.asyncio
async def test_investigate_ioc_weak_single_hit_is_suspicious(settings):
    result = await investigate_ioc_workflow(WeakHitClient(), settings, "5.6.7.8", 20)

    assert result["match_count"] == 1
    assert result["confidence_score"] < 45
    assert result["verdict"] == "suspicious"


@pytest.mark.asyncio
async def test_investigate_ioc_no_hit_is_unknown(settings):
    result = await investigate_ioc_workflow(NoHitClient(), settings, "9.9.9.9", 20)

    assert result["match_count"] == 0
    assert result["verdict"] == "unknown"
    assert result["confidence"] == "low"
    assert result["raw_references"] == []


@pytest.mark.asyncio
async def test_investigate_ioc_warninglist_hit_without_context_is_likely_benign(settings):
    result = await investigate_ioc_workflow(WarninglistClient(), settings, "8.8.8.8", 20)

    assert result["warninglists"]["hit"] is True
    assert result["verdict"] == "likely_benign_or_noise"
    assert result["confidence_score"] < 40
    reason_names = {reason.split(":", 1)[0] for reason in result["confidence_reasons"]}
    assert "warninglist_hit" in reason_names


@pytest.mark.asyncio
async def test_investigate_ioc_verdict_and_confidence_stay_within_public_enum(settings):
    clients = [FakeClient(), WarninglistClient(), WeakHitClient(), NoHitClient()]
    for client in clients:
        result = await investigate_ioc_workflow(client, settings, "1.2.3.4", 20)
        assert result["verdict"] in VALID_VERDICTS
        assert result["confidence"] in VALID_CONFIDENCE
