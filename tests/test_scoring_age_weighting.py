from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.investigation_engine import (
    EXPIRED_SCORE_CAP,
    build_investigation_enrichment,
    calculate_score,
)

NOW = datetime(2026, 7, 5, tzinfo=UTC)


def _settings(monkeypatch, tmp_path, **env) -> Settings:
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings()


def _matches(count: int, *, to_ids: bool = False, age_days: int | None = None, tags=None):
    timestamp = NOW - timedelta(days=age_days) if age_days is not None else None
    return [
        MISPAttributeSummary(
            event_id=index + 1,
            type="ip-dst",
            value="1.2.3.4",
            to_ids=to_ids,
            timestamp=timestamp,
            tags=list(tags or []),
        )
        for index in range(count)
    ]


def _freshness(label: str, weight: float) -> dict:
    return {"label": label, "age_weight": weight, "newest_signal_age_days": 400}


def test_age_weighting_off_is_byte_identical_to_legacy_scoring():
    matches = _matches(3, to_ids=True, tags=["malware:family=x"])
    kwargs = dict(
        matches=matches,
        related_events=[{"id": 1}, {"id": 2}],
        warninglists={"status": "available", "hit": False},
        tags=["malware:family=x", "misp-galaxy:threat-actor=apt-x"],
        related_iocs=[{"type": "domain", "value": "c2.test"}],
    )

    legacy = calculate_score(**kwargs)
    switched_off = calculate_score(
        **kwargs, freshness=_freshness("expired", 0.15), age_weighting=False
    )

    assert switched_off == legacy


def test_stale_weight_discounts_positive_factors_only():
    result = calculate_score(
        matches=_matches(3, to_ids=True),
        related_events=[{"id": 1}],
        warninglists={"status": "available", "hit": True},
        tags=["malware:family=x"],
        related_iocs=[],
        freshness=_freshness("stale", 0.4),
        age_weighting=True,
    )

    by_name = {factor["name"]: factor for factor in result["factors"]}
    assert by_name["misp_matches"]["points"] == round(25 * 0.4)
    assert by_name["to_ids"]["points"] == round(15 * 0.4)
    assert by_name["related_events"]["points"] == round(4 * 0.4)
    assert by_name["threat_tags"]["points"] == round(5 * 0.4)
    assert by_name["warninglist_hit"]["points"] == -30
    assert by_name["intel_age"]["detail"] == "label=stale, weight=0.4"


def test_weighted_nonzero_factor_never_drops_below_one_point():
    result = calculate_score(
        matches=[],
        related_events=[{"id": 1}],
        warninglists={"status": "available", "hit": False},
        tags=[],
        related_iocs=[],
        freshness=_freshness("expired", 0.15),
        age_weighting=True,
    )

    by_name = {factor["name"]: factor for factor in result["factors"]}
    assert by_name["related_events"]["points"] == 1  # round(4 * 0.15) would be 1 anyway; floor=1


def test_expired_intel_caps_score_and_records_cap_factor():
    result = calculate_score(
        matches=_matches(6, to_ids=True),
        related_events=[{"id": index} for index in range(1, 6)],
        warninglists={"status": "available", "hit": False},
        tags=["malware:a", "ransomware:b", "apt:c", "botnet:d"],
        related_iocs=[{"value": "x"}] * 5,
        freshness=_freshness("expired", 1.0),
        age_weighting=True,
    )

    assert result["score"] == EXPIRED_SCORE_CAP
    assert any(factor["name"] == "intel_age_cap" for factor in result["factors"])


def test_high_confidence_intel_floors_weight_at_stale():
    result = calculate_score(
        matches=_matches(6, to_ids=True),
        related_events=[{"id": index} for index in range(1, 6)],
        warninglists={"status": "available", "hit": False},
        tags=["malware:a", "ransomware:b", "apt:c", "botnet:d"],
        related_iocs=[{"value": "x"}] * 5,
        freshness=_freshness("expired", 0.15),
        age_weighting=True,
        age_weights=(1.0, 0.75, 0.4, 0.15),
        high_confidence_intel=True,
    )

    by_name = {factor["name"]: factor for factor in result["factors"]}
    # Floored to the stale weight (0.4), not the expired weight (0.15).
    assert by_name["misp_matches"]["points"] == round(35 * 0.4)
    assert "intel_age" in by_name


def test_high_confidence_intel_bypasses_expired_cap():
    kwargs = dict(
        matches=_matches(6, to_ids=True),
        related_events=[{"id": index} for index in range(1, 6)],
        warninglists={"status": "available", "hit": False},
        tags=["malware:a", "ransomware:b", "apt:c", "botnet:d"],
        related_iocs=[{"value": "x"}] * 5,
        freshness=_freshness("expired", 1.0),
        age_weighting=True,
    )

    capped = calculate_score(**kwargs, high_confidence_intel=False)
    uncapped = calculate_score(**kwargs, high_confidence_intel=True)

    assert capped["score"] == EXPIRED_SCORE_CAP
    assert uncapped["score"] > EXPIRED_SCORE_CAP
    assert not any(factor["name"] == "intel_age_cap" for factor in uncapped["factors"])


def test_unknown_freshness_keeps_full_points_and_flags_it():
    kwargs = dict(
        matches=_matches(3, to_ids=True),
        related_events=[{"id": 1}],
        warninglists={"status": "available", "hit": False},
        tags=["malware:family=x"],
        related_iocs=[],
    )
    legacy = calculate_score(**kwargs)
    result = calculate_score(
        **kwargs,
        freshness={"label": "unknown", "age_weight": 1.0, "newest_signal_age_days": None},
        age_weighting=True,
    )

    assert result["score"] == legacy["score"]
    assert any(factor["name"] == "intel_age_unknown" for factor in result["factors"])


def test_enrichment_without_settings_matches_legacy_and_has_no_freshness():
    matches = _matches(3, to_ids=True, age_days=400)
    kwargs = dict(
        primary_ioc="1.2.3.4",
        matches=matches,
        related_events=[],
        warninglists={"status": "available", "hit": False},
        tags=["malware:family=x"],
    )

    enrichment = build_investigation_enrichment(**kwargs)

    assert "freshness" not in enrichment


def test_enrichment_with_weighting_disabled_scores_like_legacy(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path, AGENTIC_MISP_MCP_AGE_WEIGHTING="false")
    matches = _matches(3, to_ids=True, age_days=400, tags=["malware:family=x"])
    kwargs = dict(
        primary_ioc="1.2.3.4",
        matches=matches,
        related_events=[],
        warninglists={"status": "available", "hit": False},
        tags=["malware:family=x"],
    )

    legacy = build_investigation_enrichment(**kwargs)
    disabled = build_investigation_enrichment(**kwargs, settings=settings, now=NOW)

    assert disabled["confidence_score"] == legacy["confidence_score"]
    assert disabled["confidence_reasons"] == legacy["confidence_reasons"]
    assert disabled["verdict"] == legacy["verdict"]
    assert disabled["freshness"]["label"] == "expired"


def test_enrichment_with_weighting_enabled_discounts_expired_intel(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    matches = _matches(3, to_ids=True, age_days=400)
    kwargs = dict(
        primary_ioc="1.2.3.4",
        matches=matches,
        related_events=[],
        warninglists={"status": "available", "hit": False},
        tags=[],
    )

    legacy = build_investigation_enrichment(**kwargs)
    weighted = build_investigation_enrichment(**kwargs, settings=settings, now=NOW)

    assert weighted["freshness"]["label"] == "expired"
    assert weighted["freshness"]["age_weight"] == 0.15
    assert weighted["confidence_score"] < legacy["confidence_score"]
    assert any("intel_age" in reason for reason in weighted["confidence_reasons"])


def test_fresh_intel_scores_like_legacy_with_informational_factor(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    matches = _matches(3, to_ids=True, age_days=5)
    kwargs = dict(
        primary_ioc="1.2.3.4",
        matches=matches,
        related_events=[],
        warninglists={"status": "available", "hit": False},
        tags=[],
    )

    legacy = build_investigation_enrichment(**kwargs)
    weighted = build_investigation_enrichment(**kwargs, settings=settings, now=NOW)

    assert weighted["freshness"]["label"] == "fresh"
    assert weighted["confidence_score"] == legacy["confidence_score"]
    assert any("label=fresh" in reason for reason in weighted["confidence_reasons"])


@pytest.mark.parametrize("hit", [True])
def test_warninglist_penalty_not_discounted_for_old_intel(monkeypatch, tmp_path, hit):
    settings = _settings(monkeypatch, tmp_path)
    matches = _matches(1, age_days=400)

    enrichment = build_investigation_enrichment(
        primary_ioc="10.1.2.3",
        matches=matches,
        related_events=[],
        warninglists={"status": "available", "hit": hit},
        tags=[],
        settings=settings,
        now=NOW,
    )

    factors = {
        reason.split(":")[0]: reason for reason in enrichment["confidence_reasons"]
    }
    assert "warninglist_hit" in factors
    assert "-30" in factors["warninglist_hit"]
