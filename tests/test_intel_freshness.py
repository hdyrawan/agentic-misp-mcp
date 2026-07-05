from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.intel_freshness import (
    FreshnessLabel,
    age_weight,
    build_freshness,
    compute_newest_signal,
    freshness_label,
)

DEFAULT_WEIGHTS = (1.0, 0.75, 0.4, 0.15)


def _label(age_days):
    return freshness_label(age_days, fresh_days=30, aging_days=90, stale_days=365)


@pytest.mark.parametrize(
    ("age_days", "expected"),
    [
        (29, FreshnessLabel.FRESH),
        (30, FreshnessLabel.FRESH),
        (31, FreshnessLabel.AGING),
        (89, FreshnessLabel.AGING),
        (90, FreshnessLabel.AGING),
        (91, FreshnessLabel.STALE),
        (364, FreshnessLabel.STALE),
        (365, FreshnessLabel.STALE),
        (366, FreshnessLabel.EXPIRED),
        (0, FreshnessLabel.FRESH),
        (-1, FreshnessLabel.FRESH),
        (None, FreshnessLabel.UNKNOWN),
    ],
)
def test_freshness_label_boundaries(age_days, expected):
    assert _label(age_days) is expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        (FreshnessLabel.FRESH, 1.0),
        (FreshnessLabel.AGING, 0.75),
        (FreshnessLabel.STALE, 0.4),
        (FreshnessLabel.EXPIRED, 0.15),
        (FreshnessLabel.UNKNOWN, 1.0),
        ("stale", 0.4),
    ],
)
def test_age_weight_mapping(label, expected):
    assert age_weight(label, DEFAULT_WEIGHTS) == expected


def test_compute_newest_signal_prefers_newest_across_sources():
    old = datetime(2016, 1, 1, tzinfo=UTC)
    newer = datetime(2026, 6, 1, tzinfo=UTC)
    newest = datetime(2026, 7, 1, tzinfo=UTC)
    matches = [
        MISPAttributeSummary(value="1.2.3.4", timestamp=old, last_seen=None),
        MISPAttributeSummary(value="1.2.3.4", timestamp=newer, last_seen=newest),
    ]
    events = [MISPEventSummary(id=1, publish_timestamp=old, timestamp=old)]

    result, signals = compute_newest_signal(matches, events)

    assert result == newest
    assert signals["attribute_last_seen"] == newest.isoformat()
    assert signals["attribute_timestamp"] == newer.isoformat()
    assert signals["event_publish_timestamp"] == old.isoformat()
    assert signals["event_timestamp"] == old.isoformat()


def test_compute_newest_signal_all_missing_is_none():
    matches = [MISPAttributeSummary(value="1.2.3.4")]
    events = [MISPEventSummary(id=1)]

    result, signals = compute_newest_signal(matches, events)

    assert result is None
    assert all(value is None for value in signals.values())


def _settings(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings()


def test_build_freshness_stale_block(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)
    now = datetime(2026, 7, 5, tzinfo=UTC)
    signal = now - timedelta(days=100)
    matches = [MISPAttributeSummary(value="1.2.3.4", timestamp=signal)]

    block = build_freshness(matches, [], settings=settings, now=now)

    assert block["label"] == "stale"
    assert block["newest_signal_age_days"] == 100
    assert block["age_weight"] == 0.4
    assert block["signals"]["attribute_timestamp"] == signal.isoformat()
    assert block["thresholds_days"] == {"fresh": 30, "aging": 90, "stale": 365}


def test_build_freshness_unknown_when_no_timestamps(monkeypatch, tmp_path):
    settings = _settings(monkeypatch, tmp_path)

    block = build_freshness(
        [MISPAttributeSummary(value="1.2.3.4")], [MISPEventSummary(id=7)], settings=settings
    )

    assert block["label"] == "unknown"
    assert block["newest_signal_age_days"] is None
    assert block["age_weight"] == 1.0


def test_build_freshness_honors_configured_thresholds_and_weights(monkeypatch, tmp_path):
    settings = _settings(
        monkeypatch,
        tmp_path,
        AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS="7",
        AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS="14",
        AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS="60",
        AGENTIC_MISP_MCP_AGE_WEIGHTS="1.0,0.9,0.5,0.1",
    )
    now = datetime(2026, 7, 5, tzinfo=UTC)
    matches = [MISPAttributeSummary(value="x", timestamp=now - timedelta(days=61))]

    block = build_freshness(matches, [], settings=settings, now=now)

    assert block["label"] == "expired"
    assert block["age_weight"] == 0.1
    assert block["thresholds_days"] == {"fresh": 7, "aging": 14, "stale": 60}
