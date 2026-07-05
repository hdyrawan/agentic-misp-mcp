from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPEventSummary,
    parse_misp_datetime,
)
from agentic_misp_mcp.settings import Settings


class FreshnessLabel(StrEnum):
    """Age classification for the newest known intel signal behind an IOC."""

    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


def freshness_label(
    age_days: float | None,
    *,
    fresh_days: int,
    aging_days: int,
    stale_days: int,
) -> FreshnessLabel:
    """Map a signal age in days to a freshness label.

    Boundary semantics: an age exactly equal to a threshold still belongs to that
    threshold's bucket (<= fresh_days is fresh, <= aging_days is aging, <= stale_days
    is stale, beyond is expired). A negative age (clock skew, future-dated intel) is fresh.
    """
    if age_days is None:
        return FreshnessLabel.UNKNOWN
    if age_days <= fresh_days:
        return FreshnessLabel.FRESH
    if age_days <= aging_days:
        return FreshnessLabel.AGING
    if age_days <= stale_days:
        return FreshnessLabel.STALE
    return FreshnessLabel.EXPIRED


def age_weight(label: FreshnessLabel | str, weights: tuple[float, float, float, float]) -> float:
    """Return the score multiplier for a freshness label.

    `unknown` weighs 1.0: the absence of a timestamp must not reduce (or add)
    confidence — it is surfaced as a label instead of silently discounting evidence.
    """
    resolved = FreshnessLabel(str(label))
    by_label = {
        FreshnessLabel.FRESH: weights[0],
        FreshnessLabel.AGING: weights[1],
        FreshnessLabel.STALE: weights[2],
        FreshnessLabel.EXPIRED: weights[3],
    }
    return by_label.get(resolved, 1.0)


def compute_newest_signal(
    matches: list[MISPAttributeSummary],
    events: list[MISPEventSummary],
) -> tuple[datetime | None, dict[str, str | None]]:
    """Return the newest known intel timestamp and the per-source newest signals.

    Sources, per docs/improvement-plan-v0.3.0.md §2.2: attribute `last_seen`, attribute
    `timestamp`, event `publish_timestamp`, event `timestamp`. `first_seen` is deliberately
    not a freshness signal (it marks when activity started, not how current the intel is).
    """
    signals: dict[str, datetime | None] = {
        "attribute_last_seen": _newest(match.last_seen for match in matches),
        "attribute_timestamp": _newest(match.timestamp for match in matches),
        "event_publish_timestamp": _newest(event.publish_timestamp for event in events),
        "event_timestamp": _newest(event.timestamp for event in events),
    }
    newest = _newest(iter(signals.values()))
    rendered = {
        name: value.isoformat() if value is not None else None for name, value in signals.items()
    }
    return newest, rendered


def build_freshness(
    matches: list[MISPAttributeSummary],
    events: list[MISPEventSummary],
    *,
    settings: Settings,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the additive `freshness` response block (plan §2.4)."""
    now = now or datetime.now(timezone.utc)  # noqa: UP017
    newest, signals = compute_newest_signal(matches, events)
    age_days: float | None = None
    if newest is not None:
        age_days = (now - newest).total_seconds() / 86400
    label = freshness_label(
        age_days,
        fresh_days=settings.freshness_fresh_days,
        aging_days=settings.freshness_aging_days,
        stale_days=settings.freshness_stale_days,
    )
    return {
        "label": label.value,
        "newest_signal_age_days": int(age_days) if age_days is not None else None,
        "age_weight": age_weight(label, settings.age_weights),
        "signals": signals,
        "thresholds_days": {
            "fresh": settings.freshness_fresh_days,
            "aging": settings.freshness_aging_days,
            "stale": settings.freshness_stale_days,
        },
    }


def build_freshness_from_expanded_events(
    matches: list[MISPAttributeSummary],
    related_events: list[dict[str, Any]],
    *,
    settings: Settings,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the freshness block from `event_context.expand_related_events` dicts.

    Errored event entries carry no timestamps and are skipped.
    """
    events = [
        MISPEventSummary(
            id=int(event.get("id") or 0),
            timestamp=parse_misp_datetime(event.get("timestamp")),
            publish_timestamp=parse_misp_datetime(event.get("publish_timestamp")),
        )
        for event in related_events
        if event.get("status") != "error"
    ]
    return build_freshness(matches, events, settings=settings, now=now)


def _newest(values: Any) -> datetime | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None
