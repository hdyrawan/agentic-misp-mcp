from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from agentic_misp_mcp.models.misp import MISPAttributeSummary
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.intel_freshness import build_freshness_from_expanded_events

MALICIOUS_TAG_KEYWORDS = (
    "malware",
    "ransomware",
    "apt",
    "botnet",
    "c2",
    "command-and-control",
    "phishing",
    "trojan",
    "exploit",
    "misp-galaxy",
)
BENIGN_TAG_KEYWORDS = ("false-positive", "benign", "known-good", "allowlist", "whitelist")
HIGH_VALUE_IOC_TYPES = {
    "ip-src",
    "ip-dst",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "filename|sha256",
    "filename|md5",
    "filename|sha1",
    "email-src",
    "email-dst",
}

THREAT_ACTOR_TAG_KEYWORDS = ("threat-actor", "intrusion-set")
CAMPAIGN_TAG_KEYWORDS = ("campaign",)
MITRE_TAG_KEYWORDS = ("mitre-attack", "attack-pattern")
MITRE_TECHNIQUE_PATTERN = re.compile(r"\bt\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
MALWARE_TAG_KEYWORDS = (
    "malware",
    "ransomware",
    "trojan",
    "backdoor",
    "worm",
    "rat",
    "botnet",
    "c2",
    "command-and-control",
    "phishing",
    "exploit",
)

VALID_VERDICTS = {
    "likely_malicious",
    "suspicious",
    "unknown",
    "likely_benign_or_noise",
}
VALID_CONFIDENCE = {"high", "medium", "low"}

# Expired-only intel (no high-confidence floor) cannot score past this bound, keeping it
# below the likely_malicious verdict threshold (75) — see docs/improvement-plan-v0.3.0.md §2.3.
EXPIRED_SCORE_CAP = 60


def build_investigation_enrichment(
    *,
    primary_ioc: str,
    matches: list[MISPAttributeSummary],
    related_events: list[dict[str, Any]],
    warninglists: dict[str, Any],
    tags: list[str],
    settings: Settings | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build deterministic agentic investigation fields from normalized MISP data.

    When `settings` is provided, the result gains a `freshness` block and — if
    `settings.age_weighting` is enabled — age-aware weighting is applied to the score
    (see docs/improvement-plan-v0.3.0.md §2.2/§2.3). Without `settings` the output is
    identical to the pre-freshness engine, which keeps this callable stable for callers
    and tests that predate age-aware scoring.
    """
    context = classify_tags(tags)
    related_iocs = extract_related_iocs(primary_ioc=primary_ioc, related_events=related_events)
    freshness = (
        build_freshness_from_expanded_events(matches, related_events, settings=settings, now=now)
        if settings is not None
        else None
    )
    # The high-confidence floor (plan §2.3): curated actionable intel — an actionable
    # (to_ids) match plus threat-actor/malware attribution — ages slower than
    # uncorroborated OSINT and is exempt from the expired score cap.
    high_confidence_intel = any(match.to_ids is True for match in matches) and bool(
        context["possible_threat_actors"] or context["possible_malware_families"]
    )
    scoring = calculate_score(
        matches=matches,
        related_events=related_events,
        warninglists=warninglists,
        tags=tags,
        related_iocs=related_iocs,
        freshness=freshness,
        age_weighting=bool(settings is not None and settings.age_weighting),
        age_weights=settings.age_weights if settings is not None else (1.0, 0.75, 0.4, 0.15),
        high_confidence_intel=high_confidence_intel,
    )
    has_malicious_context = bool(
        context["possible_malware_families"]
        or context["possible_threat_actors"]
        or context["possible_campaigns"]
        or context["mitre_attack"]
    ) or any(match.to_ids is True for match in matches)
    verdict, verdict_reason = calculate_verdict(
        scoring["score"],
        warninglist_hit=bool(warninglists.get("hit")),
        seen=bool(matches),
        has_malicious_context=has_malicious_context,
    )
    confidence = calculate_confidence(scoring["score"])
    confidence_reasons = build_confidence_reasons(scoring["factors"])
    has_errored_events = any(event.get("status") == "error" for event in related_events)
    recommendations = build_recommendations(
        verdict=verdict,
        warninglists=warninglists,
        seen=bool(matches),
        related_iocs=related_iocs,
        has_errored_events=has_errored_events,
    )
    enrichment = {
        "context": context,
        "related_iocs": related_iocs,
        "confidence_score": scoring["score"],
        "confidence": confidence,
        "confidence_reasons": confidence_reasons,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "recommended_next_steps": recommendations,
    }
    if freshness is not None:
        enrichment["freshness"] = freshness
    return enrichment


def _tag_value(tag: str) -> str:
    if "=" in tag:
        return tag.split("=", 1)[1].strip('"')
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag


def classify_tags(tags: list[str]) -> dict[str, list[str]]:
    """Classify raw MISP tags into the stabilized public context shape."""
    malware_families: list[str] = []
    threat_actors: list[str] = []
    campaigns: list[str] = []
    mitre_attack: list[str] = []
    notable_tags: list[str] = []

    for tag in tags:
        lowered = tag.lower()
        if _contains_any(lowered, THREAT_ACTOR_TAG_KEYWORDS):
            threat_actors.append(_tag_value(tag))
        elif _contains_any(lowered, CAMPAIGN_TAG_KEYWORDS):
            campaigns.append(_tag_value(tag))
        elif _contains_any(lowered, MITRE_TAG_KEYWORDS) or MITRE_TECHNIQUE_PATTERN.search(lowered):
            mitre_attack.append(_tag_value(tag))
        elif _contains_any(lowered, MALWARE_TAG_KEYWORDS):
            malware_families.append(_tag_value(tag))
        else:
            notable_tags.append(tag)

    return {
        "possible_malware_families": sorted(set(malware_families)),
        "possible_threat_actors": sorted(set(threat_actors)),
        "possible_campaigns": sorted(set(campaigns)),
        "mitre_attack": sorted(set(mitre_attack)),
        "notable_tags": sorted(set(notable_tags)),
    }


def collect_related_ioc_candidates(
    *, primary_ioc: str, related_events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Collect high-value IOCs co-occurring with the primary IOC's related events.

    Returns unsorted, uncapped candidates so callers can apply their own ranking
    (see `extract_related_iocs` below and `workflows/pivoting.py`).
    """
    primary = primary_ioc.lower()
    collected: dict[tuple[str, str], dict[str, Any]] = {}
    for event in related_events:
        if event.get("status") == "error":
            continue
        event_id = event.get("id")
        for attribute in event.get("key_attributes") or []:
            if not isinstance(attribute, dict):
                continue
            value = attribute.get("value")
            attr_type = attribute.get("type") or "unknown"
            if not value or str(value).lower() == primary:
                continue
            if attr_type not in HIGH_VALUE_IOC_TYPES:
                continue
            key = (str(attr_type), str(value))
            item = collected.setdefault(
                key,
                {
                    "type": str(attr_type),
                    "value": str(value),
                    "event_ids": [],
                    "categories": [],
                    "tags": [],
                },
            )
            if event_id is not None and event_id not in item["event_ids"]:
                item["event_ids"].append(event_id)
            category = attribute.get("category")
            if category and category not in item["categories"]:
                item["categories"].append(category)
            for tag in attribute.get("tags") or []:
                if tag not in item["tags"]:
                    item["tags"].append(tag)
    return list(collected.values())


def extract_related_iocs(
    *, primary_ioc: str, related_events: list[dict[str, Any]], max_iocs: int = 25
) -> list[dict[str, Any]]:
    candidates = collect_related_ioc_candidates(
        primary_ioc=primary_ioc, related_events=related_events
    )
    related = sorted(
        candidates,
        key=lambda item: (-len(item["event_ids"]), item["type"], item["value"]),
    )
    return related[:max_iocs]


def calculate_score(
    *,
    matches: list[MISPAttributeSummary],
    related_events: list[dict[str, Any]],
    warninglists: dict[str, Any],
    tags: list[str],
    related_iocs: list[dict[str, Any]],
    freshness: dict[str, Any] | None = None,
    age_weighting: bool = False,
    age_weights: tuple[float, float, float, float] = (1.0, 0.75, 0.4, 0.15),
    high_confidence_intel: bool = False,
) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []
    score = 0

    # Age weighting (plan §2.3): the weight discounts positive evidence only; penalties
    # (warninglist/benign tags) always apply at full strength. `unknown` weighs 1.0 —
    # a missing timestamp must not manufacture confidence in either direction.
    weight = 1.0
    freshness_label_value = "unknown"
    if age_weighting and freshness is not None:
        freshness_label_value = str(freshness.get("label", "unknown"))
        weight = float(freshness.get("age_weight", 1.0))
        if high_confidence_intel:
            weight = max(weight, age_weights[2])

    def weighted(points: int) -> int:
        if weight >= 1.0 or points <= 0:
            return points
        return max(1, round(points * weight))

    match_count = len(matches)
    if match_count:
        points = weighted(min(35, 10 + match_count * 5))
        score += points
        factors.append(
            {"name": "misp_matches", "points": points, "detail": f"{match_count} match(es)"}
        )

    to_ids_count = sum(1 for match in matches if match.to_ids is True)
    if to_ids_count:
        points = weighted(min(20, to_ids_count * 5))
        score += points
        factors.append(
            {"name": "to_ids", "points": points, "detail": f"{to_ids_count} actionable match(es)"}
        )

    expanded_events = [event for event in related_events if event.get("status") != "error"]
    if expanded_events:
        points = weighted(min(20, len(expanded_events) * 4))
        score += points
        factors.append(
            {
                "name": "related_events",
                "points": points,
                "detail": f"{len(expanded_events)} related event(s)",
            }
        )

    malicious_tags = [tag for tag in tags if _contains_any(tag, MALICIOUS_TAG_KEYWORDS)]
    if malicious_tags:
        points = weighted(min(20, len(malicious_tags) * 5))
        score += points
        factors.append({"name": "threat_tags", "points": points, "detail": malicious_tags})

    if related_iocs:
        points = weighted(min(10, len(related_iocs) * 2))
        score += points
        factors.append(
            {"name": "related_iocs", "points": points, "detail": f"{len(related_iocs)} extracted"}
        )

    benign_tags = [tag for tag in tags if _contains_any(tag, BENIGN_TAG_KEYWORDS)]
    if benign_tags:
        points = -20
        score += points
        factors.append({"name": "benign_tags", "points": points, "detail": benign_tags})

    if warninglists.get("hit") is True:
        points = -30
        score += points
        factors.append(
            {
                "name": "warninglist_hit",
                "points": points,
                "detail": "IOC appears on a warninglist",
            }
        )
    elif warninglists.get("status") == "not_available":
        factors.append(
            {
                "name": "warninglist_not_available",
                "points": 0,
                "detail": "Warninglist context unavailable",
            }
        )

    if age_weighting and freshness is not None:
        if freshness_label_value == "unknown":
            factors.append(
                {
                    "name": "intel_age_unknown",
                    "points": 0,
                    "detail": "no intel timestamps available; evidence not discounted",
                }
            )
        else:
            factors.append(
                {
                    "name": "intel_age",
                    "points": 0,
                    "detail": f"label={freshness_label_value}, weight={weight}",
                }
            )

    bounded_score = max(0, min(100, score))

    # Verdict guard (plan §2.3): expired-only intel without the high-confidence floor can
    # reach `suspicious` but never `likely_malicious` without fresh corroboration.
    if (
        age_weighting
        and freshness_label_value == "expired"
        and not high_confidence_intel
        and bounded_score > EXPIRED_SCORE_CAP
    ):
        factors.append(
            {
                "name": "intel_age_cap",
                "points": 0,
                "detail": (
                    f"expired intel capped score from {bounded_score} to {EXPIRED_SCORE_CAP}"
                ),
            }
        )
        bounded_score = EXPIRED_SCORE_CAP

    return {"score": bounded_score, "scale": "0-100", "factors": factors}


def calculate_verdict(
    score: int,
    *,
    warninglist_hit: bool,
    seen: bool,
    has_malicious_context: bool,
) -> tuple[str, str]:
    """Map score + context signals to the stabilized public verdict enum."""
    if warninglist_hit and score < 40:
        return (
            "likely_benign_or_noise",
            "Warninglist hit outweighs limited malicious context.",
        )
    if score >= 75:
        return (
            "likely_malicious",
            "Multiple MISP signals and contextual indicators strongly support malicious activity.",
        )
    if score >= 45:
        return (
            "suspicious",
            "MISP context supports analyst review and correlation.",
        )
    if seen and has_malicious_context:
        return (
            "suspicious",
            "IOC is present in MISP with limited but relevant malicious context.",
        )
    if seen:
        return (
            "unknown",
            "IOC is present in MISP but has no meaningful malicious context.",
        )
    return (
        "unknown",
        "IOC was not found in MISP and requires external corroboration.",
    )


def calculate_confidence(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def build_confidence_reasons(factors: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    for factor in factors:
        detail = factor["detail"]
        detail_str = (
            ", ".join(str(item) for item in detail) if isinstance(detail, list) else str(detail)
        )
        points = factor["points"]
        sign = "+" if points >= 0 else ""
        reasons.append(f"{factor['name']}: {sign}{points} ({detail_str})")
    return reasons


def build_recommendations(
    *,
    verdict: str,
    warninglists: dict[str, Any],
    seen: bool,
    related_iocs: list[dict[str, Any]],
    has_errored_events: bool,
) -> list[str]:
    recommendations: list[str] = []
    if verdict in {"likely_malicious", "suspicious"}:
        recommendations.append("Correlate the IOC with SIEM/EDR telemetry and recent sightings.")
        recommendations.append("Review related MISP events, tags, and extracted related IOCs.")
    elif verdict == "likely_benign_or_noise":
        recommendations.append("Validate warninglist context before escalating or blocking.")
    elif seen:
        recommendations.append("Review the related MISP event context before escalating.")
    else:
        recommendations.append("Corroborate the IOC with external telemetry before escalation.")

    if related_iocs:
        recommendations.append("Pivot on extracted related IOCs for additional campaign context.")
    if warninglists.get("status") == "not_available":
        recommendations.append(
            "Manually verify warninglist/common-infrastructure status if needed."
        )
    if has_errored_events:
        recommendations.append("Retry event expansion for events that returned errors.")
    return recommendations


def _contains_any(value: str, keywords: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in keywords)
