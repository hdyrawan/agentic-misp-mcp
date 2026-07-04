from __future__ import annotations

from typing import Any

from agentic_misp_mcp.workflows.investigation_engine import collect_related_ioc_candidates

# Higher weight = more useful for hunting/detection engineering.
IOC_TYPE_USEFULNESS = {
    "sha256": 10,
    "filename|sha256": 10,
    "sha1": 9,
    "filename|sha1": 9,
    "md5": 8,
    "filename|md5": 8,
    "domain": 7,
    "hostname": 6,
    "url": 6,
    "ip-dst": 5,
    "ip-src": 5,
    "email-src": 4,
    "email-dst": 4,
}
DEFAULT_IOC_USEFULNESS = 3
EVENT_COVERAGE_WEIGHT = 5


def score_related_ioc(*, ioc_type: str, event_count: int) -> int:
    weight = IOC_TYPE_USEFULNESS.get(ioc_type, DEFAULT_IOC_USEFULNESS)
    return weight + event_count * EVENT_COVERAGE_WEIGHT


def rank_related_iocs(
    *, primary_ioc: str, related_events: list[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    """Rank IOCs co-occurring with the primary IOC by event coverage and type usefulness."""
    candidates = collect_related_ioc_candidates(
        primary_ioc=primary_ioc, related_events=related_events
    )
    ranked = [
        {
            "value": candidate["value"],
            "type": candidate["type"],
            "source_event_ids": candidate["event_ids"],
            "relationship": "same_event",
            "score": score_related_ioc(
                ioc_type=candidate["type"], event_count=len(candidate["event_ids"])
            ),
        }
        for candidate in candidates
    ]
    ranked.sort(key=lambda item: (-item["score"], item["type"], item["value"]))
    return ranked[:limit]
