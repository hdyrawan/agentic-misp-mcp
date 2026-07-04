from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow


async def generate_ioc_report_workflow(
    client: MISPClient, settings: Settings, value: str
) -> dict[str, object]:
    investigation = await investigate_ioc_workflow(
        client, settings, value, limit=settings.misp_default_limit
    )
    ioc = investigation["ioc"]
    verdict = investigation["verdict"]
    warninglists = investigation["warninglists"]
    match_count = investigation["match_count"]
    related_events = investigation["related_events"]
    related_iocs = investigation["related_iocs"]
    context = investigation["context"]

    return {
        "title": f"IOC report: {ioc['value']}",
        "executive_summary": investigation["assessment_summary"],
        "ioc": ioc,
        "verdict": verdict,
        "verdict_reason": investigation["verdict_reason"],
        "confidence": investigation["confidence"],
        "confidence_score": investigation["confidence_score"],
        "confidence_reasons": investigation["confidence_reasons"],
        "context": context,
        "misp_findings": [
            {
                "title": "MISP matches",
                "detail": f"Found {match_count} matching attribute(s) in MISP.",
                "severity": _severity_for_verdict(verdict),
            },
            {
                "title": "Related context",
                "detail": (
                    f"Expanded {len(related_events)} related event(s) "
                    f"and extracted {len(related_iocs)} related IOC(s)."
                ),
                "severity": "informational",
            },
        ],
        "warninglist_findings": [
            {
                "title": "Warninglist check",
                "detail": _warninglist_detail(warninglists),
                "severity": "low" if warninglists.get("hit") else "informational",
                "status": warninglists.get("status"),
                "hit": warninglists.get("hit"),
            }
        ],
        "related_events": related_events,
        "related_iocs": related_iocs,
        "recommended_actions": investigation["recommended_next_steps"],
        "raw_references": investigation["raw_references"],
    }


def _severity_for_verdict(verdict: str) -> str:
    if verdict == "likely_malicious":
        return "high"
    if verdict == "suspicious":
        return "medium"
    if verdict == "likely_benign_or_noise":
        return "low"
    return "informational"


def _warninglist_detail(warninglists: dict[str, object]) -> str:
    status = warninglists.get("status")
    if status == "not_available":
        return "Warninglist check unavailable; interpret results without noise-list context."
    if status == "error":
        return "Warninglist check failed; retry later or verify manually in MISP."
    if warninglists.get("hit"):
        return (
            "Treat as potential benign/common infrastructure until corroborated by other evidence."
        )
    return "No warninglist hit reported by MISP."
