from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.investigate_ioc import investigate_ioc_workflow

REPORT_TYPE = "ioc_report"


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
    has_errored_events = any(event.get("status") == "error" for event in related_events)

    key_findings = _build_key_findings(
        verdict=verdict,
        verdict_reason=investigation["verdict_reason"],
        match_count=match_count,
        related_event_count=len(related_events),
        related_ioc_count=len(related_iocs),
        context=context,
        warninglists=warninglists,
    )
    limitations = _build_limitations(
        warninglists=warninglists,
        has_errored_events=has_errored_events,
        match_count=match_count,
    )

    return {
        "report_type": REPORT_TYPE,
        "title": f"IOC report: {ioc['value']}",
        "executive_summary": investigation["assessment_summary"],
        "ioc": ioc,
        "verdict": verdict,
        "confidence": investigation["confidence"],
        "confidence_score": investigation["confidence_score"],
        "freshness": investigation["freshness"],
        "key_findings": key_findings,
        "misp_findings": {
            "match_count": match_count,
            "related_event_count": len(related_events),
            "related_ioc_count": len(related_iocs),
        },
        "warninglist_findings": {
            "status": warninglists.get("status"),
            "hit": warninglists.get("hit"),
            "detail": _warninglist_detail(warninglists),
        },
        "context": context,
        "related_events": related_events,
        "related_iocs": related_iocs,
        "recommended_actions": investigation["recommended_next_steps"],
        "limitations": limitations,
        "raw_references": investigation["raw_references"],
    }


def _build_key_findings(
    *,
    verdict: str,
    verdict_reason: str,
    match_count: int,
    related_event_count: int,
    related_ioc_count: int,
    context: dict[str, list[str]],
    warninglists: dict[str, Any],
) -> list[str]:
    findings = [f"Verdict: {verdict} — {verdict_reason}"]
    if match_count:
        findings.append(f"{match_count} MISP match(es) found for this IOC.")
    else:
        findings.append("No MISP matches were found for this IOC.")
    if related_event_count:
        findings.append(f"{related_event_count} related event(s) expanded.")
    if related_ioc_count:
        findings.append(f"{related_ioc_count} related IOC(s) extracted for pivoting.")
    if context["possible_malware_families"]:
        findings.append(
            "Possible malware families: " + ", ".join(context["possible_malware_families"]) + "."
        )
    if context["possible_threat_actors"]:
        findings.append(
            "Possible threat actors: " + ", ".join(context["possible_threat_actors"]) + "."
        )
    if context["possible_campaigns"]:
        findings.append("Possible campaigns: " + ", ".join(context["possible_campaigns"]) + ".")
    if context["mitre_attack"]:
        findings.append("MITRE ATT&CK reference(s): " + ", ".join(context["mitre_attack"]) + ".")
    if warninglists.get("hit"):
        findings.append("IOC appears on a MISP warninglist.")
    return findings


def _build_limitations(
    *, warninglists: dict[str, Any], has_errored_events: bool, match_count: int
) -> list[str]:
    limitations: list[str] = []
    if warninglists.get("status") == "not_available":
        limitations.append("Warninglist context was unavailable for this IOC.")
    if warninglists.get("status") == "error":
        limitations.append("Warninglist check failed; results may be incomplete.")
    if has_errored_events:
        limitations.append("Some related events could not be retrieved and were excluded.")
    if match_count == 0:
        limitations.append(
            "This IOC was not found in MISP; the verdict relies solely on the absence of data."
        )
    limitations.append(
        "This report is generated deterministically from available MISP data and does not "
        "replace analyst judgement."
    )
    return limitations


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
