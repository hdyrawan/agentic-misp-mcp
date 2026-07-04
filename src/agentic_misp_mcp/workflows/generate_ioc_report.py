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
    assessment = investigation["assessment"]
    warninglists = investigation["warninglists"]
    match_count = investigation["match_count"]
    related_events = investigation["related_events"]

    return {
        "title": f"IOC report: {ioc['value']}",
        "executive_summary": assessment["summary"],
        "ioc": ioc,
        "misp_findings": [
            {
                "title": "MISP matches",
                "detail": f"Found {match_count} matching attribute(s) in MISP.",
                "severity": "informational" if match_count else "low",
            }
        ],
        "warninglist_findings": [
            {
                "title": "Warninglist check",
                "detail": str(
                    warninglists.get("message") or warninglists.get("recommended_handling")
                ),
                "severity": "low" if warninglists.get("hit") else "informational",
            }
        ],
        "related_events": related_events,
        "tags": investigation["tags"],
        "confidence": assessment["confidence"],
        "recommended_actions": investigation["recommended_next_steps"],
    }
