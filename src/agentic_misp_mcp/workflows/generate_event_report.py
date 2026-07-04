from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import build_event_references
from agentic_misp_mcp.workflows.explain_event_context import explain_event_context_workflow
from agentic_misp_mcp.workflows.extract_event_iocs import extract_event_iocs_workflow
from agentic_misp_mcp.workflows.summarize_event import summarize_event_workflow

REPORT_TYPE = "event_report"
EXTRACT_IOC_LIMIT = 100


async def generate_event_report_workflow(
    client: MISPClient, settings: Settings, event_id: int
) -> dict[str, object]:
    summary = await summarize_event_workflow(client, settings, event_id)
    explanation = await explain_event_context_workflow(client, settings, event_id)
    ioc_extraction = await extract_event_iocs_workflow(
        client, settings, event_id, EXTRACT_IOC_LIMIT
    )

    event_info = summary["event"]
    context = explanation["context"]
    iocs_by_type = ioc_extraction["iocs_by_type"]
    ioc_count = ioc_extraction["ioc_count"]

    event_section = {
        "event_id": event_info["id"],
        "info": event_info["info"],
        "date": event_info["date"],
        "threat_level": explanation["threat_level"],
        "analysis_status": explanation["analysis_status"],
        "distribution": event_info["distribution"],
    }
    executive_summary = _build_executive_summary(
        event_id=event_info["id"],
        info=event_info["info"],
        ioc_count=ioc_count,
        threat_level=explanation["threat_level"],
        context=context,
    )
    limitations = _build_limitations(
        ioc_count=ioc_count, attribute_count=summary["attribute_count"]
    )
    raw_references = build_event_references(settings=settings, event_ids=[event_info["id"]])

    return {
        "report_type": REPORT_TYPE,
        "title": f"MISP event report: {event_info['id']}",
        "event": event_section,
        "executive_summary": executive_summary,
        "technical_summary": explanation["explanation"],
        "attribute_summary": explanation["attribute_summary"],
        "ioc_summary": {
            "ioc_count": ioc_count,
            "iocs_by_type": iocs_by_type,
        },
        "context": context,
        "recommended_actions": explanation["recommended_next_steps"],
        "limitations": limitations,
        "raw_references": raw_references,
    }


def _build_executive_summary(
    *,
    event_id: int,
    info: str | None,
    ioc_count: int,
    threat_level: str | None,
    context: dict[str, list[str]],
) -> str:
    summary = f"Event {event_id} ('{info or 'untitled'}') has {ioc_count} extracted IOC(s)"
    if threat_level:
        summary += f" and a threat level of {threat_level}"
    summary += "."

    highlights: list[str] = []
    if context["possible_malware_families"]:
        highlights.append(
            "malware family/families: " + ", ".join(context["possible_malware_families"])
        )
    if context["possible_threat_actors"]:
        highlights.append("threat actor(s): " + ", ".join(context["possible_threat_actors"]))
    if context["possible_campaigns"]:
        highlights.append("campaign(s): " + ", ".join(context["possible_campaigns"]))
    if highlights:
        summary += " Notable context: " + "; ".join(highlights) + "."
    return summary


def _build_limitations(*, ioc_count: int, attribute_count: int) -> list[str]:
    limitations: list[str] = []
    if attribute_count == 0:
        limitations.append("This event has no recorded attributes.")
    elif ioc_count == 0:
        limitations.append(
            "No supported IOC types (ip, domain, url, md5, sha1, sha256, email) were extracted "
            "from this event's attributes."
        )
    limitations.append(
        "This report reflects a bounded snapshot of event data and does not include full raw "
        "MISP event JSON."
    )
    return limitations
