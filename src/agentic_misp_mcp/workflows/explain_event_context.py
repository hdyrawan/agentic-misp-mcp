from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.misp import MISPEventSummary
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import (
    ANALYSIS_LABELS,
    THREAT_LEVEL_LABELS,
    build_event_references,
)
from agentic_misp_mcp.workflows.investigation_engine import classify_tags

MAX_KEY_IOCS = 25


async def explain_event_context_workflow(
    client: MISPClient, settings: Settings, event_id: int
) -> dict[str, object]:
    event = await client.get_event(event_id, attribute_limit=settings.misp_event_attribute_limit)

    context = classify_tags(event.tags)
    key_iocs = [
        {"type": attribute.type, "value": attribute.value}
        for attribute in event.attributes
        if attribute.value
    ][:MAX_KEY_IOCS]
    explanation = _build_explanation(event=event, context=context)
    recommended_next_steps = _build_recommended_next_steps(context=context)
    raw_references = build_event_references(settings=settings, event_ids=[event.id])

    return {
        "event_id": event.id,
        "event_info": event.info,
        "event_date": event.date,
        "threat_level": THREAT_LEVEL_LABELS.get(event.threat_level_id, event.threat_level_id),
        "analysis_status": ANALYSIS_LABELS.get(event.analysis, event.analysis),
        "attribute_summary": dict(sorted(event.attributes_by_type.items())),
        "context": context,
        "key_iocs": key_iocs,
        "explanation": explanation,
        "recommended_next_steps": recommended_next_steps,
        "raw_references": raw_references,
    }


def _build_explanation(*, event: MISPEventSummary, context: dict[str, list[str]]) -> str:
    details: list[str] = []
    header = f"Event {event.id} ('{event.info or 'untitled'}')"
    if event.date:
        header += f" dated {event.date}"
    details.append(header + ".")

    if event.threat_level_id:
        threat_level = THREAT_LEVEL_LABELS.get(event.threat_level_id, event.threat_level_id)
        details.append(f"Threat level: {threat_level}.")
    if event.analysis:
        details.append(f"Analysis status: {ANALYSIS_LABELS.get(event.analysis, event.analysis)}.")
    if context["possible_malware_families"]:
        details.append(
            "Possible malware families: " + ", ".join(context["possible_malware_families"]) + "."
        )
    if context["possible_threat_actors"]:
        details.append(
            "Possible threat actor(s): " + ", ".join(context["possible_threat_actors"]) + "."
        )
    if context["possible_campaigns"]:
        details.append("Possible campaign(s): " + ", ".join(context["possible_campaigns"]) + ".")
    if context["mitre_attack"]:
        details.append("MITRE ATT&CK reference(s): " + ", ".join(context["mitre_attack"]) + ".")
    details.append(
        f"{event.attribute_count} attribute(s) recorded across "
        f"{len(event.attributes_by_type)} type(s)."
    )
    return " ".join(details)


def _build_recommended_next_steps(*, context: dict[str, list[str]]) -> list[str]:
    steps: list[str] = []
    if context["possible_malware_families"]:
        steps.append("Correlate identified malware families with detection/EDR signatures.")
    if context["possible_threat_actors"]:
        steps.append("Cross-reference the identified threat actor(s) with prior intelligence.")
    if context["possible_campaigns"]:
        steps.append("Review other events linked to the identified campaign(s).")
    if context["mitre_attack"]:
        steps.append("Map MITRE ATT&CK references to existing detection coverage.")
    steps.append("Review key IOCs for hunting and detection engineering.")
    return steps
