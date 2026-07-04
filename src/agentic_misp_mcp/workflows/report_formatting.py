from __future__ import annotations

from typing import Any

CONTEXT_LABELS = {
    "possible_malware_families": "Possible malware families",
    "possible_threat_actors": "Possible threat actors",
    "possible_campaigns": "Possible campaigns",
    "mitre_attack": "MITRE ATT&CK",
    "notable_tags": "Notable tags",
}


def render_heading(text: str, *, level: int = 1) -> str:
    return f"{'#' * level} {text}"


def render_section(title: str, body: str, *, level: int = 2) -> str:
    return f"{render_heading(title, level=level)}\n\n{body.strip()}\n"


def render_bullet_list(items: list[str], *, empty_message: str) -> str:
    if not items:
        return empty_message
    return "\n".join(f"- {item}" for item in items)


def render_context_section(context: dict[str, list[str]]) -> str:
    lines = []
    for key, label in CONTEXT_LABELS.items():
        values = context.get(key) or []
        if values:
            lines.append(f"- **{label}:** {', '.join(values)}")
    if not lines:
        return "No malware family, threat actor, campaign, or MITRE ATT&CK context was identified."
    return "\n".join(lines)


def render_related_events_section(related_events: list[dict[str, Any]]) -> str:
    if not related_events:
        return "No related events were found."
    lines = []
    for event in related_events:
        if event.get("status") == "error":
            lines.append(f"- Event {event.get('id')}: unavailable ({event.get('message')})")
            continue
        info = event.get("info") or "untitled"
        date = event.get("date") or "unknown date"
        attribute_count = event.get("attribute_count", 0)
        lines.append(
            f"- Event {event.get('id')} ('{info}'), date: {date}, attributes: {attribute_count}"
        )
    return "\n".join(lines)


def render_related_iocs_section(related_iocs: list[dict[str, Any]], *, max_items: int = 25) -> str:
    if not related_iocs:
        return "No related IOCs were extracted."
    lines = []
    for ioc in related_iocs[:max_items]:
        value = ioc.get("value")
        ioc_type = ioc.get("type")
        event_ids = ioc.get("event_ids") or ioc.get("source_event_ids") or []
        event_ids_text = ", ".join(str(event_id) for event_id in event_ids) or "unknown"
        lines.append(f"- `{value}` ({ioc_type}) — seen in event(s): {event_ids_text}")
    return "\n".join(lines)


def render_references_section(raw_references: list[dict[str, Any]]) -> str:
    if not raw_references:
        return "No references available."
    return "\n".join(
        f"- {reference.get('type', 'reference')} {reference.get('id')}: {reference.get('url')}"
        for reference in raw_references
    )


def render_iocs_by_type_section(iocs_by_type: dict[str, list[str]]) -> str:
    lines = [
        f"- **{ioc_type}:** {', '.join(values)}"
        for ioc_type, values in iocs_by_type.items()
        if values
    ]
    if not lines:
        return "No IOCs were extracted from this event."
    return "\n".join(lines)


def render_ioc_type_counts_section(iocs_by_type: dict[str, list[str]]) -> str:
    counts = {ioc_type: len(values) for ioc_type, values in iocs_by_type.items() if values}
    if not counts:
        return "No IOCs were extracted from this event."
    lines = [f"- **{ioc_type}:** {count}" for ioc_type, count in counts.items()]
    return "\n".join(lines)
