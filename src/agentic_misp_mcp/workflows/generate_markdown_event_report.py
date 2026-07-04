from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.generate_event_report import generate_event_report_workflow
from agentic_misp_mcp.workflows.report_formatting import (
    render_bullet_list,
    render_context_section,
    render_heading,
    render_ioc_type_counts_section,
    render_iocs_by_type_section,
    render_references_section,
    render_section,
)


async def generate_markdown_event_report_workflow(
    client: MISPClient, settings: Settings, event_id: int
) -> str:
    report = await generate_event_report_workflow(client, settings, event_id)
    return _render_markdown(report)


def _render_markdown(report: dict) -> str:
    event = report["event"]
    ioc_summary = report["ioc_summary"]

    sections = [
        render_heading(f"MISP Event Report: {event['event_id']}"),
        render_section("Executive Summary", report["executive_summary"]),
        render_section(
            "Event Overview",
            "\n".join(
                [
                    f"- **Event ID:** {event['event_id']}",
                    f"- **Info:** {event.get('info') or 'untitled'}",
                    f"- **Date:** {event.get('date') or 'unknown'}",
                    f"- **Threat level:** {event.get('threat_level') or 'unknown'}",
                    f"- **Analysis status:** {event.get('analysis_status') or 'unknown'}",
                    f"- **Distribution:** {event.get('distribution') or 'unknown'}",
                ]
            ),
        ),
        render_section("Technical Summary", report["technical_summary"]),
        render_section(
            "IOC Summary",
            "\n".join(
                [
                    f"- **Total IOCs:** {ioc_summary['ioc_count']}",
                    render_ioc_type_counts_section(ioc_summary["iocs_by_type"]),
                ]
            ),
        ),
        render_section("Key IOCs", render_iocs_by_type_section(ioc_summary["iocs_by_type"])),
        render_section("Context", render_context_section(report["context"])),
        render_section(
            "Recommended Actions",
            render_bullet_list(
                report["recommended_actions"], empty_message="No recommended actions."
            ),
        ),
        render_section(
            "Limitations",
            render_bullet_list(report["limitations"], empty_message="No known limitations."),
        ),
        render_section("References", render_references_section(report["raw_references"])),
    ]
    return "\n".join(sections).strip() + "\n"
