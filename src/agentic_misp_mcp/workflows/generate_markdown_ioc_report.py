from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.generate_ioc_report import generate_ioc_report_workflow
from agentic_misp_mcp.workflows.report_formatting import (
    render_bullet_list,
    render_context_section,
    render_heading,
    render_references_section,
    render_related_events_section,
    render_related_iocs_section,
    render_section,
)


async def generate_markdown_ioc_report_workflow(
    client: MISPClient, settings: Settings, value: str
) -> str:
    report = await generate_ioc_report_workflow(client, settings, value)
    return _render_markdown(report)


def _render_freshness_line(freshness: dict | None) -> str:
    if not freshness:
        return "unknown"
    label = freshness.get("label", "unknown")
    age = freshness.get("newest_signal_age_days")
    if age is None:
        return f"{label} (no intel timestamps available)"
    return f"{label} (newest signal {age} day(s) old)"


def _render_markdown(report: dict) -> str:
    ioc = report["ioc"]
    misp_findings = report["misp_findings"]
    warninglist_findings = report["warninglist_findings"]

    sections = [
        render_heading(f"IOC Report: {ioc['value']}"),
        render_section("Executive Summary", report["executive_summary"]),
        render_section(
            "Verdict and Confidence",
            "\n".join(
                [
                    f"- **Verdict:** {report['verdict']}",
                    f"- **Confidence:** {report['confidence']} "
                    f"(score {report['confidence_score']}/100)",
                    f"- **Intel freshness:** {_render_freshness_line(report.get('freshness'))}",
                ]
            ),
        ),
        render_section(
            "Key Findings",
            render_bullet_list(report["key_findings"], empty_message="No key findings identified."),
        ),
        render_section(
            "MISP Findings",
            "\n".join(
                [
                    f"- **Match count:** {misp_findings['match_count']}",
                    f"- **Related events:** {misp_findings['related_event_count']}",
                    f"- **Related IOCs:** {misp_findings['related_ioc_count']}",
                ]
            ),
        ),
        render_section(
            "Warninglist Findings",
            "\n".join(
                [
                    f"- **Status:** {warninglist_findings.get('status')}",
                    f"- **Hit:** {warninglist_findings.get('hit')}",
                    f"- **Detail:** {warninglist_findings.get('detail')}",
                ]
            ),
        ),
        render_section("Related Events", render_related_events_section(report["related_events"])),
        render_section("Related IOCs", render_related_iocs_section(report["related_iocs"])),
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
