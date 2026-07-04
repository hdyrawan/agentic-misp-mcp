from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.generate_markdown_event_report import (
    generate_markdown_event_report_workflow,
)

REQUIRED_HEADINGS = (
    "# MISP Event Report:",
    "## Executive Summary",
    "## Event Overview",
    "## Technical Summary",
    "## IOC Summary",
    "## Key IOCs",
    "## Context",
    "## Recommended Actions",
    "## Limitations",
    "## References",
)


class MixedIocClient:
    async def get_event(self, event_id, attribute_limit):
        attributes = [
            MISPAttributeSummary(event_id=event_id, type="ip-dst", value="1.2.3.4"),
            MISPAttributeSummary(event_id=event_id, type="domain", value="evil.example.test"),
            MISPAttributeSummary(event_id=event_id, type="sha256", value="a" * 64),
        ]
        return MISPEventSummary(
            id=event_id,
            info="mixed ioc event",
            date="2026-01-01",
            threat_level_id="1",
            analysis="2",
            distribution="0",
            tags=[
                "misp-galaxy:ransomware=example-ransomware",
                "misp-galaxy:campaign=example-campaign",
            ],
            attribute_count=3,
            attributes_by_type={"ip-dst": 1, "domain": 1, "sha256": 1},
            attributes=attributes[:attribute_limit],
        )


class NoIocClient:
    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="empty event", attribute_count=0)


def _assert_required_headings(markdown: str) -> None:
    for heading in REQUIRED_HEADINGS:
        assert heading in markdown, f"missing heading: {heading}"


@pytest.mark.asyncio
async def test_generate_markdown_event_report_mixed_ioc_types(settings):
    markdown = await generate_markdown_event_report_workflow(MixedIocClient(), settings, 42)

    assert markdown.startswith("# MISP Event Report: 42")
    _assert_required_headings(markdown)
    assert "1.2.3.4" in markdown
    assert "evil.example.test" in markdown
    assert "a" * 64 in markdown
    assert '"Event"' not in markdown


@pytest.mark.asyncio
async def test_generate_markdown_event_report_tags_and_context(settings):
    markdown = await generate_markdown_event_report_workflow(MixedIocClient(), settings, 42)

    assert "example-ransomware" in markdown
    assert "example-campaign" in markdown


@pytest.mark.asyncio
async def test_generate_markdown_event_report_no_iocs(settings):
    markdown = await generate_markdown_event_report_workflow(NoIocClient(), settings, 7)

    _assert_required_headings(markdown)
    assert "No IOCs were extracted from this event." in markdown
    assert "No malware family, threat actor, campaign, or MITRE ATT&CK context" in markdown
    assert "no recorded attributes" in markdown
