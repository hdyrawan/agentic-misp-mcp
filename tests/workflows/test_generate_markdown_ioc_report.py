from __future__ import annotations

import pytest

from agentic_misp_mcp.misp.warninglists import WarninglistCheckResult
from agentic_misp_mcp.models.misp import MISPAttributeSummary, MISPEventSummary
from agentic_misp_mcp.workflows.generate_markdown_ioc_report import (
    generate_markdown_ioc_report_workflow,
)

REQUIRED_HEADINGS = (
    "# IOC Report:",
    "## Executive Summary",
    "## Verdict and Confidence",
    "## Key Findings",
    "## MISP Findings",
    "## Warninglist Findings",
    "## Related Events",
    "## Related IOCs",
    "## Context",
    "## Recommended Actions",
    "## Limitations",
    "## References",
)


class HitClient:
    async def search_attributes(self, value, limit):
        return [
            MISPAttributeSummary(
                event_id=1,
                type="ip-dst",
                value=value,
                to_ids=True,
                tags=["misp-galaxy:threat-actor=example-actor"],
            )
        ]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(
            id=event_id,
            info="event",
            date="2026-01-01",
            attribute_count=1,
            attributes_by_type={"domain": 1},
            attributes=[
                MISPAttributeSummary(
                    event_id=event_id,
                    type="domain",
                    category="Network activity",
                    value="c2.example.test",
                )
            ],
        )

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


class UnknownClient:
    async def search_attributes(self, value, limit):
        return []

    async def get_event(self, event_id, attribute_limit):
        raise AssertionError("get_event should not be called when there are no matches")

    async def check_warninglists(self, value):
        return WarninglistCheckResult(status="available", hit=False)


class NoiseClient:
    async def search_attributes(self, value, limit):
        return [MISPAttributeSummary(event_id=1, type="ip-dst", value=value)]

    async def get_event(self, event_id, attribute_limit):
        return MISPEventSummary(id=event_id, info="event", attribute_count=0)

    async def check_warninglists(self, value):
        return WarninglistCheckResult(
            status="available", hit=True, matches=[{"name": "common-infra"}]
        )


def _assert_required_headings(markdown: str) -> None:
    for heading in REQUIRED_HEADINGS:
        assert heading in markdown, f"missing heading: {heading}"


@pytest.mark.asyncio
async def test_generate_markdown_ioc_report_known_ioc_with_hits(settings):
    markdown = await generate_markdown_ioc_report_workflow(HitClient(), settings, "1.2.3.4")

    assert markdown.startswith("# IOC Report: 1.2.3.4")
    _assert_required_headings(markdown)
    assert "c2.example.test" in markdown
    assert "example-actor" in markdown
    assert '"Event"' not in markdown
    assert "{'id2" not in markdown


@pytest.mark.asyncio
async def test_generate_markdown_ioc_report_unknown_ioc(settings):
    markdown = await generate_markdown_ioc_report_workflow(UnknownClient(), settings, "9.9.9.9")

    _assert_required_headings(markdown)
    assert "No MISP matches were found" in markdown
    assert "No related events were found." in markdown
    assert "No related IOCs were extracted." in markdown


@pytest.mark.asyncio
async def test_generate_markdown_ioc_report_warninglist_noise_ioc(settings):
    markdown = await generate_markdown_ioc_report_workflow(NoiseClient(), settings, "8.8.8.8")

    _assert_required_headings(markdown)
    assert "likely_benign_or_noise" in markdown
    assert "**Hit:** True" in markdown
