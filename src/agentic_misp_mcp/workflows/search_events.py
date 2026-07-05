from __future__ import annotations

import re

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.settings import Settings
from agentic_misp_mcp.workflows.event_context import event_summary

# MISP restSearch silently ignores parameters it cannot parse, so malformed dates would
# return unfiltered results while looking filtered. Validate the shape before calling.
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_ORG_LENGTH = 255


def _validate_date(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if not _DATE_PATTERN.match(cleaned):
        raise ValueError(f"{field_name} must be a YYYY-MM-DD date")
    return cleaned


def _validate_org(org: str | None) -> str | None:
    if not isinstance(org, str) or not org.strip():
        return None
    cleaned = org.strip()
    if len(cleaned) > MAX_ORG_LENGTH:
        raise ValueError(f"org must be <= {MAX_ORG_LENGTH} characters")
    return cleaned


async def search_events_workflow(
    client: MISPClient,
    settings: Settings,
    date_from: str | None = None,
    date_to: str | None = None,
    published: bool | None = None,
    org: str | None = None,
    limit: int | None = 20,
) -> dict[str, object]:
    cleaned_from = _validate_date(date_from, "date_from")
    cleaned_to = _validate_date(date_to, "date_to")
    cleaned_org = _validate_org(org)
    resolved_limit = settings.clamp_limit(limit)
    events = await client.search_events(
        date_from=cleaned_from,
        date_to=cleaned_to,
        published=published,
        org=cleaned_org,
        limit=resolved_limit,
    )

    return {
        "filters": {
            "date_from": cleaned_from,
            "date_to": cleaned_to,
            "published": published,
            "org": cleaned_org,
        },
        "event_count": len(events),
        "events": [event_summary(event) for event in events],
        "limit": resolved_limit,
    }
