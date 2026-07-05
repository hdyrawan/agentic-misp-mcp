from __future__ import annotations

from datetime import datetime

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.models.misp import MISPSightingReadSummary
from agentic_misp_mcp.settings import Settings


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


async def get_ioc_sightings_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 50
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    sightings = await client.search_sightings(ioc.value, resolved_limit)
    dated = [sighting.date_sighting for sighting in sightings if sighting.date_sighting is not None]

    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "sighting_count": len(sightings),
        "newest_sighting_at": _iso(max(dated)) if dated else None,
        "oldest_sighting_at": _iso(min(dated)) if dated else None,
        "sightings": [_sighting_summary(sighting) for sighting in sightings],
        "limit": resolved_limit,
    }


def _sighting_summary(sighting: MISPSightingReadSummary) -> dict[str, object]:
    return {
        "event_id": sighting.event_id,
        "attribute_id": sighting.attribute_id,
        "type": sighting.type,
        "source": sighting.source,
        "date_sighting": _iso(sighting.date_sighting),
    }
