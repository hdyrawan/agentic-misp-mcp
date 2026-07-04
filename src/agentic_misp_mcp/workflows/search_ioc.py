from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc
from agentic_misp_mcp.settings import Settings


async def search_ioc_workflow(
    client: MISPClient, settings: Settings, value: str, limit: int | None = 20
) -> dict[str, object]:
    ioc = normalize_ioc(value)
    resolved_limit = settings.clamp_limit(limit)
    matches = await client.search_attributes(ioc.value, resolved_limit)
    return {
        "ioc": {"value": ioc.value, "type": ioc.type.value},
        "limit": resolved_limit,
        "match_count": len(matches),
        "matches": [match.model_dump(exclude_none=True) for match in matches],
    }
