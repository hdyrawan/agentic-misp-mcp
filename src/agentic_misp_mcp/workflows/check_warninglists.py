from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.models.ioc import normalize_ioc


async def check_warninglists_workflow(client: MISPClient, value: str) -> dict[str, object]:
    ioc = normalize_ioc(value)
    result = await client.check_warninglists(ioc.value)
    return {
        "value": ioc.value,
        "ioc_type": ioc.type.value,
        "status": result.status,
        "hit": result.hit,
        "matches": result.matches,
        "message": result.message,
        "recommended_handling": _recommended_handling(result.status, result.hit),
    }


def _recommended_handling(status: str, hit: bool) -> str:
    if status == "not_available":
        return (
            "Warninglist check unavailable; "
            "interpret investigation results without noise-list context."
        )
    if status == "error":
        return "Warninglist check failed; retry later or verify manually in MISP."
    if hit:
        return (
            "Treat as potential benign/common infrastructure until corroborated by other evidence."
        )
    return "No warninglist hit reported by MISP."
