from __future__ import annotations

from agentic_misp_mcp.misp.client import MISPClient

TESTED_BASELINE = "2.5.42"


async def get_misp_status_workflow(client: MISPClient) -> dict[str, object]:
    version = await client.get_version()
    warninglists_available = await client.probe_warninglists_available()

    return {
        "misp_version": version,
        "tested_baseline": TESTED_BASELINE,
        "version_tested": version == TESTED_BASELINE,
        "warninglists_available": warninglists_available,
    }
