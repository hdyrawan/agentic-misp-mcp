from __future__ import annotations


async def propose_feed_changes_workflow(goal: str | None = None) -> dict[str, object]:
    return {
        "status": "proposal_only",
        "goal": goal,
        "requires_operator_approval": True,
        "mutates_misp": False,
        "proposals": [
            {
                "action": "improve_lookup_coverage",
                "rationale": (
                    "Review enabled OSINT feeds and ensure lookup-visible feeds cover "
                    "required IOC types before relying on feed-backed enrichment."
                ),
                "risk_notes": (
                    "Adding lookup-visible feeds can increase analyst noise; test against "
                    "representative IOCs first."
                ),
            },
            {
                "action": "reduce_stale_feeds",
                "rationale": (
                    "Prioritize feeds with stale or missing fetch timestamps for "
                    "operator-side fetch/cache checks."
                ),
                "risk_notes": (
                    "Bulk fetches may create load on MISP and upstream providers; schedule "
                    "during a maintenance window."
                ),
            },
            {
                "action": "review_disabled_feeds",
                "rationale": (
                    "Disabled feeds may be intentional, deprecated, or awaiting credentials; "
                    "review before enabling any feed."
                ),
                "risk_notes": (
                    "Enabling a feed is an operator-only administrative action and may "
                    "introduce untrusted data."
                ),
            },
            {
                "action": "optimize_feed_hygiene",
                "rationale": (
                    "Remove duplicate, unauthenticated, or erroring feed configurations "
                    "from operational runbooks after operator review."
                ),
                "risk_notes": (
                    "Deleting or editing feeds can affect investigations and should be "
                    "handled outside MCP with change control."
                ),
            },
        ],
    }
