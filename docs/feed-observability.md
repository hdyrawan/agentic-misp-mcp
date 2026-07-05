# Feed observability

M3 adds safe, read-only MISP feed observability. These tools help an analyst understand configured feed coverage and freshness without exposing feed administration to the agent loop.

## Tools

- `list_feeds(limit=50, enabled=None)` — lists configured feeds in a bounded response. Sensitive URL query parameters and authentication metadata are redacted.
- `get_feed_status(feed_id)` — returns redacted details for one feed, including `age_days_since_fetch`, `age_days_since_cache`, `health_label`, and warnings when timestamps are missing or stale.
- `summarize_feed_health(limit=100)` — groups configured feeds by health label: `healthy`, `stale`, `never_fetched`, `disabled`, `cache_stale`, `error`, and `unknown`.
- `propose_feed_changes(goal=None)` — dry-run only. It returns `status: "proposal_only"`, rationale, risk notes, and `requires_operator_approval: true`; it never calls a MISP write/admin endpoint.

## Health thresholds

Defaults:

- `AGENTIC_MISP_MCP_FEED_FRESH_DAYS=7`
- `AGENTIC_MISP_MCP_FEED_STALE_DAYS=30`

Both values must be at least `1`, and `FEED_FRESH_DAYS` must be less than `FEED_STALE_DAYS`. Fetch/cache ages at or below the stale threshold are still usable, but ages above the fresh threshold produce warnings.

## Safety boundary

The MCP surface does not expose feed fetch/cache/enable/disable/edit/delete actions and does not expose a raw feed API proxy. Those remain operator-only MISP administrative actions outside the MCP tool boundary.

The feed tools redact:

- URL query values for common secret keys such as `token`, `authkey`, `api_key`, `password`, and `secret`.
- URL embedded credentials.
- Metadata fields such as `headers`, `Authorization`, `Cookie`, `api_key`, `token`, `password`, and `secret`.

Every feed observability tool is registered through the read policy and audit wrapper, so calls are allowed under `read_only` and still create audit records.
