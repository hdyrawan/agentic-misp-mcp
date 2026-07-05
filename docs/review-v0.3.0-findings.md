# v0.3.0 pre-merge review — findings and resolutions (2026-07-05)

Code-quality + security review of the two v0.3.0 feature branches before merging to `main`:

- `feature/m2-age-aware-scoring-wip` — M2 age-aware scoring integration (freshness block,
  weighted scoring behind `AGENTIC_MISP_MCP_AGE_WEIGHTING`, read-tool response envelope).
- `feature/m3-read-tools-feed-observability` — M3 read tools (`get_ioc_sightings`,
  `search_events`, `get_misp_status`) plus four feed-observability tools.

Both branches were merged into `release/v0.3.0` first; every finding below was fixed on that
integration branch before the merge to `main`.

## Findings

### F1 — `search_events` date filters were silently ignored by MISP (high, confirmed live)

`event_search_payload` sent `datefrom`/`dateto` to `/events/restSearch`. MISP ignores unknown
restSearch parameters instead of rejecting them, so the filter never applied — confirmed live
on the `2.5.42` lab: `datefrom=2099-01-01` still returned events, while `from=2099-01-01`
correctly returned zero. Impact: an agent asking for "events since yesterday" would receive
unfiltered results and treat them as filtered — wrong data presented with full confidence.

**Fix:** payload now uses MISP's real `from`/`to` parameter names, with a comment marking the
names as load-bearing. Client test updated to pin them.

### F2 — `propose_feed_changes` was a static no-op tool (medium)

The tool ignored its `goal` argument entirely and returned four hardcoded generic
recommendations. It also hijacked the `propose_*` naming prefix, which this project reserves
for write-proposal builders (`propose_event`/`propose_attribute`), while being registered as a
`read` action — exactly the naming ambiguity the tool conventions exist to prevent. It added
agent-visible surface with no function behind it.

**Fix:** tool removed (workflow, registration, tests, docs). Tool count is 25, not 26.

### F3 — `search_events` accepted arbitrary filter strings (medium)

`date_from`/`date_to` went to MISP unvalidated; combined with F1's silent-ignore behavior, any
malformed date silently produced unfiltered results. `org` had no length bound.

**Fix:** dates must match `YYYY-MM-DD` (rejected with a clear `ValueError` otherwise, which the
audit layer records as a clean error); `org` is bounded at 255 characters.

### F4 — cross-module private import (low)

`search_events.py` imported `_event_summary` from `find_events_by_tag.py`.

**Fix:** promoted to `event_context.event_summary` as the shared public helper; both callers
updated.

### F5 — `get_feed_status` trusted its tool-layer type annotation (low)

The workflow accepted `int | str` and interpolated the value into the `/feeds/view/<id>`
request path, relying on the registry annotation to keep it an int.

**Fix:** the workflow itself now requires a positive integer (bool excluded) before any request
is built.

## Reviewed and found sound

- **Feed secret redaction** (`workflows/feed_health.py`): feed URLs are redacted for userinfo
  and sensitive query keys (including bare `key`); `headers`/`authkey`/token-like feed fields
  are replaced with `[REDACTED]`; remaining metadata passes through `sanitize_for_audit`.
- **M2 scoring integration**: age weight discounts positive factors only (penalties always at
  full strength), `unknown` freshness never discounts or boosts, the expired cap (60) and
  high-confidence floor (stale weight) behave per the plan, and
  `AGENTIC_MISP_MCP_AGE_WEIGHTING=false` reproduces pre-M2 scoring exactly (regression-tested).
- **Policy/audit surface**: all new tools are `read`-classified, registered through the shared
  audit wrapper, allowed under `read_only`, and covered by the existing no-admin/no-proxy
  contract tests; no new write capability anywhere in v0.3.0.
- **Merged envelope**: after integration, all M3 tools automatically gained the M2
  `tool_name`/`schema_version` response envelope.

## Post-fix verification

353 automated tests passing, ruff lint/format clean, and a live end-to-end validation pass
against the MISP `2.5.42` lab (see `docs/live-validation-report-v0.3.0.md`).
