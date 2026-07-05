# Live validation report — v0.3.0 (2026-07-05)

End-to-end live validation of the `v0.3.0` release (`release/v0.3.0` integration branch:
M2 age-aware scoring + M3 read tools/feed observability + the review fixes documented in
`docs/review-v0.3.0-findings.md`) against the non-production MISP `2.5.42` lab. Method: MCP
Inspector `--cli` over stdio, config from the operator's local live env file, default
`read_only` policy; direct MISP API calls used only to verify endpoint behavior. Paths/hosts
genericized.

## Results

| # | Check | Result |
|---|-------|--------|
| 1 | `tools/list` | PASS (25 tools) |
| 2 | `investigate_ioc("8.8.8.8")` envelope + freshness | PASS (`tool_name`, `schema_version: 1`, `freshness.label=fresh`, age-weighted score) |
| 3 | `get_misp_status` | PASS (`misp_version: 2.5.42`, `version_tested: true`, `warninglists_available: true`) |
| 4 | **F1 fix** `search_events(date_from=2099-01-01)` | PASS (0 events — filter actually applies; pre-fix `datefrom` returned unfiltered results) |
| 5 | `search_events(date_from=2026-07-01, limit=5)` | PASS (5 events, metadata-mode response, `attribute_count` populated from event field)¹ |
| 6 | **F3 fix** `search_events(date_from="last week")` | PASS (clean `isError` — "date_from must be a YYYY-MM-DD date"; audit `outcome=error`) |
| 7 | `get_ioc_sightings("203.0.113.183")` | PASS (5 sightings incl. the v0.2.1 validation sighting, newest/oldest timestamps) |
| 8 | `find_events_by_tag("tlp:clear")` metadata-mode regression | PASS (3 events, envelope present) |
| 9 | `list_feeds` + output secret scan | PASS (50 feeds; zero unredacted authkey/api_key/password/Authorization values) |
| 10 | `summarize_feed_health` | PASS (100 feeds grouped: 95 disabled, 5 never_fetched) |
| 11 | `generate_markdown_ioc_report("8.8.8.8")` | PASS ("**Intel freshness:** fresh (newest signal 0 day(s) old)" line present) |
| 12 | Read-only write block: `submit_ioc_with_approval(approved=true)` | PASS (`blocked`; audit `outcome=blocked`, `success=false`) |
| 13 | Audit log outcomes for the session | PASS (`success`/`error`/`blocked` all recorded correctly) |
| 14 | Audit log secret scan | PASS (API key appears 0 times) |

¹ This check **failed on the first run** and produced review finding F6: the pre-fix
`search_events` fetched full event JSON and exceeded the 5 MB response cap (fail-closed with a
clean error — the cap itself worked as designed). After switching both event-discovery payloads
to `metadata: true` (~16 KB for the same 5 events, tags preserved), the check passes.

## Verdict

No unresolved issues. The two live-confirmed review findings (F1 silent date-filter ignore, F6
full-event response blowup) are fixed and re-verified against the lab; age-aware scoring,
the response envelope, the six new read tools, feed-secret redaction, and the read-only policy
boundary all behave as designed. No writes were made to MISP during this validation (the single
write attempt was the intentional read-only block check).
