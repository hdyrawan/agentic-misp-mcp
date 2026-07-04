# Live validation report — v0.2.0-beta.1

## Summary

| Item | Value |
| --- | --- |
| Date/time | 2026-07-04T11:07:07+00:00 |
| Branch | `main` |
| Commit hash | `3b8a9c3bf7d42d2f0c298591bbefa0048f4dd766` |
| MCP server version | `0.2.0-beta.1` |
| MISP version | `2.5.42` |
| MISP URL | redacted |
| Sandbox event | Event `1645` created specifically for this validation |
| Secrets in report | Redacted; no API keys, bearer tokens, cookies, authorization headers, or approval tokens included |

Result: live beta validation executed against the configured local MISP lab. `38` checks passed, `0` failed, and `4` were not executed for documented safety/fixture reasons.

This validates the repository as a `v0.2.0-beta.1` production-write beta candidate suitable for isolated pilot validation. It does **not** make the project GA production-ready.

## Environment summary

- Deployment shape: local repository execution using `uv run`, direct MCP workflow registration, and direct MISP API setup calls for sandbox event creation/basic API checks.
- MISP lab: configured via `<user-config-dir>/agentic-misp-mcp/live.env`; secrets were not printed or copied into this report.
- TLS: lab config uses `MISP_VERIFY_TLS=false` for normal calls; the explicit TLS fail-closed check forced verification on and failed closed as expected against the lab certificate.
- Audit paths: isolated under `/tmp/agentic-misp-mcp-live/`, not committed.
- Approval stores: isolated SQLite files under `/tmp/agentic-misp-mcp-live/`, not committed.
- Test IOC values used RFC 5737 documentation ranges and are not sensitive.

## Test event

A dedicated sandbox event was created for validation: Event `1645`. The seed IOC was an RFC 5737 documentation address (`198.51.100.6`), used only as lab validation data.

## Test cases

| # | Test case | Result | Evidence summary |
| ---: | --- | --- | --- |
| 1 | valid API key can connect to MISP | PASS | status_code=200 |
| 2 | invalid/revoked API key fails safely | PASS | status_code=403 |
| 3 | TLS fail-closed with MISP_VERIFY_TLS=true | PASS | error_type=ConnectError |
| 4 | timeout behavior against slow/unreachable MISP | PASS | error_type=ConnectTimeout |
| 5 | HTTP 429/rate-limit behavior | NOT EXECUTED | No safe lab rate-limit trigger configured; did not DoS the local MISP lab |
| 6 | create dedicated sandbox event | PASS | Evidence captured in validation JSON. |
| 7 | direct MISP get_event | PASS | status_code=200 |
| 8 | direct MISP get_attribute | PASS | status_code=200 |
| 9 | read-only tool search_ioc | PASS | status=None |
| 10 | read-only tool pivot_ioc | PASS | status=None |
| 11 | read-only tool find_related_iocs | PASS | status=None |
| 12 | read-only tool extract_event_iocs | PASS | status=None |
| 13 | read-only tool explain_event_context | PASS | status=None |
| 14 | read-only tool generate_event_report | PASS | status=None |
| 15 | read-only tool generate_markdown_ioc_report | PASS | Evidence captured in validation JSON. |
| 16 | read-only tool generate_markdown_event_report | PASS | Evidence captured in validation JSON. |
| 17 | warninglist endpoint available check using hit candidate | PASS | status=available, hit_count=0; endpoint worked but this was not a positive hit |
| 18 | warninglist miss candidate | PASS | status=available, hit_count=0 |
| 19 | large event/result truncation behavior | NOT EXECUTED | sandbox result did not exceed configured response-size limit; no large fixture available |
| 20 | production mode blocks approved=true alone | PASS | status=blocked, approval_status=not_found |
| 21 | first call creates pending_approval | PASS | status=pending_approval |
| 22 | CLI can list approval request | PASS | returncode=0 |
| 23 | CLI can show approval request | PASS | returncode=0 |
| 24 | CLI can approve approval request | PASS | returncode=0 |
| 25 | second call with approval_request_id executes exactly once | PASS | status=executed, approval_status=used |
| 26 | same approval_request_id replay is blocked | PASS | status=blocked, approval_status=already_used |
| 27 | modified payload after approval is blocked | PASS | status=blocked, approval_status=hash_mismatch |
| 28 | expired approval is blocked | PASS | status=blocked, approval_status=expired |
| 29 | rejected approval is blocked | PASS | status=blocked, approval_status=rejected |
| 30 | wrong tool cannot redeem another tool approval | PASS | status=blocked, approval_status=wrong_tool |
| 31 | type allowlist blocks out-of-policy attribute type | PASS | status=blocked |
| 32 | category allowlist blocks out-of-policy attribute category | PASS | status=blocked |
| 33 | tag allowlist blocks out-of-policy tag | PASS | status=blocked |
| 34 | publish blocked when AGENTIC_MISP_MCP_ENABLE_PUBLISH=false | PASS | status=blocked |
| 35 | analyst_write cannot publish | PASS | status=blocked |
| 36 | curator/admin can publish only when publish enabled | PASS | status=executed, approval_status=used |
| 37 | audit log includes approval_request_id | PASS |  |
| 38 | audit log includes operation_hash | PASS |  |
| 39 | audit log includes approval_status | PASS |  |
| 40 | audit log does not leak MISP_API_KEY approval_token bearer cookies authorization | PASS | leaks=[] |
| 41 | confirmed warninglist positive hit | NOT EXECUTED | Lab warninglist data did not produce a hit for the selected candidate. |
| 42 | warninglist not_available behavior | NOT EXECUTED | Lab warninglist endpoint was available; validation did not disable warninglists or change MISP server configuration. |

## Audit log evidence snippets

Sanitized audit snippets below show approval correlation fields and blocked/publish outcomes. Full temporary audit logs were left under `/tmp/agentic-misp-mcp-live/` on the validation host and are not committed.

```json
{"approval_status": "not_found", "operation_hash": "974b004158f59c7eab535acfbccafabb5bee745d7936a367c10b32404c0fd2e5", "outcome": "blocked", "success": false, "tool": "submit_ioc_with_approval"}
{"approval_request_id": "fad2c42b-5d23-4b6f-8749-9b1dee959edb", "approval_status": "pending", "operation_hash": "0bbc028e09a5dcff44d7b9158957bbc5de1b6f68f0888f48b72ccb7b07f98189", "outcome": "success", "success": true, "tool": "submit_ioc_with_approval"}
{"approval_request_id": "fad2c42b-5d23-4b6f-8749-9b1dee959edb", "approval_status": "used", "operation_hash": "0bbc028e09a5dcff44d7b9158957bbc5de1b6f68f0888f48b72ccb7b07f98189", "outcome": "success", "success": true, "tool": "submit_ioc_with_approval"}
{"outcome": "blocked", "success": false, "tool": "publish_event_with_approval"}
{"approval_request_id": "57419ee2-c4a3-4049-be1b-0ff8825be51b", "approval_status": "used", "operation_hash": "2f80ff7a96552409b2d434db44dd88e7814141ffaf0535c4ccc21df2373bd0df", "outcome": "success", "success": true, "tool": "publish_event_with_approval"}
```

Audit redaction check passed: the validation scan found no configured MISP API key, approval token, bearer token marker, cookie marker, `Authorization`, or `MISP_API_KEY` string in the isolated audit logs.

## Known issues / not executed

- HTTP 429/rate-limit behavior was not executed: no safe lab rate-limit trigger was configured, and the validation did not intentionally DoS the local MISP lab.
- Large event/result truncation was not executed: the dedicated sandbox event/result did not exceed the configured response-size limit, and no large fixture was available.
- Warninglist endpoint was available, but the selected hit candidate (`127.0.0.1`) returned zero matches on this lab. This validates graceful available/miss behavior, not a confirmed positive warninglist hit.
- Warninglist `not_available` behavior was not executed because this lab had the warninglist endpoint available and validation did not alter MISP server configuration to disable it.

## Release decision

- Ready for isolated live beta / pilot validation: **yes**.
- Ready to tag as `v0.2.0-beta.1`: **yes, from this validation report perspective**, assuming maintainers accept the two documented not-executed beta limitations above.
- GA production-ready: **no**. This remains a production-write beta, not GA production readiness.

