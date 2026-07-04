# Live validation report — v0.2.0-rc.1

## Summary

| Item | Value |
| --- | --- |
| Date/time | 2026-07-04T18:20:00+00:00 – 2026-07-04T18:45:00+00:00 (UTC) |
| Branch | `fix/v0.2.0-rc.1-live-validation-blockers` (built on `release/v0.2.0-rc.1-ga-readiness`, tagged `v0.2.0-rc.1`, merged to `main` at `810d76e`) |
| MISP version | `2.5.42` (same lab used for `v0.2.0-beta.1`/`v0.2.0-beta.2` validation) |
| MISP URL | redacted (generic placeholder used below: `https://misp.lab.internal`) |
| Sandbox event | Reused Event `1645` (`agentic-misp-mcp v0.2.0-beta.1 live validation sandbox`, already published) — no new event created; propose_event/propose_attribute never touch MISP by design |
| Secrets in report | Redacted; no API keys, bearer tokens, cookies, authorization headers, or approval tokens included |

**Result: two real, reproducible defects were found during this pass and fixed. Both are
confirmed live against the real MISP lab, not just via unit tests.** All other checklist items
passed as expected. See "Fixes made" below.

This is the first RC pass to exercise live writes end-to-end (propose validation, production
approval lifecycle including one real MISP write, sighting/tag/warninglist parsing) against a
real MISP `2.5.42` instance rather than mocked transports. It closes the open live-evidence gaps
`docs/live-validation-report-v0.2.0-beta.2.md` explicitly left open: HTTP 429 (mock-only, see
below), large-result truncation, TLS fail-closed, and — most significantly — **a live positive
warninglist hit**, which had never been exercised against real MISP data before this pass.

## Environment summary

- Deployment shape: local repository execution using `uv run` against the lab `.env`
  (`<user-config-dir>/agentic-misp-mcp/live.env`); secrets were not printed or copied into this
  report.
- TLS: lab config uses `MISP_VERIFY_TLS=false` for this self-signed lab (expected `WARN`, not
  `FAIL`, from `config doctor`).
- Audit log and approval store paths were overridden to isolated scratch directories (mode
  `0700`) for this validation run only; not committed and not the lab's real deployment paths.
- Tests were executed both as direct workflow-function calls (for isolated behavior checks) and
  through the actual registered MCP tool functions (`tools.registry.register_tools` +
  `AuditLogger`) for the audit-trail and end-to-end approval-lifecycle checks, so the audit
  evidence reflects the real tool-call path, not a bypass of it.
- One MISP warninglist (`List of RFC 1918 CIDR blocks`, id `88`) was temporarily enabled via the
  lab's own admin API solely to produce a genuine positive-hit response (this lab ships with all
  125 warninglists disabled by default) and was disabled again immediately after the check,
  restoring the lab to its original state.

## Test cases

| # | Test case | Result | Evidence summary |
| ---: | --- | --- | --- |
| 1 | `propose_event` — valid payload | PASS | `status: "proposal"`, correct MISP `Event` payload shape built, no MISP call made |
| 2 | `propose_event` — invalid payload (blank `info`, out-of-range `distribution`/`threat_level_id`/`analysis`) | PASS | `status: "invalid"`, four validation errors returned, no MISP call made |
| 3 | `propose_attribute` — valid payload | PASS | `status: "proposal"`, correct attribute payload shape including `event_id` |
| 4 | `propose_attribute` — invalid payload (unsupported type/category, blank value) | PASS | `status: "invalid"`, three validation errors returned, no MISP call made |
| 5 | TLS fail-closed (`MISP_VERIFY_TLS=true` against the lab's self-signed cert) | PASS | Real `ConnectError` (`certificate verify failed: self-signed certificate`) surfaced as `MISPClientError`; no silent bypass |
| 6 | Timeout behavior (`MISP_TIMEOUT_SECONDS=0.001` against the real lab) | PASS | Real `ConnectTimeout` surfaced as `MISPClientError` |
| 7 | Large-result truncation (`AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES=1024` against a real ~2.9KB lab response) | PASS | `MISPResponseTooLargeError` raised with the configured limit in the message |
| 8 | Safe HTTP 429 handling | PARTIAL — mock-transport only | This lab has no rate limiter/proxy to safely trigger a real `429`; verified via `httpx.MockTransport` returning `429`, confirming `MISPRateLimitError` is raised cleanly. Not live-tested; same gap noted in `docs/live-validation-report-v0.2.0-beta.2.md`. |
| 9 | Warninglist positive hit | **PASS after fix** (initially FAILED — see "Fixes made") | Real hit against `10.1.2.3` / `192.168.1.1` (RFC 1918 list, temporarily enabled): `status: "available"`, `hit: true`, real `matched` CIDR block in `matches` |
| 10 | Warninglist miss | PASS | `8.8.8.8` → `status: "available"`, `hit: false` (consistent with beta.2) |
| 11 | Warninglist `not_available` | PASS — mock-transport, controlled method (per validation plan) | `httpx.MockTransport` returning `404` on `/warninglists/checkValue` → `status: "not_available"` |
| 12 | Production approval requires `approval_request_id` | PASS | `approved=false`, no `approval_request_id` → real `pending_approval` record created in a disposable SQLite store |
| 13 | `approved=true` alone blocked in production mode | PASS | No `approval_request_id` supplied → `status: "blocked"`, `approval_status: "not_found"`, reason states `approval_request_id` is required |
| 14 | Redeem before approval | PASS | `status: "blocked"`, `approval_status: "not_yet_approved"` |
| 15 | One-time approval redemption (real MISP write) | **PASS after fix** (initially a false positive — see "Fixes made") | Approved request redeemed once → real `sightings/add` call against sandbox event `1645`'s real attribute value → `status: "executed"`, `approval_status: "used"` |
| 16 | Replay of a used approval | PASS | Second redemption attempt on the same `request_id` → `status: "blocked"`, `approval_status: "already_used"`; no second MISP call made |
| 17 | Wrong-tool redemption | PASS | An approval created for `tag_event_with_approval` redeemed via `add_sighting_with_approval` → `status: "blocked"`, `approval_status: "wrong_tool"` |
| 18 | Hash-mismatch redemption | PASS | Approved payload redeemed with different call arguments → `status: "blocked"`, `approval_status: "hash_mismatch"` |
| 19 | Expired approval redemption | PASS | 1-second TTL approval, redeemed after 2 seconds → `status: "blocked"`, `approval_status: "expired"` |
| 20 | Rejected approval redemption | PASS | Approval rejected via `approval_store.reject()`, then redeemed → `status: "blocked"`, `approval_status: "rejected"` |
| 21 | Audit redaction/correlation | PASS | Real audit log for the full approval lifecycle: `approval_token` shown as `[REDACTED]` in every record; no `MISP_API_KEY`/`Authorization` value in any record; `operation_hash` and `approval_request_id` correctly correlate the `pending` → `used` record pair |
| 22 | `config doctor` against a safe config | PASS | Real lab `.env`: overall `PASS`, two expected `WARN`s (`MISP_VERIFY_TLS=false`, scratch audit-log path), no `FAIL` |
| 23 | `config doctor` against an unsafe config | PASS | `AGENTIC_MISP_MCP_ENABLE_WRITE=true` + `AGENTIC_MISP_MCP_APPROVAL_MODE=lab` + `AGENTIC_MISP_MCP_ENABLE_PUBLISH=true` with `AGENTIC_MISP_MCP_ROLE=read_only` → overall `FAIL`, exit code `2`, two correct `FAIL` lines |
| 24 | `approvals prune` against a disposable approval DB | PASS | 5-record disposable store (1 used, 2 approved, 1 expired, 1 rejected) → `prune --older-than 0s` deleted exactly the 3 terminal records (used/expired/rejected), left both `approved` records untouched |

## Fixes made

Two real, reproducible defects were found live against the real MISP lab and fixed on this
branch. Both are narrow, targeted fixes — no new features, no new tools, no scope expansion.

### 1. `add_sighting_with_approval` reported `executed`/audit `success` for a sighting MISP rejected

**Root cause:** unlike `tag_event_with_approval` and `publish_event_with_approval` (which check
`result.saved` / `result.published` and return `status: "failed"` when MISP answers HTTP 200 but
rejects the operation), `add_sighting_with_approval_workflow` called `client.add_sighting()` and
unconditionally returned `_executed_result(...)`. When MISP cannot attach a sighting to a real
attribute (e.g. `event_id` alone with no matching attribute value), it answers
`{"message": "Could not add the Sighting. Reason: No valid attributes found."}` — no `Sighting`
key, no exception — and the tool reported this as a successful write in both its return value and
the audit log (`outcome: "success"`).

**Fix:**
- `models/misp.py`: `MISPSightingSummary` gained `saved: bool` and `message: str | None` fields;
  `parse_sighting` now sets `saved = "Sighting" in raw`, mirroring how `parse_tag_result` and
  `parse_publish_result` already detect a MISP-side rejection.
- `workflows/controlled_write.py`: `add_sighting_with_approval_workflow` now checks
  `if not result.saved: return _failed_result(...)` before returning `_executed_result`, matching
  the existing `tag_event`/`publish_event` pattern exactly.
- Verified live: a real successful sighting (against sandbox event `1645`'s real attribute value
  `198.51.100.6`) now correctly reports `status: "executed"`, `saved: true`; a real rejected
  sighting now correctly reports `status: "failed"`, `saved: false`, and the real MISP rejection
  message. Confirmed end-to-end through the actual registered MCP tool + real `AuditLogger`: the
  audit record's `outcome` field changed from `"success"` (bug) to `"failed"` (fixed) for the
  identical rejected call.
- Test coverage: `tests/test_controlled_write_tools.py::test_add_sighting_reports_failed_when_misp_rejects_the_sighting`
  (new), plus `FakeWriteClient`/`FakeRejectingWriteClient` in both
  `tests/test_controlled_write_tools.py` and `tests/workflows/test_controlled_write.py` updated
  to model the real `saved` signal.

**Severity:** this broke the audit trail's core safety guarantee for one of the four controlled
write tools — a failed write was recorded as a successful one. Classified as an RC blocker; fixed
before GA consideration.

### 2. `check_warninglists` silently reported `not_available` for a real MISP `2.5.42` positive hit

**Root cause:** `parse_warninglist_response` recognized several documented/community MISP
warninglist response shapes (`{"matches": [...]}`, `{"result": ...}`, `{"Warninglist": {...}}`,
etc.) but not the shape this project's actually-supported MISP version, `2.5.42`, returns for a
real positive hit: a dict keyed by the queried value, mapping to a list of match objects, e.g.
`{"10.1.2.3": [{"id": "88", "name": "List of RFC 1918 CIDR blocks", "matched": "10.0.0.0/8"}]}`.
This shape fell through every recognized branch and hit the `Unrecognized MISP warninglist
response shape` default, reporting `status: "not_available"` instead of `hit: true` — silently
discarding the single most valuable signal `check_warninglists` exists to provide, against the
one MISP version this project claims to support.

This is exactly the gap `docs/misp-compatibility.md` already flagged as an open risk ("a live
positive hit against real warninglist data has not been performed on any version") — this pass
performed it and found the parser did not handle it.

**Fix:** `misp/warninglists.py`'s `parse_warninglist_response` gained a new branch, checked after
all previously-recognized shapes: if the dict is non-empty and every value is a list, treat it as
this value-keyed hit shape and flatten all list entries into `matches`.

- Verified live: `check_warninglists("10.1.2.3")` and `check_warninglists("192.168.1.1")` against
  the real lab (with the `RFC 1918` warninglist temporarily enabled) now correctly return
  `status: "available"`, `hit: true`, with the real `matched` CIDR block populated. The existing
  miss case (`8.8.8.8` → `hit: false`) and the mock-based `not_available` case are unaffected.
- Test coverage:
  `tests/workflows/test_check_warninglists.py::test_misp_2_5_42_value_keyed_hit_shape_is_recognized`
  and `::test_misp_2_5_42_empty_list_miss_shape_is_recognized` (new), using the exact live-observed
  response shape.

**Severity:** classified as an RC blocker — `check_warninglists` is a read-only tool with no write
risk, but a silently-wrong `not_available` for a real hit against the project's own documented,
tested MISP version undermines the tool's core purpose and the project's MISP-compatibility
claims. Fixed before GA consideration.

### Post-fix full validation

After both fixes: `uv run --extra dev ruff check .` (clean), `uv run --extra dev ruff format
--check .` (clean), `uv run --extra dev pytest -q` (257 passed, up from 254 at RC tag time), `git
diff --check` (clean).

## Not executed (with reason)

- **Safe HTTP 429 / rate-limit live reproduction.** No rate limiter or proxy exists in this lab to
  safely trigger a real `429` without a load-testing setup, which is out of scope (no DoS-style
  testing). Verified via `httpx.MockTransport` instead — same gap and same justification as
  `docs/live-validation-report-v0.2.0-beta.2.md`.
- **Broader MISP version compatibility.** Only MISP `2.5.42` was validated, consistent with
  `docs/misp-compatibility.md`. No second MISP version was stood up for this pass.
- **`submit_ioc_with_approval`, `tag_event_with_approval`, `publish_event_with_approval` full
  production-approval-lifecycle live execution.** The full replay/hash/wrong-tool/expired/rejected
  approval-lifecycle matrix was validated live end-to-end using `add_sighting_with_approval` as
  the representative controlled-write tool (lowest risk, and it exercises the exact same shared
  `_production_approval_check` code path all four controlled-write tools call). The other three
  tools share that same policy/approval code path and are already covered by the existing mocked
  test suite (`tests/test_controlled_write_tools.py`, `tests/workflows/test_controlled_write.py`);
  repeating the full lifecycle live for each would exercise the same shared function again against
  the same lab, not new code paths.

## Evidence summary for release notes

- Two real defects were found and fixed via live lab validation: a false-positive audit
  outcome for a rejected sighting, and a silently-dropped positive warninglist hit against the
  project's own documented, supported MISP version. Both are now fixed, live-verified, and covered
  by new unit tests using the exact real response shapes observed.
- The full production approval lifecycle (pending → require valid `approval_request_id` →
  reject `approved=true` alone → block redemption before approval → one real MISP write on
  redemption → block replay/wrong-tool/hash-mismatch/expired/rejected redemption attempts) was
  validated end-to-end against a real MISP instance with a disposable SQLite approval store, not
  just mocked.
- TLS fail-closed, timeout, and large-result-truncation behavior were all confirmed live against
  the real lab for the first time (previously only mocked/unit-tested).
- `config doctor` and `approvals prune` were re-confirmed against both a safe config and a
  deliberately unsafe config, and against a disposable approval store with a realistic mix of
  terminal and non-terminal records.
- No secrets, private IPs beyond the lab's own internal address (redacted above), sensitive IOCs,
  approval tokens, or personal filesystem paths appear in this report or the underlying audit
  logs.

## What remains open for GA

- Live HTTP 429/rate-limit reproduction remains mock-only (no safe way to trigger it in this lab).
- Broader MISP version compatibility beyond `2.5.42` remains untested — see
  `docs/misp-compatibility.md`.
- Container/dependency/secret scanning and signed release artifacts are not yet part of CI/release
  — see `docs/production-readiness.md`.
