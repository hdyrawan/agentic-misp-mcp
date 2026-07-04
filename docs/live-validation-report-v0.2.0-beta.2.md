# Live validation report — v0.2.0-beta.2

## Summary

| Item | Value |
| --- | --- |
| Date/time | 2026-07-04T13:03:22+00:00 |
| Branch | `hardening/v0.2.0-beta.2-operational-readiness` |
| Package version | `0.2.0-beta.2` |
| MISP version | `2.5.42` (same non-production lab used for `v0.2.0-beta.1` validation) |
| MISP URL | redacted (generic placeholder used below: `https://misp.lab.internal`) |
| Secrets in report | Redacted; no API keys, bearer tokens, cookies, authorization headers, or approval tokens included |

Result: `v0.2.0-beta.2` operational-readiness validation executed against the same configured
local MISP lab used for `v0.2.0-beta.1`. All checks in scope for this release passed. This is a
narrower validation pass than `v0.2.0-beta.1`'s, because beta.2 adds only CLI-only operator
tooling (`config doctor`, `approvals prune`) and mocked/controlled test coverage — it changes no
MCP tool behavior and touches no policy/approval/audit code path that beta.1 already validated
live.

This validates the repository as a `v0.2.0-beta.2` operational-readiness hardening candidate
suitable for isolated pilot validation. It does **not** make the project GA production-ready.

## Environment summary

- Deployment shape: local repository execution using `uv run` against the same lab `.env` used
  for `v0.2.0-beta.1` (`<user-config-dir>/agentic-misp-mcp/live.env`); secrets were not printed or
  copied into this report.
- TLS: lab config uses `MISP_VERIFY_TLS=false` for this self-signed lab; `config doctor` correctly
  flagged this as a `WARN`, not a `FAIL` (expected, matches `docs/production-readiness.md`'s
  TLS-requirements guidance that this is lab-only).
- Audit log and approval store paths were overridden to isolated scratch directories (mode
  `0700`) for this validation run only, not committed and not the lab's real deployment paths.
- Approval mode in this lab's `.env` is `lab` (the default), consistent with beta.1's validated
  configuration; no production approval-mode store existed to validate against live, so
  `config doctor`'s production-only checks (approval-store permissions, allowlist coverage,
  leftover token) were exercised only via the mocked test suite (`tests/test_config_doctor.py`),
  not against this lab.

## Test cases

| # | Test case | Result | Evidence summary |
| ---: | --- | --- | --- |
| 1 | `agentic-misp-mcp config-check` against the real lab `.env` | PASS | exit code `0`, no secrets printed |
| 2 | `agentic-misp-mcp config doctor` against the real lab `.env` | PASS | overall `PASS`, exit code `0`; two expected `WARN` lines (`MISP_VERIFY_TLS=false`; audit log path pointing into this validation run's scratch directory), no `FAIL` |
| 3 | `config doctor` never prints secret values | PASS | `MISP_API_KEY` and `AGENTIC_MISP_MCP_APPROVAL_TOKEN` values absent from output; only presence/absence and `[REDACTED]` markers shown |
| 4 | `agentic-misp-mcp approvals prune --older-than <n> --vacuum` against a real (scratch) SQLite approval store | PASS | ran cleanly against a `0700` scratch store containing one expired record; `VACUUM` completed without error; exit code `0` |
| 5 | `approvals prune --older-than bogus` (invalid duration) | PASS | exit code `2`, clear `Invalid --older-than value` message, store untouched |
| 6 | read-only regression: `check_warninglists("8.8.8.8")` | PASS | `status=available`, `hit=False` |
| 7 | read-only regression: `search_attributes("8.8.8.8", 5)` | PASS | returned `3` matches from lab data, no error |

## Evidence summary for release notes

- `config doctor` and `approvals prune` both behave correctly against a real (non-mocked)
  environment: `config doctor` produces the expected PASS/WARN/FAIL classification without ever
  connecting to MISP or printing secrets, and `approvals prune` correctly deletes only terminal
  records, supports `--vacuum`, and rejects invalid durations without touching the store.
- The read-only regression smoke test (`check_warninglists`, `search_attributes`) confirms
  beta.2's additive-only CLI changes did not affect the existing, already-validated read-only
  MISP client path.
- The four `v0.2.0-beta.1` live-validation gaps this release targets (HTTP 429, large-result
  truncation, positive warninglist hit, warninglist `not_available`) were closed with
  mocked/controlled tests per the release's own scope (`tests/test_operational_gap_closure.py`),
  not by reproducing a live HTTP 429 or an oversized live MISP result — doing so live would
  require a load-testing or artificially degraded MISP instance, out of scope here and
  explicitly excluded from this beta's live-validation ground rules (no DoS-style testing).
  `docs/live-validation-plan.md` still lists these as open live-evidence items for a future pass.
- No bugs were found during this validation pass; no source changes were required as a result of
  it.
- Explicit statement for release notes: `v0.2.0-beta.2` is an operational-readiness hardening
  release for isolated pilot validation only, not GA production-ready.

## What remains open (unchanged from beta.1, not addressed by this release)

- Live HTTP 429/rate-limit reproduction, live large-event/result-set truncation against realistic
  scale, and a live positive warninglist hit remain live-untested — see
  `docs/live-validation-plan.md` and `docs/production-readiness.md`'s release/sign-off checklist.
  This release closes them with mocked/controlled tests only, as scoped.
- Broader MISP version compatibility beyond `2.5.42` remains untested.
- `propose_event`/`propose_attribute` payload-shape validation against real MISP endpoints remains
  pending.
