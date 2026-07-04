# Live beta validation checklist — v0.2.0-beta.2

`v0.2.0-beta.2` is an operational-readiness hardening release on top of `v0.2.0-beta.1`'s
production-write approval beta. It adds `agentic-misp-mcp config doctor`, `agentic-misp-mcp
approvals prune`, a rollback playbook, and mocked/controlled coverage closing four
`v0.2.0-beta.1` live-validation gaps (HTTP 429, large-result truncation, positive warninglist hit,
warninglist `not_available`). It does not change any MCP tool's behavior, add MISP write
capability, or touch the policy/approval/audit code paths validated in `v0.2.0-beta.1`.

Status target: **operational-readiness hardening, still suitable for isolated pilot validation
only**. Passing this checklist does **not** make the project GA production-ready.

## Ground rules

Same ground rules as
[`docs/live-beta-validation-v0.2.0-beta.1.md`](live-beta-validation-v0.2.0-beta.1.md): use an
isolated non-production MISP instance, scoped test data, no new write capability, and never
include `MISP_API_KEY`, `approval_token`, bearer tokens, cookies, or authorization headers in
evidence. Use generic/placeholder hostnames and paths in any recorded evidence, not real internal
lab addresses.

## What is in scope for this checklist

This release adds no new MCP tools and changes no read/write workflow behavior, so it does not
repeat the full `v0.2.0-beta.1` read-only/controlled-write checklist. Instead it validates:

| Check | Required evidence | Status |
| --- | --- | --- |
| `agentic-misp-mcp config doctor` runs against a real lab `.env` | Confirm it does not connect to MISP, produces PASS/WARN/FAIL lines matching the real configuration (e.g. `MISP_VERIFY_TLS=false` on a self-signed lab produces a `WARN`, not a crash), and exits `0` when no `FAIL` is present. | [x] |
| `config doctor` never prints secret values | Confirm `MISP_API_KEY` and `AGENTIC_MISP_MCP_APPROVAL_TOKEN` values never appear in output, only presence/absence. | [x] |
| `agentic-misp-mcp approvals prune` runs against a real (scratch) approval store | Create a store, add a record, let it terminalize, run `prune --older-than <duration> --vacuum`, confirm no crash and a sane exit code. | [x] |
| `approvals prune` rejects an invalid `--older-than` value | Confirm nonzero exit and no store mutation. | [x] |
| Read-only regression smoke test | Confirm `search_attributes`/`check_warninglists` (unmodified in this release) still succeed against the live lab MISP instance, since beta.2 touches only new CLI-only code paths. | [x] |

## Evidence summary for release notes

- `config doctor` result: **PASS** overall against the real lab `.env`, with two expected `WARN`
  lines (`MISP_VERIFY_TLS=false` — expected for this self-signed lab; the audit log path pointing
  into a scratch/temp directory for this validation run only, not the lab's real deployment path).
  No `FAIL`. Exit code `0`.
- `approvals prune` result: ran cleanly against a scratch approval store (0700 permissions);
  `--vacuum` completed without error; an invalid `--older-than` value (`bogus`) exited nonzero
  (`2`) with a clear message and did not touch the store.
- Read-only regression: `check_warninglists` and `search_attributes` both completed successfully
  against the live lab MISP instance with no errors, confirming beta.2's additive-only CLI changes
  did not regress the existing read-only path.
- No new bugs found during this validation pass.
- Full results: see
  [`docs/live-validation-report-v0.2.0-beta.2.md`](live-validation-report-v0.2.0-beta.2.md).
- Explicit statement for release notes: `v0.2.0-beta.2` is an operational-readiness hardening
  release for isolated pilot validation only, not GA production-ready. The `v0.2.0-beta.1`
  live-validation gaps this release closes (HTTP 429, large-result truncation, positive
  warninglist hit, warninglist `not_available`) were closed with mocked/controlled tests per
  scope, not live MISP rate-limit/large-dataset reproduction — see
  `docs/live-validation-plan.md` for what remains genuinely live-untested.

## Stop conditions

Do not tag `v0.2.0-beta.2` if `config doctor` ever prints a secret value, if `approvals prune`
ever deletes a `pending` or `approved` record, or if the read-only regression smoke test fails.
