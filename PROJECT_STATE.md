# PROJECT_STATE

Project: agentic-misp-mcp

Current status:
- **`v0.2.0` is GA production-ready for the MCP server scope defined in this project** (MCP
  server behavior, MISP API behavior, approval workflow, audit/redaction, config safety,
  runtime/deployment docs) — not a SIEM/SOAR/SOC platform, case-management system, or broad
  enterprise-monitoring claim; SIEM/SOAR/SOC integration remains optional future work, not a GA
  requirement. Manual audit-log review is the accepted control for this release, not automated
  SOC-grade alerting/monitoring. `MISP 2.5.42` is the validated GA baseline; other MISP versions
  should run the validation checklist (`docs/live-validation-plan.md`,
  `docs/misp-compatibility.md`) before being trusted — none are covered by this GA claim. HTTP
  429/rate-limit handling has controlled/mocked test coverage only; a live 429 was not performed
  (no safe way to trigger one in the lab).
- `main` now contains `v0.2.0-beta.2` (merged via PR #8, commit `6482348`): adds
  `agentic-misp-mcp config doctor` (PASS/WARN/FAIL operational-readiness checks, secrets
  redacted, nonzero exit on `FAIL`), `agentic-misp-mcp approvals prune --older-than <duration>
  [--vacuum]` (operator-CLI-only approval-store maintenance, never exposed as an MCP tool),
  `docs/rollback.md`, expanded Docker production guidance, and mocked/controlled test coverage
  closing four `v0.2.0-beta.1` live-validation gaps (HTTP 429, large-result truncation, positive
  warninglist hit, warninglist `not_available`). No MCP tools were added or changed; the MCP tool
  count and write-tool count (6) remain unchanged. See `docs/live-validation-report-v0.2.0-beta.2.md`
  for live validation evidence (config doctor / approvals prune run against the same lab used for
  beta.1, plus a read-only regression smoke test — no bugs found).
- `main` now contains `v0.2.0`, the **first GA release** (merged via PR #9, commit `810d76e`, then
  PR #13 with two live-validation fixes, commit `c846035`). `v0.2.0-rc.1` was tagged and released
  as a GitHub pre-release at `810d76e`; its own release notes were amended to flag that the two
  fixes below post-date that exact tagged artifact. `v0.2.0-rc.1` added payload validation to
  `propose_event`/`propose_attribute` (`policy/proposal_validation.py` — required fields, value
  ranges, known attribute type/category vocabulary; a malformed/unsupported payload returns
  `status: "invalid"`, audited as a new `outcome: "invalid"`, and still never calls MISP), a MISP
  compatibility matrix (`docs/misp-compatibility.md`), a fixed `.github/dependabot.yml`, and a
  documented dependency-update/supply-chain release-checklist process. Live validation of
  `v0.2.0-rc.1` against the real MISP lab then found and fixed two real defects (see
  `docs/live-validation-report-v0.2.0-rc.1.md`):
  - `add_sighting_with_approval` reported `status: "executed"` (audited `outcome: "success"`) for
    a sighting MISP actually rejected (no `Sighting` key in the response, just an error
    `message`). `MISPSightingSummary` gained a `saved`/`message` signal and the workflow now
    returns `status: "failed"`, matching the existing `tag_event`/`publish_event` pattern.
  - `check_warninglists` silently reported `not_available` for a real positive hit against MISP
    `2.5.42`, because `parse_warninglist_response` didn't recognize this version's actual
    value-keyed hit shape (`{"<value>": [{match...}]}`). Fixed by recognizing that shape.
  No MCP tools were added or changed at any point from `v0.2.0-rc.1` to `v0.2.0`; the MCP tool
  count and write-tool count (6) remain unchanged. `v0.2.0` is a GA release per this project's
  evidence-based GA criteria (automated tests pass, live validation found no unresolved critical
  blockers, docs consistent, secrets/redaction pass, known limitations documented, no unsafe tool
  boundary) — see "Known limitations" below for what remains open beyond this GA claim, and note
  this is **not** the same as full certification against `docs/production-readiness.md`'s broader,
  stricter checklist (multi-version MISP compatibility, live HTTP 429, supply-chain scanning,
  signed releases).
- `v0.2.0-beta.1` production-write beta (now part of `main` via `v0.2.0-beta.2`): opt-in
  `AGENTIC_MISP_MCP_APPROVAL_MODE=production` adds SQLite approval records, CLI-only
  approve/reject, one-time redemption, exact operation hashes, TTL expiry, replay/payload-swap
  blocking, publish kill switch, and type/category/tag guardrails for the four existing
  write-executing tools only. Default lab mode remains backward compatible; `approval_token` is
  lab/shared-secret hardening only, while production requires an operator-approved
  `approval_request_id` and consumes it before the MISP write attempt. Suitable for isolated
  pilot validation only; not GA production-ready.
- Phase 1 complete: read-only core MCP
- Phase 2 complete: agentic IOC investigation engine
- Phase 3 complete: event intelligence and pivoting
- Phase 4 complete: deterministic report generation
- Phase 5 complete: runtime/deployment tooling (config-check CLI, experimental HTTP
  transport, Docker/Compose docs), merged into main
- Phase 6 complete: OpenAPI inventory/planning-only classifier. Added `openapi-inventory`
  CLI command. Classifies MISP OpenAPI endpoints into read/write/admin/sync/dangerous/unknown
  with risk level, approval_required, and recommended_role. Does not expose any MISP API
  endpoint as an MCP tool.
- Policy/approval foundation complete: `policy/engine.py`, `policy/approvals.py`,
  `policy/models.py`, plus `AGENTIC_MISP_MCP_ROLE` / `AGENTIC_MISP_MCP_ENABLE_WRITE` /
  `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` settings. Read-only tool boundary unchanged (13 tools).
- Phase 8 complete: controlled write workflows. Added exactly six new MCP tools
  (`propose_event`, `propose_attribute`, `submit_ioc_with_approval`,
  `add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval`),
  wired into the `PolicyEngine`/`ApprovalRequest` foundation. Added a `publish` policy
  action (curator/admin only). Added narrow MISP write methods (`add_attribute`,
  `add_sighting`, `tag_event`, `publish_event`) to `misp/client.py` — no
  generic write/request proxy. Writes are disabled by default
  (`AGENTIC_MISP_MCP_ENABLE_WRITE=false`), and even when enabled, every write tool call
  resolves to `blocked`, `pending_approval`, or `executed` — never a silent write.
- Phase 9 complete: production hardening. Added GitHub Actions CI for Python 3.11/3.12,
  Makefile quality targets, top-level `SECURITY.md`, Docker/.dockerignore hygiene, production
  hardening tests, and documentation updates for CI, early-development status, HTTP transport
  warnings, runtime-only secrets, and Phase 8 policy environment variables. Tool behavior and
  MCP tool count remain unchanged.
- Phase 10 alpha public-readiness: repository hygiene, tracked-file inventory, sensitive-content scan,
  README/security/changelog/project-state review, version check, final quality gates, and Docker
  release-check validation completed for safe public GitHub publishing as an early-development
  MIT-licensed open-source project. README has been rewritten for public publish readiness, and
  `llms.txt` has been added for LLM/coding-agent orientation. No git tag has been created.
- Phase 10.1 complete: external review follow-up documentation added. Added `docs/testing.md`
  (mocked endpoint/response/workflow coverage and known gaps), `docs/roles.md` (per-role
  intended use, allowed tool categories, write permissions, approval requirements, and
  limitations — explicitly clarifying that `admin` does not expose any raw MISP admin API and
  that no user/organisation/server/settings admin tools exist), `docs/approval-flow.md` (the
  `approved=false` → `pending_approval` → `approved=true` flow with worked examples for
  `submit_ioc_with_approval` and `publish_event_with_approval`), and
  `docs/live-validation-plan.md` (the live MISP lab validation checklist — see Phase 10.2 below
  for its execution). README now links all four alongside existing docs. No MCP tools were added,
  no tool behavior changed, and no dry-run mode was added in this phase.
- Dry-run mode was considered during this review follow-up but deliberately **deferred** until
  after live lab validation (`docs/live-validation-plan.md`) is complete, so that any dry-run
  behavior can be designed against confirmed real MISP response shapes rather than mocked
  assumptions.
- Phase 10.2 complete: live MISP lab validation executed against a non-production MISP `2.5.42`
  lab, using Docker and MCP Inspector (both browser and headless `--cli` modes). Read-only tools,
  error paths (unreachable `MISP_URL`, invalid `MISP_API_KEY`), and policy-blocking behavior all
  passed. Core controlled-write validation also passed for `submit_ioc_with_approval`,
  `add_sighting_with_approval`, `tag_event_with_approval`, and `publish_event_with_approval`
  (including role-based publish blocking), tested against a dedicated sandbox event rather than
  real historical data. Two real bugs were found and fixed during this pass:
  - A blank/whitespace `AGENTIC_MISP_MCP_APPROVAL_TOKEN` (e.g. `KEY=` in a `.env` file) was
    parsed as a configured empty-string token rather than "unset," silently blocking every
    controlled-write execution. Now normalizes to `None`.
  - `tag_event_with_approval`/`publish_event_with_approval` reported `status: "executed"` even
    when MISP itself rejected the operation (HTTP 200 with `saved`/`published: false`). Both now
    report a distinct `status: "failed"`, with a matching `outcome: "failed"` audit entry.
  See `docs/live-validation-plan.md` for full evidence and what remains: `propose_event`/
  `propose_attribute` payload validation, large event/result-set behavior, rate-limit/timeout/TLS
  failure modes, warninglist endpoint compatibility across MISP versions, broader MISP version
  compatibility, and final sign-off.

- Phase 11 candidate merged to `main`: `v0.2.0-beta.1` production-write beta. Scope is limited
  to a production approval layer for the four existing write-executing tools only
  (`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`,
  `publish_event_with_approval`); no raw proxy, new MISP endpoints, admin MCP tools, or additional
  write capabilities are in scope. Lab approval mode remains the default unless
  `AGENTIC_MISP_MCP_APPROVAL_MODE=production` is explicitly configured. Suitable for isolated
  pilot validation; not GA production-ready.
- Phase 12 (`v0.2.0-rc.1`, current release-candidate branch): GA-readiness follow-up on top of
  `v0.2.0-beta.2`. Added `propose_event`/`propose_attribute` payload validation (required fields,
  value ranges, known attribute type/category vocabulary) with a new `status: "invalid"`/
  `outcome: "invalid"` result distinct from `blocked`/`failed`/`success`; a MISP compatibility
  matrix (`docs/misp-compatibility.md`) documenting the one tested version (`2.5.42`) and known
  version-drift risks; a fixed `.github/dependabot.yml` (previously blank `package-ecosystem`);
  and a documented dependency-update/supply-chain release-checklist process in
  `docs/production-readiness.md`. No MCP tools added or changed; write-tool count (6) and total
  tool count (19) unchanged. `docs/live-beta-validation-v0.2.0-rc.1.md` was added as a pending
  checklist at the time this phase's docs were written; it was fully executed in Phase 13 below.
- Phase 13 complete: `v0.2.0-rc.1` live validation executed against the real MISP `2.5.42` lab
  end-to-end (not mocked): `propose_event`/`propose_attribute` valid/invalid, TLS fail-closed,
  timeout, large-result truncation, a real positive warninglist hit (with one warninglist
  temporarily enabled in the lab for this check, then disabled again), warninglist miss, the full
  production approval lifecycle (pending → require valid `approval_request_id` → block
  `approved=true` alone → one real MISP write on redemption → block replay/wrong-tool/
  hash-mismatch/expired/rejected redemption), audit redaction/correlation, `config doctor` against
  safe and unsafe configs, and `approvals prune` against a disposable store. Found and fixed the
  two real defects described above. Result recorded in
  `docs/live-validation-report-v0.2.0-rc.1.md`. `v0.2.0-rc.1` was tagged and released as a GitHub
  pre-release, then the two fixes were merged to `main` afterward (the tag itself was not moved;
  its release notes were amended instead). `v0.2.0` GA release prep (version bump, RC→GA doc
  wording) followed as this same pass's final step.

Current tests: 257 passed on `main` (up from 220 at the start of the beta.2/rc.1 work, 254 at the
`v0.2.0-rc.1` tag).
Current MCP tool count: 19 (unchanged; `config doctor`, `approvals prune`, and the proposal
validation layer are not MCP tools).
Current license: MIT.

Current MCP tools:
1. search_ioc
2. investigate_ioc
3. summarize_event
4. check_warninglists
5. generate_ioc_report
6. pivot_ioc
7. find_related_iocs
8. extract_event_iocs
9. explain_event_context
10. find_events_by_tag
11. generate_event_report
12. generate_markdown_ioc_report
13. generate_markdown_event_report
14. propose_event
15. propose_attribute
16. submit_ioc_with_approval
17. add_sighting_with_approval
18. tag_event_with_approval
19. publish_event_with_approval

Hard rules:
- No raw MISP API proxy
- No generic user/organisation/server/settings-style admin tools
- Write tools (14-19 above) are disabled by default and policy/approval-gated when enabled
- No Hermes runtime testing yet
- Mocked tests only unless explicitly requested

Current validation status:
- Live read-only lab validation: passed (see Phase 10.2 above).
- Core controlled-write lab validation: passed for `submit_ioc_with_approval`,
  `add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval` (see
  Phase 10.2 above), and re-confirmed end-to-end in Phase 13 including the full production
  approval lifecycle and one real MISP write.
- TLS fail-closed, timeout, large-result truncation, warninglist hit/miss/`not_available`,
  `propose_event`/`propose_attribute` validation, audit redaction/correlation, `config doctor`
  (safe and unsafe configs), and `approvals prune`: all live-validated in Phase 13. See
  `docs/live-validation-report-v0.2.0-rc.1.md`.
- `v0.2.0` is a **GA release** per this project's own evidence-based GA criteria. This is
  narrower than full production-readiness certification against `docs/production-readiness.md`'s
  broader, stricter checklist — see "Known limitations" below.

Known limitations (explicitly not covered by the `v0.2.0` GA claim):
- Only MISP `2.5.42` has been validated; broader MISP version compatibility remains untested
  (`docs/misp-compatibility.md`).
- A real (non-mocked) HTTP `429`/rate-limit response was not reproduced live — no safe way to
  trigger one in this lab without a load-testing setup, which is out of scope. Verified via a mock
  transport only.
- Container image scanning, dependency vulnerability scanning, secret scanning, and a signed
  release tag are not yet part of CI/release (`docs/production-readiness.md`,
  `docs/ga-production-readiness-plan.md`).
- Approval-operator separation still relies on filesystem permissions rather than a stronger
  mechanism.

Next steps:
- Broader MISP version compatibility testing beyond `2.5.42` (`docs/misp-compatibility.md`).
- Automate the three still-open supply-chain scans (dependency vulnerability, container image,
  secret scanning) in CI/release, per `docs/production-readiness.md`'s "Dependency update process
  and supply-chain release checklist".
- Decide whether and when to tag `v0.2.0` (this GA release prep has not tagged or pushed a `v0.2.0`
  git tag; that step was left for explicit approval).
