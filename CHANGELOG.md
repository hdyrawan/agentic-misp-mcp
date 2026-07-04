# Changelog

All notable changes to this project will be documented in this file.

This project has mocked test coverage plus live-lab validation (read-only and controlled-write)
against MISP `2.5.42`; broader MISP version compatibility testing is still pending.

## v0.2.0 (2026-07-04) — first GA release

**`v0.2.0` is GA production-ready for the MCP server scope defined in this project** (MCP server
behavior, MISP API behavior, approval workflow, audit/redaction, config safety, runtime/
deployment docs), not full production-readiness certification against
`docs/production-readiness.md`'s broader, stricter checklist. GA here means: automated tests pass
(257), live validation against a real MISP lab found no unresolved critical blockers, docs are
consistent, secrets/redaction review passes, and known limitations are documented — see
`docs/live-validation-report-v0.2.0-rc.1.md` and `docs/ga-production-readiness-plan.md`. It builds
on `v0.2.0-rc.1` (tagged and released as a GitHub pre-release) plus two fixes found during that
release candidate's own live validation pass, detailed below. No new MCP tools, no new MISP write
capability, no raw proxy/admin behavior were introduced anywhere in this progression.

This is not a SIEM/SOAR/SOC platform, case-management system, or broad enterprise-monitoring
claim; SIEM/SOAR/SOC integration remains optional future work, not a GA requirement. Manual
audit-log review is the accepted control for this release, not automated SOC-grade
alerting/monitoring. `MISP 2.5.42` is the validated GA baseline; other MISP versions should run
the validation checklist (`docs/live-validation-plan.md`, `docs/misp-compatibility.md`) before
being trusted — none are covered by this GA claim. HTTP 429/rate-limit handling has
controlled/mocked test coverage only; a live 429 was not performed (no safe way to trigger one in
the lab).

### v0.2.0-rc.1 live validation fixes (2026-07-04)

Live validation of `v0.2.0-rc.1` against a real MISP `2.5.42` lab found and fixed two real
blockers. See `docs/live-validation-report-v0.2.0-rc.1.md` for full evidence.

- Fixed `add_sighting_with_approval`: it reported `status: "executed"` (and audited
  `outcome: "success"`) even when MISP answered HTTP 200 but rejected the sighting itself (e.g.
  `{"message": "Could not add the Sighting. Reason: No valid attributes found."}`, with no
  `Sighting` key). `MISPSightingSummary` gained a `saved`/`message` signal, mirroring the existing
  `tag_event`/`publish_event` rejection handling, and the workflow now returns `status: "failed"`
  when MISP rejects the sighting.
- Fixed `check_warninglists`: `parse_warninglist_response` did not recognize MISP `2.5.42`'s real
  positive-hit response shape for `/warninglists/checkValue` — a dict keyed by the queried value,
  mapping to a list of match objects (e.g. `{"10.1.2.3": [{"id": "88", "name": "...", "matched":
  "10.0.0.0/8"}]}`) — and silently reported `status: "not_available"` instead of `hit: true`. This
  was the exact live positive-hit gap `docs/misp-compatibility.md` had flagged as untested.
- 257 mocked/controlled tests pass (up from 254); `ruff check`/`ruff format --check` clean. Both
  fixes were also re-verified live against the MISP lab after the change.

### v0.2.0-rc.1 GA-readiness release candidate (2026-07-04)

`v0.2.0-rc.1` builds on `v0.2.0-beta.2` and is a **release candidate for GA review**, not a GA
claim. It adds no new MCP tools, no new MISP write capability, and no raw proxy/admin behavior.

- Added payload validation to `propose_event`/`propose_attribute`
  (`src/agentic_misp_mcp/policy/proposal_validation.py`): required fields, `distribution`/
  `threat_level_id`/`analysis` value ranges, tag list shape, and a known-vocabulary allowlist of
  standard MISP attribute types/categories. A malformed or unsupported payload now returns a new
  `status: "invalid"` (audited as a new `outcome: "invalid"`, distinct from `blocked`/`failed`/
  `success`) with a `validation_errors` list, instead of building a proposal. Both tools still
  never call MISP either way. See `tests/test_proposal_validation.py`,
  `tests/workflows/test_controlled_write.py`, and `tests/test_controlled_write_tools.py`.
- Fixed `.github/dependabot.yml`: its `package-ecosystem` value was blank, so no Dependabot
  updates were actually running. It now tracks `pip` and `github-actions` ecosystems on a weekly
  schedule. Documented the dependency-update review process and the still-open
  container-image/dependency/secret scanning release-checklist items in
  `docs/production-readiness.md`.
- Added `docs/misp-compatibility.md`: a MISP version compatibility matrix documenting the one
  version this project has actually tested against (`2.5.42`), this project's API/response-shape
  assumptions, untested versions, and known version-drift risks (especially warninglist endpoint
  shape and the curated attribute type/category vocabulary).
- Added `docs/live-beta-validation-v0.2.0-rc.1.md`: the live validation checklist for this release
  candidate. As of this release, it has **not** been executed — every item is pending, not passed.
  No `docs/live-validation-report-v0.2.0-rc.1.md` was created, since no live validation was
  actually run; creating one without real evidence would misrepresent validation status.
- Updated `docs/ga-production-readiness-plan.md`, `docs/production-readiness.md`,
  `docs/production-write.md`, `docs/security.md`, `docs/configuration.md`,
  `docs/approval-flow.md`, `README.md`, and `llms.txt` to describe the new validation behavior,
  the new `invalid` audit outcome, and this release's actual (partial) progress against the GA
  plan's open items. This release does not claim GA production readiness; see
  `docs/ga-production-readiness-plan.md` for what remains.
- 254 mocked/controlled tests pass (up from 220 on `main` at the start of this pass); `ruff
  check`/`ruff format --check` clean.

### v0.2.0-beta.2 operational-readiness hardening (2026-07-04)

`v0.2.0-beta.2` builds on the `v0.2.0-beta.1` production-write approval beta with operational
tooling and closed test gaps. It adds no new MCP tools, no new MISP write capability, and no raw
proxy/admin behavior; it is still a beta, not a GA production-readiness claim.

- Added `agentic-misp-mcp config doctor`, a deeper operational-readiness check beyond
  `config-check`: validates write/approval-mode pairing, publish/role pairing, approval-store and
  audit-log writability and permission safety, production write allowlist coverage, approval TTL
  length, temporary-directory paths, and leftover lab approval tokens in production mode. Output
  is `PASS`/`WARN`/`FAIL` per check, secrets are never printed, and the command exits nonzero on
  any `FAIL`. See `src/agentic_misp_mcp/config_doctor.py` and `docs/configuration.md`.
- Added `agentic-misp-mcp approvals prune --older-than <duration> [--vacuum]`, an operator-CLI-only
  maintenance command that deletes old terminal (`used`/`rejected`/`expired`) approval records
  past an age threshold (`7d`/`30d`/`24h`/`3600s`-style durations), optionally followed by SQLite
  `VACUUM`. Never deletes `pending`/`approved` records regardless of age. An invalid duration exits
  nonzero without mutating the store. Not exposed through any MCP tool — the LLM/agent cannot
  prune or vacuum the approval store. See `SqliteApprovalStore.prune()` in
  `src/agentic_misp_mcp/policy/approval_store.py`.
- Added `docs/rollback.md`: how to find a mistaken controlled write in the audit log, correlate it
  with its approval record, and roll it back directly in MISP (no delete/unpublish/retract MCP
  tool exists by design), plus an explicit explanation of why a mistaken publish is not fully
  reversible.
- Expanded Docker production guidance in `docs/production-readiness.md`: a concrete read-only
  root-filesystem `docker run` example, explicit stdio-first/no-public-HTTP-by-default guidance,
  role-separated least-privilege deployment guidance, and a "generic paths only" convention
  reminder.
- Closed four `v0.2.0-beta.1` live-validation gaps with mocked/controlled tests exercised through
  the full registered-tool and audit path (`tests/test_operational_gap_closure.py`): HTTP `429`
  (`MISPRateLimitError`) propagates cleanly with no crash and no secret leak in the audit record;
  an oversized MISP response (`MISPResponseTooLargeError`) is bounded and never dumped into the
  audit log; a positive warninglist hit surfaces correctly through the registered
  `check_warninglists` tool; and warninglist `not_available` surfaces correctly through the same
  path. These are mocked/controlled closures, not live reproductions of a real `429` or an
  oversized live MISP result — see `docs/live-validation-report-v0.2.0-beta.2.md` for what was
  validated live instead (the new CLI commands, plus a read-only regression smoke test).
- Added regression/contract tests: `tests/test_config_doctor.py` (21 tests),
  `tests/test_approvals_prune.py` (20 tests), and `tests/test_operational_gap_closure.py` (6
  tests), plus `test_write_tool_count_unchanged_at_six` and
  `test_no_config_doctor_or_approvals_prune_mcp_tools_exist` in `tests/test_tools_contract.py`
  confirming the write-tool surface and the no-new-MCP-tool boundary are unchanged.
- Added `docs/live-beta-validation-v0.2.0-beta.2.md` and
  `docs/live-validation-report-v0.2.0-beta.2.md`: `config doctor` and `approvals prune` were run
  against the same non-production MISP `2.5.42` lab used for `v0.2.0-beta.1`, plus a read-only
  regression smoke test (`check_warninglists`, `search_attributes`) confirming this release's
  additive-only CLI changes did not regress the existing read-only path. No bugs found.

### Live beta validation hardening (2026-07-04)

- Clarified that `main` now contains the `v0.2.0-beta.1` production-write beta candidate and that it is suitable for isolated pilot validation only, not GA production readiness.
- Added `docs/live-beta-validation-v0.2.0-beta.1.md` with read-only edge-case checks and production approval-mode checks for one-time redemption, replay/hash-mismatch/wrong-tool blocking, publish kill switch behavior, allowlists, and audit redaction.
- Expanded production deployment hardening and GA backlog guidance in `docs/production-readiness.md`.

### v0.2.0-beta.1 production-write approval beta

- Added opt-in `AGENTIC_MISP_MCP_APPROVAL_MODE=production` for the four existing write-executing approval tools only. Lab mode remains the default.
- Added SQLite approval persistence, one-time-use redemption, TTL expiry, exact canonical operation hashes, replay/payload-swap/wrong-tool blocking, and CLI-only approval administration.
- Added `AGENTIC_MISP_MCP_ENABLE_PUBLISH=false` default publish kill switch plus optional attribute type and tag allowlists.
- Added approval correlation audit fields without changing top-level outcome values.
- Added `docs/production-write.md` and `.env.production-write.example`; this remains a beta, not GA production certification.

### Production readiness baseline (2026-07-04)

- Added `docs/production-readiness.md`: scope, the read-only-first production target,
  controlled-write production requirements, required runtime configuration, TLS requirements,
  secret handling, audit logging/manual review guidance, a Docker hardening checklist, a
  condensed live validation checklist, a release/sign-off checklist (with explicit acceptance
  criteria, marked done/pending against current evidence), and explicit non-goals.
- Added `.env.production.example`: a placeholder-only production env template defaulting to
  `MISP_VERIFY_TLS=true`, `AGENTIC_MISP_MCP_ROLE=read_only`,
  `AGENTIC_MISP_MCP_ENABLE_WRITE=false`, `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`, and
  `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=false`. Leaves `AGENTIC_MISP_MCP_APPROVAL_TOKEN`
  unset (commented out with guidance) rather than blank, to avoid the blank-token ambiguity
  described below. Added a `.gitignore` exception so the file is tracked.
- Added a "Production deployment" section to `README.md`: Docker stdio deployment, `config-check`,
  a MISP connectivity test, audit-log volume mounting, and an explicit statement that HTTP
  transport requires an authenticated TLS-terminating gateway and is not the default
  recommendation.
- Reconciled remaining stale validation-status claims across `README.md`, `PROJECT_STATE.md`,
  `docs/security.md`, `docs/testing.md`, `docs/live-validation-plan.md`, and `llms.txt`: all now
  consistently state that live read-only validation and core controlled-write validation have
  passed in a lab, that production deployment is not yet validated, and that broader MISP
  compatibility/edge-case validation/production hardening remain pending. Also fixed
  `docs/live-validation-plan.md` sections 1-3, which were still entirely unchecked despite
  `README.md` already recording passing evidence for `search_ioc`, `investigate_ioc`,
  `summarize_event`, and `generate_ioc_report`.
- No source code changes in this pass; `146` tests still pass.

### README rewrite and security-doc corrections (2026-07-04, follow-up)

- Rewrote the README's "Quick start" section: it previously buried a single Docker-only
  walkthrough (build image → env file → audit-log dir → connectivity test → MCP Inspector → SSH
  tunnel) behind a wall of validation-specific steps, with no local (non-Docker) path at all. It
  is now two short, parallel paths — **Option A: local install** (`pip`/`uv`) and **Option B:
  Docker** — each with install → configure → validate → run → MCP client config, plus a shared
  "Verify it's working" step. The deeper validation walkthrough (MCP Inspector, SSH tunneling,
  read-only test checklist) moved to a renamed "Testing against a live MISP lab (optional)"
  section further down, deduplicated against the new Quick start.
- Corrected `docs/security.md`'s stale opening claim ("has not been validated against a live MISP
  instance") — it has, for both read-only and controlled-write tools; only broader MISP version
  compatibility remains pending. Also corrected the CHANGELOG's own top-of-file disclaimer to the
  same effect.
- Documented the project's commit-provenance policy explicitly in `docs/security.md` and the
  README's "Contributing" section: commits must not carry an AI co-author trailer, regardless of
  what tooling assisted in writing them.

### Controlled-write live validation and fixes (2026-07-04, follow-up)

- Extended the MCP Inspector CLI live-lab validation to the controlled-write path
  (`AGENTIC_MISP_MCP_ENABLE_WRITE=true`, `analyst_write`/`curator` roles) against a dedicated
  sandbox event, exercising the full `pending_approval` → `approved=true` → `executed` flow for
  `submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, and
  `publish_event_with_approval`, plus role-based blocking (`analyst_write` on publish).
- **Fixed:** a present-but-empty `AGENTIC_MISP_MCP_APPROVAL_TOKEN` env var (e.g. `KEY=` in a
  `.env` file) was parsed as a configured empty-string token rather than "no token configured,"
  causing every controlled-write execution to be silently blocked with "approval token is
  required or invalid" even though `config-check` correctly displayed it as "not set". Blank/
  whitespace-only tokens now normalize to `None` in `settings.py`.
- **Fixed:** `tag_event_with_approval` and `publish_event_with_approval` reported
  `status: "executed"` even when MISP itself rejected the operation — `/events/addTag` and
  `/events/publish` can answer HTTP 200 with `saved`/`published: false` (e.g. an unrecognized tag
  name) without raising. Confirmed live: MISP never actually attached the tag despite the
  `executed` response. Both tools now return a distinct `status: "failed"` when MISP rejects the
  write, and `audit_call` records a matching `outcome: "failed"` (not `success`, not `blocked`) so
  the audit trail doesn't claim success for a write MISP never applied.
- Added regression tests: `test_settings.py::test_blank_approval_token_env_var_becomes_none`,
  `test_controlled_write_tools.py::test_tag_event_reports_failed_when_misp_rejects_the_tag` /
  `test_publish_event_reports_failed_when_misp_does_not_publish`, and
  `test_audit.py::test_audit_tool_reported_failure_is_not_success`.

### MCP Inspector CLI live validation (2026-07-04)

- Ran a CLI-mode (non-browser) MCP Inspector integration pass against a live, non-production
  MISP `2.5.42` lab: `tools/list`, live `search_ioc` / `find_events_by_tag` calls, a policy-blocking
  check on `submit_ioc_with_approval`, and error-path checks for an unreachable `MISP_URL` and an
  invalid `MISP_API_KEY`.
- Confirmed audit records match the documented semantics exactly: blocked writes log
  `success: false` / `outcome: "blocked"`; runtime failures (bad URL, bad key) log
  `outcome: "error"` with no secret material in `error_message`.
- No source changes were required; no bugs found. Controlled write tools and broader MISP
  version compatibility remain the only pending items before wider production use.

### Fixed

- Fixed audit records for blocked policy decisions (for example a write attempted while
  read-only or with `AGENTIC_MISP_MCP_ENABLE_WRITE=false`) incorrectly logging `success: true`.
  Blocked attempts (`policy.allowed == false`) now log `success: false` and a distinct
  `outcome: "blocked"`, separate from `outcome: "error"` for runtime exceptions. Found during
  first live read-only MISP validation.

### Security hardening before live lab validation

### Added

- Added optional approval-token enforcement via `AGENTIC_MISP_MCP_APPROVAL_TOKEN` for
  approval-gated write tools. When configured, `approved=true` also requires a matching
  `approval_token`; missing or incorrect tokens return `blocked`.
- Added centralized sanitization helpers for audit arguments, safe exception messages, recursive
  approval-request secret-key validation, and sensitive text redaction.
- Added `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` (default 5 MiB) and bounded MISP response reading
  before JSON parsing.
- Added `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=false` guardrail so experimental HTTP mode
  refuses `0.0.0.0` by default.

### Changed

- Audit logs and workflow partial-error outputs now use safe, truncated exception summaries rather
  than raw exception strings.
- Settings validation uses Pydantic hidden inputs so validation output does not reveal
  `MISP_API_KEY` values.
- Removed unused internal `MISPClient.create_event()` dead code; `propose_event` remains
  proposal-only and no event-submission MCP tool is exposed.
- Documentation now separates proposal-only tools from approval-gated write tools and clarifies
  that `approved=true` alone is programmatic gating, not a complete HITL approval mechanism.

### Security

- Kept the 19-tool MCP boundary unchanged: no raw proxy, no shell/filesystem tools, no generic
  admin/user/org/server-settings tools, and no `submit_event_with_approval`.
- Kept safe defaults unchanged: read-only role, write disabled, approval required, and TLS
  verification enabled by default.

### Phase 10.1 - Review follow-up documentation

### Added

- Added `docs/testing.md` documenting exactly which mocked MISP-like endpoints and response
  shapes are covered, which workflows/tools are tested with mocks, what is not covered yet
  (rate limiting, malformed responses, timeouts, large/paginated results, version drift), and
  that live MISP validation is still pending.
- Added `docs/roles.md` documenting the `read_only`, `analyst_write`, `curator`, and `admin`
  policy roles: intended use, allowed tool categories, controlled write permissions, approval
  requirements, and limitations for each — explicitly clarifying that the `admin` role does not
  expose any raw MISP admin API and that no user/organisation/server/settings admin tools exist.
- Added `docs/approval-flow.md` documenting the controlled write approval flow end to end
  (`approved=false` first call, `pending_approval` response, presenting the proposal to a
  human, explicit approval, second call with `approved=true`, audit logging), with worked
  examples for `submit_ioc_with_approval` and `publish_event_with_approval`.
- Added `docs/live-validation-plan.md`, a live MISP lab validation checklist covering MISP
  version, deployment method, API key permissions, warninglist load state, read/report/pivot
  tools, controlled write tools (lab only), large-event testing, rate-limit/timeout/error-path
  testing, warninglist testing, and expected evidence to record. Not yet executed.
- Linked all four new documents (plus existing `docs/security.md`, `docs/configuration.md`, and
  `docs/openapi-inventory.md`) from a new README "Documentation" section.

### Changed

- No MCP tools were added or removed and no tool behavior changed in this phase — this was a
  documentation-only follow-up to external review. Dry-run mode was considered and deliberately
  deferred until after live lab validation is complete.

### Phase 10 - Release readiness

### Changed

- Switched project license metadata and `LICENSE` to MIT.
- Prepared repository documentation for safe public GitHub publishing as an early-development
  open-source project.
- Rewrote README with clearer positioning, safety model, grouped tool list, quick start,
  example prompts, configuration table, roadmap, and contributing guidance.
- Added `llms.txt` for LLM/coding-agent orientation.
- Rechecked README, security policy, changelog, project state, packaging metadata, tracked-file
  hygiene, and sensitive-content scan results.

### Security

- Confirmed no real MISP configuration, API keys, audit logs, local handoff notes, virtualenvs, or
  cache directories are tracked.
- Confirmed the secret scan only reports expected placeholders, test fixtures, environment variable
  names, and generic security documentation.

### Phase 9 - Production hardening

### Added

- Added GitHub Actions CI for Python 3.11 and 3.12 running Ruff lint, Ruff format check, and the
  mocked pytest suite through `uv run --extra dev`.
- Added a `Makefile` with `lint`, `format-check`, `test`, and `check` targets.
- Added top-level `SECURITY.md` with early-development status, vulnerability reporting guidance,
  supported-version status, and secret-handling expectations.
- Added production-hardening tests for tool-boundary invariants, secret-safe CLI output, and safe
  policy defaults.

### Changed

- Documented CI, development commands, Docker secret handling, HTTP transport warnings, and Phase 8
  policy runtime guidance.
- Confirmed packaging metadata, Python 3.11+ requirement, MIT license metadata, CLI script,
  runtime dependencies, and dev optional dependencies without risky dependency changes.
- Tightened `.dockerignore` hygiene while keeping Docker runtime behavior unchanged: credentials
  are still runtime-only, and the image continues to run as a non-root user.

### Security

- Reaffirmed the 19-tool MCP boundary: no raw API proxy, shell/filesystem tool, generic admin tool,
  or secret/token/password parameter is exposed.
- Reaffirmed safe policy defaults: write mode disabled, read-only role, and approval required.

### Phase 8 - Controlled write workflows

### Added

- Added read-only MCP tools for IOC search, IOC investigation, event summarization, warninglist
  checks, and deterministic IOC reports (`search_ioc`, `investigate_ioc`, `summarize_event`,
  `check_warninglists`, `generate_ioc_report`).
- Added event intelligence and pivoting workflows (`pivot_ioc`, `find_related_iocs`,
  `extract_event_iocs`, `explain_event_context`, `find_events_by_tag`).
- Added deterministic structured and Markdown report generation for IOCs and MISP events
  (`generate_event_report`, `generate_markdown_ioc_report`, `generate_markdown_event_report`).
- Added JSONL audit logging for MCP tool calls.
- Added Docker and Docker Compose examples.
- Added configuration and security documentation.
- Added a policy/approval foundation (`policy/engine.py`, `policy/approvals.py`,
  `policy/models.py`) with role, write-mode, and approval-requirement environment variables.
- Added a MISP OpenAPI endpoint inventory/classifier CLI (`openapi-inventory`) for planning
  future write scope. Classification-only; does not call MISP or expose new MCP tools.
- Added six controlled, policy-gated write MCP tools, disabled by default
  (`AGENTIC_MISP_MCP_ENABLE_WRITE=false`): `propose_event`, `propose_attribute` (proposal-only,
  never write to MISP), and `submit_ioc_with_approval`, `add_sighting_with_approval`,
  `tag_event_with_approval`, `publish_event_with_approval` (each executes only when write mode
  is enabled, the configured role permits the action, and approval is satisfied — via an
  explicit `approved=true` argument when `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`). Every call,
  including blocked and pending-approval outcomes, is audited.
- Added a dedicated `publish` policy action requiring `curator`/`admin` role, always high-risk
  and approval-gated.
- Added narrow MISP write methods (`add_attribute`, `add_sighting`, `tag_event`,
  `publish_event`) to `misp/client.py`. There is no generic write/request proxy.

### Changed

- Stabilized analyst-oriented report outputs around deterministic JSON and Markdown schemas.
- Improved IOC investigation with scoring, verdicts, related IOC extraction, tag-derived
  context, and recommended actions.
- Tool count increased from 13 to 19 with the addition of the Phase 8 controlled write tools.

### Security

- Kept the MCP server read-only by default; write tools require explicit opt-in via
  `AGENTIC_MISP_MCP_ENABLE_WRITE=true` plus a role/approval-satisfying request.
- No raw MISP API proxy or generic user/organisation/server/settings-style admin tools are
  implemented.
- MISP API key is loaded only from environment variables.
- TLS verification is enabled by default.
- Tool calls are audited without logging secrets, including policy decision fields and
  sanitized approval proposals for write tools.

### Known limitations

- Tested with mocked MISP responses only.
- Live MISP compatibility testing is pending.
- Warninglist endpoint behavior may vary by MISP version.
- Galaxy/Object parsing is currently tag-derived and does not fully parse nested MISP
  Galaxy/Object structures.
- Approval decisions are enforced per-call via the `approved` argument and are not persisted
  across process restarts.
