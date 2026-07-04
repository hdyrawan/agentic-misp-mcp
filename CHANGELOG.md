# Changelog

All notable changes to this project will be documented in this file.

This project is in **early development**. It has been tested with mocked MISP responses only;
live MISP compatibility testing is still pending.

## Unreleased

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
