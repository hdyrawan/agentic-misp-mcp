# Changelog

All notable changes to this project will be documented in this file.

This project is in **early development**. It has been tested with mocked MISP responses only;
live MISP compatibility testing is still pending.

## Unreleased

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
- Confirmed packaging metadata, Python 3.11+ requirement, Apache-2.0 license metadata, CLI script,
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
- Added narrow MISP write methods (`create_event`, `add_attribute`, `add_sighting`, `tag_event`,
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
