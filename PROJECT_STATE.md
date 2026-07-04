# PROJECT_STATE

Project: agentic-misp-mcp

Current status:
- Current `main` contains the `v0.2.0-beta.1` production-write beta candidate: opt-in
  `AGENTIC_MISP_MCP_APPROVAL_MODE=production` adds SQLite approval records, CLI-only
  approve/reject, one-time redemption, exact operation hashes, TTL expiry, replay/payload-swap
  blocking, publish kill switch, and type/category/tag guardrails for the four existing
  write-executing tools only. Default lab mode remains backward compatible; `approval_token` is
  lab/shared-secret hardening only, while production requires an operator-approved
  `approval_request_id` and consumes it before the MISP write attempt. This candidate is suitable
  for isolated pilot validation only; it is not GA production-ready.
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

Current tests: 166 passed before this documentation hardening pass; re-run the quality gate before tagging.
Current MCP tool count: 19.
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
  Phase 10.2 above).
- Production deployment: **not yet validated**. See `docs/production-readiness.md` for scope,
  requirements, and acceptance criteria.
- Not production-ready: lab-validated, not production-certified.

Next steps:
- Complete the `v0.2.0-beta.1` live beta validation checklist in
  `docs/live-beta-validation-v0.2.0-beta.1.md`, including read-only edge cases and production
  approval-mode replay/hash-mismatch/wrong-tool/publish/allowlist/audit checks.
- Broader MISP version compatibility testing beyond `2.5.42`.
