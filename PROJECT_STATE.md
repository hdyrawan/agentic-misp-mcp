# PROJECT_STATE

Project: agentic-misp-mcp

Current status:
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
- Phase 7 complete: policy and approval foundation (`policy/engine.py`, `policy/approvals.py`,
  `policy/models.py`), plus `AGENTIC_MISP_MCP_ROLE` / `AGENTIC_MISP_MCP_ENABLE_WRITE` /
  `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` settings. Read-only tool boundary unchanged (13 tools).
- Phase 8 complete: controlled write workflows. Added exactly six new MCP tools
  (`propose_event`, `propose_attribute`, `submit_ioc_with_approval`,
  `add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval`),
  wired into the Phase 7 `PolicyEngine`/`ApprovalRequest` foundation. Added a `publish` policy
  action (curator/admin only). Added narrow MISP write methods (`create_event`,
  `add_attribute`, `add_sighting`, `tag_event`, `publish_event`) to `misp/client.py` — no
  generic write/request proxy. Writes are disabled by default
  (`AGENTIC_MISP_MCP_ENABLE_WRITE=false`), and even when enabled, every write tool call
  resolves to `blocked`, `pending_approval`, or `executed` — never a silent write.
- Phase 9 complete: production hardening. Added GitHub Actions CI for Python 3.11/3.12,
  Makefile quality targets, top-level `SECURITY.md`, Docker/.dockerignore hygiene, production
  hardening tests, and documentation updates for CI, early-development status, HTTP transport
  warnings, runtime-only secrets, and Phase 8 policy environment variables. Tool behavior and
  MCP tool count remain unchanged.

Current tests: 124 passed.
Current MCP tool count: 19.

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
- No live MISP testing yet
- No Hermes runtime testing yet
- Mocked tests only unless explicitly requested

Next phases:
- Phase 10 release
