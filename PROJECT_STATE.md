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

Current tests: 83 passed.
Current MCP tool count remains 13.

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

Hard rules:
- Read-only until Phase 8
- No raw MISP API proxy
- No write/admin tools
- No live MISP testing yet
- No Hermes runtime testing yet
- Mocked tests only unless explicitly requested

Next phases:
- Phase 7 policy/approval engine
- Phase 8 controlled write workflows
- Phase 9 production hardening
- Phase 10 release
