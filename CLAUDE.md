# Claude Code Instructions

This project is `agentic-misp-mcp`, an agentic MCP server for MISP threat intelligence workflows.

Always read:
- `goal.md`
- `docs/handoff/phase-2-claude-code.md`

Current task:
Implement Phase 2 — Agentic Investigation Engine.

Do not re-plan the entire project. Continue from the existing v0.1 implementation.

Scope:
- Improve `investigate_ioc()`.
- Improve `generate_ioc_report()` to use the new investigation fields.
- Add deterministic scoring, verdict calculation, related IOC extraction, context extraction, and recommendations.
- Add mocked tests.
- Keep the existing five MCP tools unchanged.
- Do not add new MCP tools.
- Do not add write/admin/raw API proxy functionality.
- Do not test against live MISP.
- Do not test Hermes integration.
- Do not run Docker validation in this phase.

Required checks:
- `ruff check .`
- `ruff format --check .`
- `pytest`
