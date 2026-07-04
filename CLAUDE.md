# Claude Code Instructions

This project is `agentic-misp-mcp`, a read-only, workflow-first MCP server for MISP threat
intelligence. See `goal.md` for the project's guiding principles and `README.md` for current
scope and status.

## Working on this project

- This is an early-stage, read-only project. Do not implement event creation, attribute
  creation, sighting submission, tagging, publishing, raw MISP API proxying, shell execution,
  or unrestricted filesystem access.
- Do not add new MCP tools without discussing scope first. All MCP tools must be registered
  through `src/agentic_misp_mcp/tools/registry.py` and go through the shared audit wrapper in
  `src/agentic_misp_mcp/audit.py`.
- `MISP_API_KEY` must always come from environment variables. Never accept it as a tool
  argument, log it, or return it in errors or audit records.
- Keep TLS verification enabled by default.
- Tests use mocked MISP responses only. Do not add tests that call a live MISP instance.

## Required checks

Before considering a change complete, run:

```bash
ruff check .
ruff format --check .
pytest -q
```

## Docs to keep in sync

If you change tool behavior, scope, or security posture, update the relevant docs:

- `README.md`
- `docs/configuration.md`
- `docs/security.md`
- `CHANGELOG.md`
