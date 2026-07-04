# Claude Code Handoff — Phase 2 Agentic Investigation Engine

## 1. Current project goal

`agentic-misp-mcp` is an agentic MCP server for MISP threat intelligence workflows. It must expose analyst-oriented, read-only workflows through MCP tools instead of raw MISP API endpoints.

Core goal from `goal.md`:

- Help analysts investigate IOCs.
- Pivot across related indicators.
- Summarize MISP events.
- Check warninglists.
- Generate threat intelligence reports.
- Later, controlled write actions may be added behind policy, approval, and audit logging, but not in v0.1/Phase 2.

## 2. Current implementation status

The repository currently contains a v0.1 read-only foundation:

- Python package using `src/agentic_misp_mcp` layout.
- FastMCP server factory and CLI entrypoint.
- Environment-based settings with `pydantic-settings`.
- Async MISP client using `httpx`.
- JSONL audit logging for every MCP tool call.
- Dockerfile and docker-compose example.
- Security and configuration docs.
- Five MCP tools only:
  - `search_ioc(value: str, limit: int = 20)`
  - `investigate_ioc(value: str, limit: int = 20)`
  - `summarize_event(event_id: int)`
  - `check_warninglists(value: str)`
  - `generate_ioc_report(value: str)`

Important current modules:

- `src/agentic_misp_mcp/settings.py` — environment configuration.
- `src/agentic_misp_mcp/audit.py` — JSONL audit wrapper.
- `src/agentic_misp_mcp/misp/client.py` — small read-only MISP client.
- `src/agentic_misp_mcp/misp/warninglists.py` — isolated warninglist response parsing.
- `src/agentic_misp_mcp/tools/registry.py` — the only place MCP tools are registered.
- `src/agentic_misp_mcp/workflows/investigate_ioc.py` — current investigation workflow.
- `src/agentic_misp_mcp/workflows/generate_ioc_report.py` — current deterministic report workflow.

## 3. Current file tree

```text
CHANGELOG.md
docker-compose.example.yml
Dockerfile
.dockerignore
docs/configuration.md
docs/security.md
docs/handoff/phase-2-claude-code.md
.env.example
.gitignore
goal.md
LICENSE
pyproject.toml
README.md
CLAUDE.md
src/agentic_misp_mcp/audit.py
src/agentic_misp_mcp/cli.py
src/agentic_misp_mcp/exceptions.py
src/agentic_misp_mcp/__init__.py
src/agentic_misp_mcp/misp/client.py
src/agentic_misp_mcp/misp/__init__.py
src/agentic_misp_mcp/misp/queries.py
src/agentic_misp_mcp/misp/warninglists.py
src/agentic_misp_mcp/models/__init__.py
src/agentic_misp_mcp/models/ioc.py
src/agentic_misp_mcp/models/misp.py
src/agentic_misp_mcp/models/reports.py
src/agentic_misp_mcp/server.py
src/agentic_misp_mcp/settings.py
src/agentic_misp_mcp/tools/__init__.py
src/agentic_misp_mcp/tools/registry.py
src/agentic_misp_mcp/workflows/check_warninglists.py
src/agentic_misp_mcp/workflows/generate_ioc_report.py
src/agentic_misp_mcp/workflows/__init__.py
src/agentic_misp_mcp/workflows/investigate_ioc.py
src/agentic_misp_mcp/workflows/search_ioc.py
src/agentic_misp_mcp/workflows/summarize_event.py
tests/conftest.py
tests/test_audit.py
tests/test_cli.py
tests/test_misp_client.py
tests/test_settings.py
tests/test_tools_contract.py
tests/workflows/test_check_warninglists.py
tests/workflows/test_generate_ioc_report.py
tests/workflows/test_investigate_ioc.py
tests/workflows/test_search_ioc.py
tests/workflows/test_summarize_event.py
```

## 4. Tests already run and results

The v0.1 foundation was previously validated with:

```bash
ruff check .
ruff format --check .
pytest
```

Expected current result before Phase 2 changes:

- Ruff passes.
- Format check passes.
- Pytest passes with the existing mocked test suite.

Docker validation was also previously run for v0.1 foundation, but Docker validation is out of scope for Phase 2.

## 5. Known caveats

- MISP warninglist API behavior varies by MISP version. Keep all warninglist assumptions isolated in `misp/warninglists.py`.
- If warninglist behavior is unavailable or response shape is unknown, return structured `not_available` or error state. Do not pretend the check succeeded.
- Current investigation scoring is basic and should be replaced/enhanced in Phase 2.
- Do not return full raw MISP event JSON. Preserve configured output-size limits.
- Tests must use mocked MISP responses only.

## 6. Exact next phase to implement

Implement Phase 2 — Agentic Investigation Engine.

Focus only on improving the existing read-only investigation/report workflows:

- Improve `investigate_ioc()`.
- Improve `generate_ioc_report()` to use the new investigation fields.
- Add deterministic scoring.
- Add verdict calculation.
- Add related IOC extraction.
- Add context extraction.
- Add deterministic recommendations.
- Add/update mocked tests.

Do not re-plan the whole project.

## 7. Strict scope boundaries

Keep the existing five MCP tools unchanged:

- `search_ioc`
- `investigate_ioc`
- `summarize_event`
- `check_warninglists`
- `generate_ioc_report`

Do not add new MCP tools.
Do not rename existing MCP tools.
Do not change CLI scope except if tests require tiny compatibility fixes.
Do not test against live MISP.
Do not test Hermes integration.
Do not run Docker validation in Phase 2.

## 8. Security constraints

Do not implement:

- event creation
- attribute creation
- sighting submission
- tagging
- publishing
- raw MISP API proxying
- write/admin tools
- shell execution
- unrestricted filesystem access

Keep these guarantees:

- MISP API key comes only from environment variables.
- TLS verification remains enabled by default.
- Every MCP tool call remains audited through `tools/registry.py` and `audit.py`.
- Outputs remain bounded and do not expose full raw MISP event JSON.

## 9. Exact commands Claude Code should run

From repo root:

```bash
python3.11 -m venv .venv311
source .venv311/bin/activate
pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
```

If `python3.11 -m venv` fails because `ensurepip` is unavailable, use the project’s available Python environment but still report the Python version and exact command used.

Do not run Docker validation for Phase 2.

## 10. Expected final output from Claude Code

After implementing Phase 2, report:

1. Final file tree.
2. Changed files summary.
3. Commands run.
4. Test results.
5. Assumptions and TODOs.

The final implementation should preserve v0.1 read-only scope and keep the MCP tool list exactly unchanged.
