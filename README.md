# agentic-misp-mcp

`agentic-misp-mcp` is a read-only, workflow-first MCP server for MISP threat intelligence. It
exposes analyst-oriented tools for investigating IOCs, pivoting across related indicators, and
summarizing/explaining MISP events — it is **not** a raw MISP API proxy.

## Project status

- **Early development.** APIs, tool output shapes, and internals may still change.
- Tested with **mocked MISP responses only**. Live MISP compatibility testing is pending.
- No write/admin tools are implemented, and none are currently planned for this stage.
- Not yet recommended for production use.

## Scope

- Python 3.11+
- FastMCP
- httpx
- pydantic-settings
- JSONL audit logging for every MCP tool call
- Docker support
- Read-only by default
- `MISP_API_KEY` is read only from environment variables — never accepted as a tool argument
- TLS verification (`MISP_VERIFY_TLS`) is enabled by default

### MCP tools

13 analyst-oriented tools are currently exposed:

- `search_ioc(value: str, limit: int = 20)`
- `investigate_ioc(value: str, limit: int = 20)`
- `summarize_event(event_id: int)`
- `check_warninglists(value: str)`
- `generate_ioc_report(value: str)`
- `pivot_ioc(value: str, limit: int = 20)`
- `find_related_iocs(value: str, limit: int = 20)`
- `extract_event_iocs(event_id: int, limit: int = 100)`
- `explain_event_context(event_id: int)`
- `find_events_by_tag(tag: str, limit: int = 20)`
- `generate_event_report(event_id: int)`
- `generate_markdown_ioc_report(value: str)`
- `generate_markdown_event_report(event_id: int)`

## Non-goals

This project does not implement event creation, attribute creation, sighting submission,
tagging, publishing, raw MISP API proxying, shell execution, write/admin tools, or unrestricted
filesystem access.

## Configuration

Set configuration with environment variables. See `.env.example` and `docs/configuration.md`.

Required:

- `MISP_URL`
- `MISP_API_KEY`

Safe defaults:

- `MISP_VERIFY_TLS=true`
- `MISP_TIMEOUT_SECONDS=30`
- `MISP_DEFAULT_LIMIT=20`
- `MISP_MAX_LIMIT=100`
- `MISP_EVENT_ATTRIBUTE_LIMIT=50`
- `MISP_RELATED_EVENT_LIMIT=5`
- `AGENTIC_MISP_MCP_AUDIT_LOG_PATH=./logs/audit.jsonl`
- `AGENTIC_MISP_MCP_LOG_LEVEL=INFO`

## CLI

```bash
agentic-misp-mcp --help
agentic-misp-mcp --version
agentic-misp-mcp config-check
agentic-misp-mcp --transport stdio
agentic-misp-mcp --transport http --host 0.0.0.0 --port 8000
```

`config-check` validates environment configuration without connecting to MISP and never prints
`MISP_API_KEY`. `--transport http` is experimental and depends on the installed FastMCP runtime;
stdio is the primary supported transport.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest
```

## Docker

```bash
docker build -t agentic-misp-mcp:local .
docker run --rm --env-file .env -v "$PWD/logs:/app/logs" agentic-misp-mcp:local config-check
docker run --rm --env-file .env agentic-misp-mcp:local --transport stdio
```

Docker Compose example:

```bash
cp .env.example .env
# edit .env with MISP_URL=https://misp.example.local and MISP_API_KEY=your_misp_api_key_here
docker compose -f docker-compose.example.yml run --rm agentic-misp-mcp config-check
docker compose -f docker-compose.example.yml run --rm agentic-misp-mcp
```

Do not bake MISP credentials into the image. Use `.env` only as a runtime env file and do not
commit it.
