# agentic-misp-mcp

`agentic-misp-mcp` is an agentic MCP server for MISP. It exposes analyst-oriented threat intelligence workflows, not raw MISP API endpoints.

## v0.1 scope

- Python 3.11+
- FastMCP
- httpx
- pydantic-settings
- JSONL audit logging
- Docker support
- Read-only by default
- Five analyst workflow tools:
  - `search_ioc(value: str, limit: int = 20)`
  - `investigate_ioc(value: str, limit: int = 20)`
  - `summarize_event(event_id: int)`
  - `check_warninglists(value: str)`
  - `generate_ioc_report(value: str)`

## Non-goals for v0.1

v0.1 does not implement event creation, attribute creation, sighting submission, tagging, publishing, raw MISP API proxying, shell execution, write/admin tools, or unrestricted filesystem access.

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
agentic-misp-mcp --transport stdio
```

`--transport http` is accepted as a v0.1 placeholder when supported by the installed FastMCP runtime, but stdio is the primary supported v0.1 transport.

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
docker run --rm --env-file .env agentic-misp-mcp:local --transport stdio
```

Do not bake MISP credentials into the image.
