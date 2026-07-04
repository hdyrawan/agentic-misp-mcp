# agentic-misp-mcp

`agentic-misp-mcp` is a workflow-first MCP server for MISP threat intelligence. It exposes
analyst-oriented tools for investigating IOCs, pivoting across related indicators,
summarizing/explaining MISP events, and — behind a policy/approval gate that is disabled by
default — proposing and submitting controlled writes. It is **not** a raw MISP API proxy.

## Project status

- **Early development.** APIs, tool output shapes, and internals may still change.
- Tested with **mocked MISP responses only**. Live MISP compatibility testing is pending.
- Write tools exist but are disabled by default (`AGENTIC_MISP_MCP_ENABLE_WRITE=false`) and are
  policy/approval-gated when enabled. No generic admin tools or raw API proxy are implemented.
- Not yet recommended for production use.
- CI runs lint, format checks, and the mocked test suite on Python 3.11 and 3.12.

## Scope

- Python 3.11+
- FastMCP
- httpx
- pydantic-settings
- JSONL audit logging for every MCP tool call, including policy decisions
- Docker support
- Read-only by default; controlled write requires explicit configuration
- `MISP_API_KEY` is read only from environment variables — never accepted as a tool argument
- TLS verification (`MISP_VERIFY_TLS`) is enabled by default

### MCP tools

19 analyst-oriented tools are currently exposed.

13 read-only tools:

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

6 controlled write tools (Phase 8), disabled by default and policy/approval-gated:

- `propose_event(...)` — builds an event creation proposal; never writes to MISP
- `propose_attribute(...)` — builds an attribute creation proposal; never writes to MISP
- `submit_ioc_with_approval(..., approved: bool = False)`
- `add_sighting_with_approval(..., approved: bool = False)`
- `tag_event_with_approval(event_id: int, tag: str, approved: bool = False)`
- `publish_event_with_approval(event_id: int, approved: bool = False)` — requires `curator`/`admin` role

See [`docs/security.md`](docs/security.md) for the full write-behavior contract (blocked /
pending_approval / executed).

## Non-goals

This project does not implement raw MISP API proxying, shell execution, unrestricted filesystem
access, or generic user/organisation/server/settings-style admin tools. Event/attribute
creation, sighting submission, tagging, and publishing exist only as the six narrow, disabled-
by-default, policy/approval-gated tools listed above — never as a general write API.

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
- `AGENTIC_MISP_MCP_ROLE=read_only`
- `AGENTIC_MISP_MCP_ENABLE_WRITE=false`
- `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`

## CLI

```bash
agentic-misp-mcp --help
agentic-misp-mcp --version
agentic-misp-mcp config-check
agentic-misp-mcp --transport stdio
agentic-misp-mcp --transport http --host 0.0.0.0 --port 8000
agentic-misp-mcp openapi-inventory --input <misp-openapi.json> --output docs/openapi-inventory.md
```

`config-check` validates environment configuration without connecting to MISP and never prints
`MISP_API_KEY`. `--transport http` is experimental and depends on the installed FastMCP runtime;
stdio is the primary supported transport. `openapi-inventory` classifies a MISP OpenAPI spec
(JSON only) into a read/write/admin/sync/dangerous risk inventory for internal planning — it
does not expose any MISP API endpoint as an MCP tool or call MISP; see
[`docs/openapi-inventory.md`](docs/openapi-inventory.md) for a generated sample.

## Development

```bash
uv run --extra dev ruff check .
uv run --extra dev ruff format --check .
uv run --extra dev pytest -q
```

Equivalent Makefile targets are available:

```bash
make lint
make format-check
make test
make check
```

The test suite uses mocked MISP responses only. Do not point tests at a live MISP instance, and
do not add tests that require live credentials or network access to MISP.

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
commit it. The Dockerfile installs the package into the image and runs the CLI as a non-root
runtime user; pass `MISP_URL` and `MISP_API_KEY` only at container run time.

## CI

GitHub Actions configuration lives in `.github/workflows/ci.yml` and runs the same quality gate
expected before merging changes:

```bash
uv run --extra dev ruff check .
uv run --extra dev ruff format --check .
uv run --extra dev pytest -q
```

CI does not connect to MISP and must not be configured with real MISP credentials.
