# agentic-misp-mcp

**MISP workflows for agents — investigate, pivot, report, and propose controlled writes without turning your MCP server into a raw API proxy.**

`agentic-misp-mcp` is an early-stage MCP server for security analysts working with MISP threat intelligence. It gives AI agents a small set of analyst-oriented workflows: search an IOC, investigate context, pivot through related indicators, summarize events, generate reports, and prepare tightly controlled write proposals.

It exists because agents should not need unrestricted MISP API access to help with SOC work. Instead of exposing every endpoint, this project exposes opinionated workflows with bounded output, policy checks, and audit logging.

## Status

- Early development; APIs, outputs, and internals may still change.
- Tested with mocked MISP responses only.
- Live MISP compatibility testing is pending.
- Current MCP tool count: **19**.
- Primary transport: **stdio**.
- HTTP transport exists but is experimental.
- License: MIT.

## Safety model

This project is workflow-first, not endpoint-first.

- Read-only by default.
- Controlled write tools exist but are disabled by default: `AGENTIC_MISP_MCP_ENABLE_WRITE=false`.
- Approval is required by default when writes are enabled: `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`.
- `MISP_API_KEY` is loaded only from environment variables.
- No API key, token, password, authorization header, or secret passthrough through MCP tool arguments.
- No raw MISP API proxy.
- No generic user/organisation/server/settings admin tools.
- No shell execution or unrestricted filesystem tools.
- Every MCP tool call is audited with sanitized arguments and policy decision fields.

## Current MCP tools

### Read-only investigation

- `search_ioc(value, limit=20)` — find normalized MISP attribute matches.
- `investigate_ioc(value, limit=20)` — combine matches, warninglists, related events, scoring, and next steps.
- `summarize_event(event_id)` — summarize a MISP event without returning full raw event JSON.
- `check_warninglists(value)` — check an IOC against warninglists when available.

### Pivoting and event intelligence

- `pivot_ioc(value, limit=20)` — pivot from one IOC into useful related context.
- `find_related_iocs(value, limit=20)` — rank related indicators.
- `extract_event_iocs(event_id, limit=100)` — extract supported IOC types from an event.
- `explain_event_context(event_id)` — explain what an event appears to represent.
- `find_events_by_tag(tag, limit=20)` — find events associated with a tag.

### Reporting

- `generate_ioc_report(value)` — deterministic structured IOC report.
- `generate_event_report(event_id)` — deterministic structured event report.
- `generate_markdown_ioc_report(value)` — Markdown IOC report for analyst notes or escalation.
- `generate_markdown_event_report(event_id)` — Markdown event report.

### Controlled write and proposal tools

These six tools are policy-gated. They are blocked unless write mode and role allow the action; write execution also requires explicit approval by default.

- `propose_event(...)` — build an event creation proposal; never writes to MISP.
- `propose_attribute(...)` — build an attribute creation proposal; never writes to MISP.
- `submit_ioc_with_approval(..., approved=False)` — add an attribute only when policy and approval allow.
- `add_sighting_with_approval(..., approved=False)` — add a sighting only when policy and approval allow.
- `tag_event_with_approval(event_id, tag, approved=False)` — tag an event only when policy and approval allow.
- `publish_event_with_approval(event_id, approved=False)` — publish an event only for curator/admin roles and approval.

Write-tool results are explicit: `blocked`, `pending_approval`, or `executed`. There are no silent writes.

## Quick start

### Local install

```bash
python -m pip install -e ".[dev]"
```

Or, if you use `uv` for development:

```bash
uv run --extra dev agentic-misp-mcp --help
```

### Configure `.env`

```bash
cp .env.example .env
# edit .env with your local runtime values
```

Minimum required variables:

```env
MISP_URL=https://misp.example.local
MISP_API_KEY=your_misp_api_key_here
```

Do not commit `.env` or real API keys.

### Validate configuration

```bash
agentic-misp-mcp config-check
```

`config-check` does not connect to MISP and redacts the API key.

### Run over stdio

```bash
agentic-misp-mcp --transport stdio
```

### Docker run

```bash
docker build -t agentic-misp-mcp:local .
docker run --rm \
  -e MISP_URL=https://misp.example.local \
  -e MISP_API_KEY=your_misp_api_key_here \
  agentic-misp-mcp:local config-check

docker run --rm -i --env-file .env -v "$PWD/logs:/app/logs" \
  agentic-misp-mcp:local --transport stdio
```

Do not bake secrets into the image. Pass credentials only at runtime.

## Example agent prompts

- "Investigate this IOC: `1.2.3.4`. Give me verdict, confidence, related events, and next steps."
- "Pivot from this domain and list related IOCs worth hunting: `example.test`."
- "Summarize MISP event `42` for a SOC handoff."
- "Generate a Markdown IOC report for `http://evil.example.test/x`."
- "Propose a MISP event for this phishing cluster, but do not write it yet."
- "Submit this IOC to event `42` with approval after showing the pending approval payload."

## Configuration

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `MISP_URL` | Yes | none | Base URL for MISP, for example `https://misp.example.local`. |
| `MISP_API_KEY` | Yes | none | Runtime-only MISP automation/API key. Never pass as a tool argument. |
| `MISP_VERIFY_TLS` | No | `true` | Keep TLS verification enabled. |
| `MISP_TIMEOUT_SECONDS` | No | `30` | HTTP timeout, > 0 and <= 300. |
| `MISP_DEFAULT_LIMIT` | No | `20` | Default result limit. |
| `MISP_MAX_LIMIT` | No | `100` | Maximum accepted result limit. |
| `MISP_EVENT_ATTRIBUTE_LIMIT` | No | `50` | Attribute cap for event summaries/investigations. |
| `MISP_RELATED_EVENT_LIMIT` | No | `5` | Related event expansion cap. |
| `AGENTIC_MISP_MCP_AUDIT_LOG_PATH` | No | `./logs/audit.jsonl` | JSONL audit log path. |
| `AGENTIC_MISP_MCP_LOG_LEVEL` | No | `INFO` | Application log level. |
| `AGENTIC_MISP_MCP_ROLE` | No | `read_only` | `read_only`, `analyst_write`, `curator`, or `admin`. |
| `AGENTIC_MISP_MCP_ENABLE_WRITE` | No | `false` | Global write-mode gate. |
| `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` | No | `true` | Require explicit `approved=true` for write execution. |

See `docs/configuration.md` for more examples.

## Security notes

- Use stdio by default.
- Treat HTTP transport as experimental. If you enable it, bind only to a trusted interface or place it behind authenticated TLS termination.
- Keep `.env`, audit logs, and API keys out of git.
- Tests use mocked MISP responses only; do not add live-MISP tests without an explicit lab-validation phase.
- See `SECURITY.md` and `docs/security.md` for reporting and deployment guidance.

## Development

```bash
uv run --extra dev ruff check .
uv run --extra dev ruff format --check .
uv run --extra dev pytest -q
```

Equivalent Make targets:

```bash
make lint
make format-check
make test
make check
```

CI runs the same checks on Python 3.11 and 3.12.

## Roadmap

- Live lab validation against a controlled non-production MISP instance.
- Compatibility notes for MISP version differences, especially warninglists and event shapes.
- Release tagging and packaging once the live validation story is documented.
- Additional controlled workflows only when they preserve the no-raw-proxy, policy-gated model.

## Contributing

Contributions are welcome, but keep the project boundary intact: no raw API proxy, no secret passthrough, no unaudited tool path, and no write behavior without policy and approval gates. Start by reading `PROJECT_STATE.md`, `docs/security.md`, and `src/agentic_misp_mcp/tools/registry.py`.
