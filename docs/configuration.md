# Configuration

`agentic-misp-mcp` is configured entirely through environment variables. Run
`agentic-misp-mcp config-check` before starting the MCP server to validate local runtime
configuration without connecting to MISP.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MISP_URL` | Yes | none | Base URL for the MISP instance, for example `https://misp.example.local`. |
| `MISP_API_KEY` | Yes | none | MISP automation/API key. Never pass this as a tool argument. |
| `MISP_VERIFY_TLS` | No | `true` | Verify TLS certificates. Keep enabled in production. |
| `MISP_TIMEOUT_SECONDS` | No | `30` | HTTP timeout for MISP calls. Must be greater than `0` and no more than `300`. |
| `MISP_DEFAULT_LIMIT` | No | `20` | Default search result limit. Must be at least `1` and no greater than `MISP_MAX_LIMIT`. |
| `MISP_MAX_LIMIT` | No | `100` | Maximum accepted search result limit. Must be between `1` and `1000`. |
| `MISP_EVENT_ATTRIBUTE_LIMIT` | No | `50` | Maximum event attributes included in summaries/investigations. Must be between `1` and `1000`. |
| `MISP_RELATED_EVENT_LIMIT` | No | `5` | Maximum related events expanded by investigation workflows. Must be between `0` and `100`. |
| `AGENTIC_MISP_MCP_AUDIT_LOG_PATH` | No | `./logs/audit.jsonl` | JSONL audit log path. Parent directory must be writable or creatable. |
| `AGENTIC_MISP_MCP_LOG_LEVEL` | No | `INFO` | Application log level. |
| `AGENTIC_MISP_MCP_ROLE` | No | `read_only` | Policy role: `read_only`, `analyst_write`, `curator`, or `admin`. `analyst_write` (or higher) is required for `submit_ioc_with_approval`, `add_sighting_with_approval`, and `tag_event_with_approval`; `curator`/`admin` is required for `publish_event_with_approval`. |
| `AGENTIC_MISP_MCP_ENABLE_WRITE` | No | `false` | Write-mode gate. Keep `false` to block all six controlled write tools regardless of role. |
| `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` | No | `true` | Require an explicit `approved=true` argument for controlled write/publish actions when enabled and role-allowed. |

## Example `.env`

```env
MISP_URL=https://misp.example.local
MISP_API_KEY=your_misp_api_key_here
MISP_VERIFY_TLS=true
MISP_TIMEOUT_SECONDS=30
MISP_DEFAULT_LIMIT=20
MISP_MAX_LIMIT=100
MISP_EVENT_ATTRIBUTE_LIMIT=50
MISP_RELATED_EVENT_LIMIT=5
AGENTIC_MISP_MCP_AUDIT_LOG_PATH=./logs/audit.jsonl
AGENTIC_MISP_MCP_LOG_LEVEL=INFO
AGENTIC_MISP_MCP_ROLE=read_only
AGENTIC_MISP_MCP_ENABLE_WRITE=false
AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true
```

## Policy and controlled write behavior

The original 13 MCP tools are classified as `read` and are always allowed under the default
`read_only` role. Six additional Phase 8 write tools (`propose_event`, `propose_attribute`,
`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`,
`publish_event_with_approval`) are blocked unless `AGENTIC_MISP_MCP_ENABLE_WRITE=true` and the
configured role permits the action. When approval is required (the default), the four
`_with_approval` tools return a `pending_approval` proposal until called again with
`approved=true`; only that approved call invokes a real (mocked-in-tests) MISP write method.
`propose_event`/`propose_attribute` never call MISP regardless of approval. Approval decisions
are modeled and fully audited; there is no persistent approval storage across process restarts.

## Validate configuration

```bash
agentic-misp-mcp config-check
```

The command checks required values, type parsing, safe limit bounds, and audit-log path
writability. It does not connect to MISP and never prints the API key.

## Local stdio run

```bash
export MISP_URL=https://misp.example.local
export MISP_API_KEY=your_misp_api_key_here
agentic-misp-mcp config-check
agentic-misp-mcp --transport stdio
```

## Experimental HTTP run

HTTP mode is intentionally minimal and depends on the installed FastMCP runtime supporting the
straightforward HTTP transport arguments.

```bash
agentic-misp-mcp --transport http --host 0.0.0.0 --port 8000
```

Use stdio if your MCP client or FastMCP version does not support HTTP mode.

## Docker run

```bash
docker build -t agentic-misp-mcp:local .
docker run --rm --env-file .env -v "$PWD/logs:/app/logs" agentic-misp-mcp:local config-check
docker run --rm -i --env-file .env -v "$PWD/logs:/app/logs" agentic-misp-mcp:local --transport stdio
```

## Docker Compose

```bash
cp .env.example .env
# edit .env with placeholder-safe values for your environment
docker compose -f docker-compose.example.yml run --rm agentic-misp-mcp config-check
docker compose -f docker-compose.example.yml run --rm agentic-misp-mcp
```

## Generic Claude Desktop MCP config

Use placeholders only and store the real API key locally on the machine running Claude Desktop.

```json
{
  "mcpServers": {
    "agentic-misp-mcp": {
      "command": "agentic-misp-mcp",
      "args": ["--transport", "stdio"],
      "env": {
        "MISP_URL": "https://misp.example.local",
        "MISP_API_KEY": "your_misp_api_key_here",
        "MISP_VERIFY_TLS": "true"
      }
    }
  }
}
```

## Generic Hermes MCP config

A generic stdio MCP server entry should point to the installed CLI and provide environment
variables at runtime:

```yaml
mcp_servers:
  agentic-misp-mcp:
    command: agentic-misp-mcp
    args: ["--transport", "stdio"]
    env:
      MISP_URL: https://misp.example.local
      MISP_API_KEY: your_misp_api_key_here
      MISP_VERIFY_TLS: "true"
```

## TLS

TLS verification is enabled by default. If your MISP uses a private CA, prefer installing or
mounting the CA bundle instead of disabling verification. `MISP_VERIFY_TLS=false` should be
reserved for local development and test environments.

## Secrets

Do not commit `.env` files or API keys. The Docker image does not contain secrets; pass them at
runtime with environment variables or an env file.
