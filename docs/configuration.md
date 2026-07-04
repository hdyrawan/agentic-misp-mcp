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
```

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
