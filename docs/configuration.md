# Configuration

`agentic-misp-mcp` is configured entirely through environment variables. MISP connection
variables use the `MISP_*` prefix; server policy, audit, transport, and hardening variables use
the `AGENTIC_MISP_MCP_*` prefix. Run
`agentic-misp-mcp config-check` before starting the MCP server to validate local runtime
configuration without connecting to MISP. The project is distributed under the MIT License.

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
| `AGENTIC_MISP_MCP_APPROVAL_TOKEN` | No | unset | Optional approval-token enforcement. When set and approval is required, `approved=true` calls must also include the matching `approval_token`. The token is redacted from audit logs and config-check output. |
| `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` | No | `5242880` | Maximum MISP HTTP response body size. Checked before JSON parsing using both `Content-Length` and actual bytes read. |
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | No | `false` | Permit experimental HTTP transport to bind `0.0.0.0`. Leave false unless the server is behind an authenticated TLS-terminating gateway. |

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
AGENTIC_MISP_MCP_APPROVAL_TOKEN=
AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES=5242880
AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=false
```

## Policy and controlled write behavior

The original 13 MCP tools are classified as `read` and are always allowed under the default
`read_only` role. Six additional Phase 8 write tools (`propose_event`, `propose_attribute`,
`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`,
`publish_event_with_approval`) are blocked unless `AGENTIC_MISP_MCP_ENABLE_WRITE=true` and the
configured role permits the action. When approval is required (the default), the four
`_with_approval` tools return a `pending_approval` proposal until called again with
`approved=true`; only that approved call invokes a real (mocked-in-tests) MISP write method.
When `AGENTIC_MISP_MCP_APPROVAL_TOKEN` is set, a role-allowed approved call must also include a
matching `approval_token`; missing or incorrect tokens return `blocked`. If the environment token
is unset, the older `approved=true` behavior is preserved for backward compatibility.
`propose_event`/`propose_attribute` never call MISP regardless of approval. Approval decisions
are modeled and fully audited; there is no persistent approval storage across process restarts.

Production-oriented runtime guidance:

- Keep `AGENTIC_MISP_MCP_ROLE=read_only` unless a deployment explicitly needs controlled writes.
- Keep `AGENTIC_MISP_MCP_ENABLE_WRITE=false` for read-only deployments. Setting it to `true`
  only unlocks the policy engine; role and approval checks still apply.
- Keep `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` for any deployment that enables writes.
- Do not pass approval arguments automatically from an untrusted agent loop. `approved=true` is a
  programmatic gate, not a complete HITL approval mechanism. For autonomous agents, set
  `AGENTIC_MISP_MCP_APPROVAL_TOKEN` and keep the token outside the agent's normal prompt/context.
- `MISP_API_KEY` must remain environment-only and must not be supplied through MCP tool
  arguments, CI variables for tests, committed config, or Docker image layers.

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
agentic-misp-mcp --transport http --host 127.0.0.1 --port 8000
```

Use stdio if your MCP client or FastMCP version does not support HTTP mode.

Do not expose HTTP mode directly to untrusted networks. Binding HTTP to `0.0.0.0` is blocked by
default because this mode has no built-in auth/TLS. Only set
`AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true` when the listener is behind an authenticated,
TLS-terminating gateway and audit logs are monitored closely.

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
