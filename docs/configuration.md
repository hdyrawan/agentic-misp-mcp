# Configuration

`agentic-misp-mcp` is configured entirely through environment variables. MISP connection
variables use the `MISP_*` prefix; server policy, audit, transport, and hardening variables use
the `AGENTIC_MISP_MCP_*` prefix. Run
`agentic-misp-mcp config-check` before starting the MCP server to validate local runtime
configuration without connecting to MISP. The project is distributed under the MIT License.

For a general-purpose starting point, copy `.env.example`. For a production-oriented deployment,
start from [`.env.production.example`](../.env.production.example) instead, and see
[`docs/production-readiness.md`](production-readiness.md) for the required runtime configuration,
TLS, and secret-handling requirements before deploying against a real MISP instance.

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
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | No | `false` | Permit experimental HTTP transport to bind a non-loopback host (e.g. `0.0.0.0` or `::`). Leave false unless the server is behind an authenticated TLS-terminating gateway. |
| `AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS` | No | `30` | Intel freshness label threshold: newest signal at or below this many days is `fresh`. Must be less than the aging threshold. |
| `AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS` | No | `90` | Intel freshness label threshold: `aging` upper bound. Must sit between the fresh and stale thresholds. |
| `AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS` | No | `365` | Intel freshness label threshold: `stale` upper bound; older signals are `expired`. |
| `AGENTIC_MISP_MCP_AGE_WEIGHTING` | No | `true` | Apply age-aware weighting to IOC scoring. `false` reproduces pre-v0.3.0 scoring exactly; the `freshness` response block is emitted either way. |
| `AGENTIC_MISP_MCP_AGE_WEIGHTS` | No | `1.0,0.75,0.4,0.15` | Score multipliers for fresh/aging/stale/expired intel. Four comma-separated values, each between 0 and 1. Penalties (warninglist/benign tags) are never discounted. |
| `AGENTIC_MISP_MCP_FEED_FRESH_DAYS` | No | `7` | Feed health threshold: fetch/cache ages at or below this are considered fresh. Must be at least `1` and less than `AGENTIC_MISP_MCP_FEED_STALE_DAYS`. |
| `AGENTIC_MISP_MCP_FEED_STALE_DAYS` | No | `30` | Feed health threshold: fetch/cache ages above this are stale/cache-stale. Must be greater than `AGENTIC_MISP_MCP_FEED_FRESH_DAYS`. |

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
AGENTIC_MISP_MCP_FEED_FRESH_DAYS=7
AGENTIC_MISP_MCP_FEED_STALE_DAYS=30
```

## Policy and controlled write behavior

The read-only MCP tools are classified as `read` and are allowed under the default
`read_only` role when they return bounded safe metadata. Six Phase 8 write tools (`propose_event`, `propose_attribute`,
`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`,
`publish_event_with_approval`) are blocked unless `AGENTIC_MISP_MCP_ENABLE_WRITE=true` and the
configured role permits the action. When approval is required (the default), the four
`_with_approval` tools return a `pending_approval` proposal until called again with
`approved=true`; only that approved call invokes a real (mocked-in-tests) MISP write method.
When `AGENTIC_MISP_MCP_APPROVAL_TOKEN` is set, a role-allowed approved call must also include a
matching `approval_token`; missing or incorrect tokens return `blocked`. If the environment token
is unset, the older `approved=true` behavior is preserved for backward compatibility.
`propose_event`/`propose_attribute` never call MISP regardless of approval. Approval decisions
are modeled and fully audited. In the default `lab` approval mode, approval is an in-process
programmatic gate for development and validation. In `production` approval mode, approval requests
for the four `_with_approval` write tools are persisted in the SQLite store configured by
`AGENTIC_MISP_MCP_APPROVAL_STORE_PATH`; approved records are TTL-bound, one-time-use, and bound to
the exact canonical operation hash across process restarts.
`propose_event`/`propose_attribute` also validate the proposed payload before building it
(`v0.2.0-rc.1`): required fields, `distribution`/`threat_level_id`/`analysis` ranges, and a
known-vocabulary attribute type/category allowlist. A malformed or unsupported payload returns
`status: "invalid"` with a `validation_errors` list instead of a proposal; see
[`docs/security.md`](security.md). The same validation also runs on the actual write path:
`submit_ioc_with_approval` reuses the attribute payload validation, and
`add_sighting_with_approval` validates the sighting payload, so an invalid payload returns
`status: "invalid"` before any approval record is created and MISP is never contacted.

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

## Operational-readiness doctor (v0.2.0-beta.2+)

```bash
agentic-misp-mcp config doctor
```

`config doctor` goes beyond `config-check`'s basic validation and checks operational-readiness
combinations: whether write mode is paired with production approval mode, whether publish is
paired with a curator/admin role, approval-store and audit-log writability and permission safety,
production write allowlist coverage, approval TTL length, temporary-directory paths, and leftover
lab approval tokens in production mode. Output is a line per check prefixed `PASS`, `WARN`, or
`FAIL`; secrets (`MISP_API_KEY`, `AGENTIC_MISP_MCP_APPROVAL_TOKEN`) are never printed, only their
presence/absence. It does not connect to MISP. The command exits nonzero if any check is `FAIL`.
Run it alongside `config-check` in a deployment pipeline or init container before starting the
server. See [`docs/production-readiness.md`](production-readiness.md) for the full checklist.

## Approval store maintenance (v0.2.0-beta.2+)

```bash
agentic-misp-mcp approvals prune --older-than 30d [--vacuum]
```

Deletes old terminal (`used`, `rejected`, `expired`) approval records past the given age
threshold. `--older-than` accepts a duration with an explicit `s`/`h`/`d` suffix (for example
`3600s`, `24h`, `7d`, `30d`); an invalid duration exits nonzero without touching the store.
`pending` and `approved` records are never deleted regardless of age. Pass `--vacuum` to run
SQLite `VACUUM` afterward and reclaim disk space. This is an operator-CLI-only maintenance command
and is not exposed through any MCP tool — the LLM/agent cannot prune or vacuum the approval store.

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

Do not expose HTTP mode directly to untrusted networks. Binding HTTP to any non-loopback host (`0.0.0.0`, `::`, or a LAN address) is blocked by
default because this mode has no built-in auth/TLS. Only set
`AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true` when the listener is behind an authenticated,
TLS-terminating gateway and audit logs are monitored closely.

## Docker run

```bash
docker build -t agentic-misp-mcp:local .
docker run --rm --env-file .env \
  -v /path/to/agentic-misp-mcp/logs:/app/logs \
  agentic-misp-mcp:local config-check
docker run --rm -i --env-file .env \
  -v /path/to/agentic-misp-mcp/logs:/app/logs \
  agentic-misp-mcp:local --transport stdio
```

For production-write Docker deployments, persist both the audit log directory and the SQLite
approval store directory. Set `AGENTIC_MISP_MCP_AUDIT_LOG_PATH=/app/logs/audit.jsonl` and
`AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=/app/approvals/approvals.sqlite3`, then mount host-owned
directories with permissions that are not group/world writable:

```bash
docker run --rm -i --env-file /path/to/agentic-misp-mcp/.env.production-write \
  -v /path/to/agentic-misp-mcp/logs:/app/logs \
  -v /path/to/agentic-misp-mcp/approvals:/app/approvals \
  agentic-misp-mcp:local --transport stdio
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


## Production approval and write guardrail settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENTIC_MISP_MCP_APPROVAL_MODE` | `lab` | `lab` preserves the legacy approval flow; `production` requires persisted approval request redemption. |
| `AGENTIC_MISP_MCP_APPROVAL_STORE_PATH` | `./approvals.sqlite3` | SQLite approval store for production mode. Parent directory and DB must not be group/world writable. |
| `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS` | `900` | Approval record lifetime in seconds. |
| `AGENTIC_MISP_MCP_ENABLE_PUBLISH` | `false` | Dedicated publish kill switch; publish also requires curator/admin role and approval. |
| `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES` | unset | Optional comma-separated allowlist for `submit_ioc_with_approval` attribute types. |
| `AGENTIC_MISP_MCP_ALLOWED_TAGS` | unset | Optional comma-separated allowlist for `tag_event_with_approval`; entries ending in `*` act as prefixes. |

See `docs/production-write.md` and `.env.production-write.example` for a complete production-write beta template.
