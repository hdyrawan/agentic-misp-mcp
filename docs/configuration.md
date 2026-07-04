# Configuration

`agentic-misp-mcp` is configured entirely through environment variables in v0.1.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `MISP_URL` | Yes | none | Base URL for the MISP instance. |
| `MISP_API_KEY` | Yes | none | MISP automation/API key. Never pass this as a tool argument. |
| `MISP_VERIFY_TLS` | No | `true` | Verify TLS certificates. Keep enabled in production. |
| `MISP_TIMEOUT_SECONDS` | No | `30` | HTTP timeout for MISP calls. |
| `MISP_DEFAULT_LIMIT` | No | `20` | Default search result limit. |
| `MISP_MAX_LIMIT` | No | `100` | Maximum accepted search result limit. |
| `MISP_EVENT_ATTRIBUTE_LIMIT` | No | `50` | Maximum event attributes included in summaries/investigations. |
| `MISP_RELATED_EVENT_LIMIT` | No | `5` | Maximum related events expanded by investigation workflows. |
| `AGENTIC_MISP_MCP_AUDIT_LOG_PATH` | No | `./logs/audit.jsonl` | JSONL audit log path. |
| `AGENTIC_MISP_MCP_LOG_LEVEL` | No | `INFO` | Application log level. |

## TLS

TLS verification is enabled by default. If your MISP uses a private CA, prefer installing or mounting the CA bundle instead of disabling verification. `MISP_VERIFY_TLS=false` should be reserved for local development and test environments.

## Secrets

Do not commit `.env` files or API keys. The Docker image does not contain secrets; pass them at runtime with environment variables or an env file.
