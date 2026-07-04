# agentic-misp-mcp

**MISP workflows for agents — investigate, pivot, report, and propose controlled writes without turning your MCP server into a raw API proxy.**

`agentic-misp-mcp` is an early-stage MCP server for security analysts working with MISP threat intelligence. It gives AI agents a small set of analyst-oriented workflows: search an IOC, investigate context, pivot through related indicators, summarize events, generate reports, and prepare tightly controlled write proposals.

It exists because agents should not need unrestricted MISP API access to help with SOC work. Instead of exposing every endpoint, this project exposes opinionated workflows with bounded output, policy checks, and audit logging.

## Status

- Early development; APIs, outputs, and internals may still change.
- Mocked test coverage exists for core workflows and policy paths.
- First live read-only lab validation has passed against MISP `2.5.42` using Docker, stdio transport, and MCP Inspector.
- Controlled write validation is still pending and must only be performed against an isolated lab MISP instance.
- Broader MISP version compatibility testing is still pending.
- Not production-ready.
- Current MCP tool count: **19**.
- Primary transport: **stdio**.
- HTTP transport exists but is experimental.
- Requires Python 3.11+.
- License: MIT.

## Live lab validation status

The first live validation was performed against a controlled, non-production MISP lab.

| Area | Result | Notes |
| --- | --- | --- |
| MISP version check | Passed | `/servers/getVersion` returned HTTP 200 against MISP `2.5.42`. |
| Docker runtime | Passed | Image built locally and run with runtime-only environment variables. |
| `config-check` | Passed | Configuration validated, API key was redacted, and audit-log path was writable. |
| MCP transport | Passed | MCP Inspector connected over stdio to `docker run --rm -i ... --transport stdio`. |
| `tools/list` | Passed | MCP Inspector listed the exposed MCP tools. |
| `search_ioc` | Passed | Tested with non-matching, IPv4, domain, composite `domain\|ip`, and SHA256 indicators. |
| `investigate_ioc` | Passed | Returned verdict, confidence, related event context, warninglist status, and related IOCs. |
| `summarize_event` | Passed | Summarized a real MISP event without returning unbounded raw event JSON. |
| `generate_ioc_report` | Passed | Generated a deterministic IOC report from live MISP data. |
| `check_warninglists` | Passed | Warninglist checks returned structured results when available. |
| `find_events_by_tag` | Passed | Returned real events for a live tag (`OSINT`), including info, date, threat level, and tags. |
| Audit logging | Passed | Successful calls, validation failures, runtime errors, and blocked write attempts were written to JSONL audit logs. Blocked policy decisions are recorded with `allowed=false`, `success=false`, and `outcome=blocked`. |
| Read-only write blocking | Passed | A write attempt with `approved=true` was blocked in `read_only` mode while write mode was disabled; follow-up search confirmed MISP was not modified. |
| Error path: unreachable `MISP_URL` | Passed | Returned a clean connection error (`isError: true`) with no crash; audit log recorded `outcome=error` and `error_type=MISPClientError`. |
| Error path: invalid `MISP_API_KEY` | Passed | Returned a clean authentication error with no crash and no key echoed; audit log recorded `outcome=error` and `error_type=MISPAuthenticationError`. |
| MCP Inspector CLI mode | Passed | `tools/list` and `tools/call` verified via `--cli` mode (non-browser) against `uv run agentic-misp-mcp` over stdio. |
| Controlled writes | Pending | Must be validated separately with `AGENTIC_MISP_MCP_ENABLE_WRITE=true` against an isolated lab only. |
| Production deployment | Not validated | This project remains lab-tested, not production-certified. |

The first positive live IOC test used `54.87.87.13`, which matched MISP event `187`, `OSINT - NANHAISHU RATing the South China Sea`. The generated IOC report classified the IOC as `suspicious` with medium confidence based on live MISP matches, actionable `to_ids` attributes, related event context, and extracted related IOCs.

Additional read-only validation confirmed that domain-side searches for composite `domain|ip` attributes work, including `mines.port0.org` and `eholidays.mooo.com`. SHA256 lookup was also validated using a related payload-delivery hash from the same event.

Because the first positive live test used historical OSINT data, analyst workflows should correlate hits with recent SIEM, EDR, DNS, proxy, firewall, or endpoint telemetry before blocking or escalation.

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

Important approval limitation: `approved=true` is a programmatic gate, not a complete
human-in-the-loop approval mechanism by itself. Real HITL approval requires an external
orchestrator that only submits approved calls after a human decision, or approval-token
enforcement with `AGENTIC_MISP_MCP_APPROVAL_TOKEN`. For autonomous agents, configure an approval
token so the calling agent cannot self-approve writes merely by setting `approved=true`.

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

### Proposal-only tools that never write to MISP

These tools build reviewable payloads only. They are policy-gated, but they never invoke MISP write endpoints.

- `propose_event(...)` — build an event creation proposal; never writes to MISP.
- `propose_attribute(...)` — build an attribute creation proposal; never writes to MISP.

### Approval-gated write tools

These tools are blocked unless write mode and role allow the action; write execution also requires explicit approval by default.

- `submit_ioc_with_approval(..., approved=False, approval_token=None)` — add an attribute only when policy and approval allow.
- `add_sighting_with_approval(..., approved=False, approval_token=None)` — add a sighting only when policy and approval allow.
- `tag_event_with_approval(event_id, tag, approved=False, approval_token=None)` — tag an event only when policy and approval allow.
- `publish_event_with_approval(event_id, approved=False, approval_token=None)` — publish an event only for curator/admin roles and approval.

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

### Docker usage

This flow was used for the first live read-only lab validation against MISP `2.5.42`. It uses
generic paths — replace them with your own locations outside the repository.

#### Build image

```bash
cd /path/to/agentic-misp-mcp
docker build -t agentic-misp-mcp:live-test .
```

#### Create env file outside the repository

```bash
mkdir -p /home/user/.config/agentic-misp-mcp
cat > /home/user/.config/agentic-misp-mcp/live.env <<'EOF'
# Example lab environment
MISP_URL=https://misp-lab.example.local
MISP_API_KEY=replace_with_your_lab_api_key
MISP_VERIFY_TLS=false

MISP_TIMEOUT_SECONDS=30
MISP_DEFAULT_LIMIT=20
MISP_MAX_LIMIT=100
MISP_EVENT_ATTRIBUTE_LIMIT=50
MISP_RELATED_EVENT_LIMIT=5

AGENTIC_MISP_MCP_AUDIT_LOG_PATH=/app/logs/audit.jsonl
AGENTIC_MISP_MCP_LOG_LEVEL=INFO
AGENTIC_MISP_MCP_ROLE=read_only
AGENTIC_MISP_MCP_ENABLE_WRITE=false
AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true
AGENTIC_MISP_MCP_APPROVAL_TOKEN=
AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES=5242880
AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=false
EOF
```

`MISP_VERIFY_TLS=false` is lab-only, for a self-signed certificate on an isolated lab MISP
instance. Do not use it for production-like environments; keep TLS verification enabled there.

#### Create audit log directory

```bash
mkdir -p /home/user/.local/state/agentic-misp-mcp/logs
```

#### Run config-check

```bash
docker run --rm \
  --env-file /home/user/.config/agentic-misp-mcp/live.env \
  -v /home/user/.local/state/agentic-misp-mcp/logs:/app/logs \
  agentic-misp-mcp:live-test \
  config-check
```

`config-check` validates runtime configuration and audit-log writability. It does not prove MISP
API connectivity.

#### Test MISP connectivity from inside the container

```bash
docker run --rm \
  --env-file /home/user/.config/agentic-misp-mcp/live.env \
  --entrypoint python \
  agentic-misp-mcp:live-test \
  -c "import os, httpx; verify=os.environ.get('MISP_VERIFY_TLS','true').lower()=='true'; r=httpx.get(os.environ['MISP_URL'].rstrip('/') + '/servers/getVersion', headers={'Authorization': os.environ['MISP_API_KEY'], 'Accept':'application/json'}, verify=verify, timeout=10); print('STATUS:', r.status_code); print(r.text[:1000])"
```

Expected result:

```text
STATUS: 200
```

A `200` response confirms the container can reach the MISP API before running any MCP tools.

#### Run the MCP server over stdio

```bash
docker run --rm -i \
  --env-file /home/user/.config/agentic-misp-mcp/live.env \
  -v /home/user/.local/state/agentic-misp-mcp/logs:/app/logs \
  agentic-misp-mcp:live-test --transport stdio
```

#### Run with MCP Inspector

Live validation used MCP Inspector v0.22.0 against the stdio transport:

```bash
npx @modelcontextprotocol/inspector@0.22.0 \
  docker run --rm -i \
    --env-file /home/user/.config/agentic-misp-mcp/live.env \
    -v /home/user/.local/state/agentic-misp-mcp/logs:/app/logs \
    agentic-misp-mcp:live-test --transport stdio
```

#### Headless host access with SSH tunnel

MCP Inspector serves its client UI and proxy on ports 6274 and 6277. When Inspector runs on a
headless Linux host, forward both ports over SSH and open the UI from your workstation browser:

```bash
ssh -L 6274:localhost:6274 -L 6277:localhost:6277 user@mcp-host.example.local
```

Then browse to `http://localhost:6274` on the workstation.

#### Check audit logs

```bash
tail -n 20 /home/user/.local/state/agentic-misp-mcp/logs/audit.jsonl
```

Or pretty-print each JSON record:

```bash
tail -n 20 /home/user/.local/state/agentic-misp-mcp/logs/audit.jsonl | jq .
```

Audit entries are JSONL, with sanitized arguments and policy decision fields. Successful calls,
validation failures, runtime errors, and blocked write attempts are recorded. Blocked policy
decisions use `outcome=blocked`.

Do not bake secrets into the image. Pass credentials only at runtime.

### Read-only live test checklist

Use this checklist for a controlled, non-production MISP lab:

- [ ] Run `config-check`.
- [ ] Confirm `/servers/getVersion` returns HTTP 200 from inside the Docker container.
- [ ] Connect MCP Inspector over stdio.
- [ ] Run `tools/list`.
- [ ] Run `search_ioc` for a known non-matching IOC and confirm clean no-match behavior.
- [ ] Run `search_ioc` for a known matching IPv4 indicator.
- [ ] Run `search_ioc` for a known matching domain indicator.
- [ ] Run `search_ioc` for a known matching SHA256 indicator.
- [ ] Run `investigate_ioc` for a known matching IOC.
- [ ] Run `summarize_event` for a known event ID.
- [ ] Run `generate_ioc_report` for a known matching IOC.
- [ ] Run `check_warninglists` for representative public, private, or lab indicators.
- [ ] Attempt one write tool while `AGENTIC_MISP_MCP_ROLE=read_only` and
      `AGENTIC_MISP_MCP_ENABLE_WRITE=false`; confirm it is blocked.
- [ ] Search for the attempted test write value and confirm MISP was not modified.
- [ ] Check `audit.jsonl` for successful calls, validation failures, runtime errors, and blocked
      write decisions.
- [ ] Confirm no write tools were executed.

The specific IOC and event ID values used in one lab may not exist in another MISP instance. Use
known-good indicators from your own lab dataset.

### Docker MCP client configuration

For MCP clients that can spawn Docker on the same host, use stdio with `docker run`:

```json
{
  "mcpServers": {
    "agentic-misp-mcp": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--env-file",
        "/home/user/.config/agentic-misp-mcp/live.env",
        "-v",
        "/home/user/.local/state/agentic-misp-mcp/logs:/app/logs",
        "agentic-misp-mcp:live-test",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

This pattern assumes the MCP client can spawn Docker on the same host. For remote or headless
testing, run the client on the Docker host or use MCP Inspector with SSH port forwarding.

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
| `AGENTIC_MISP_MCP_APPROVAL_TOKEN` | No | unset | Optional approval-token hardening. When set, approved write calls must include the matching `approval_token`; audit logs redact it. |
| `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` | No | `5242880` | Maximum MISP HTTP response body size, enforced before JSON parsing. |
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | No | `false` | Allows experimental HTTP transport to bind `0.0.0.0`; keep false unless behind authenticated TLS termination. |

See `docs/configuration.md` for more examples.

## Security notes

- Use stdio by default.
- Treat HTTP transport as experimental. Binding to `0.0.0.0` is refused by default because HTTP mode has no built-in auth/TLS; use `127.0.0.1` or place it behind authenticated TLS termination and explicitly opt in.
- Keep `.env`, audit logs, and API keys out of git.
- Automated tests still use mocked MISP responses.
- First manual read-only live lab validation has passed against MISP `2.5.42`.
- Controlled write validation and broader MISP version compatibility remain pending.
- A read-only write-block test confirmed that `approved=true` does not bypass disabled write mode or the `read_only` role.
- Blocked policy decisions are audited with `allowed=false`, `success=false`, and `outcome=blocked`.
- Successful allowed calls are audited with `outcome=success`; runtime failures are audited with `outcome=error`.
- Approval tokens and other sensitive values are redacted in audit logs.
- See `SECURITY.md` and `docs/security.md` for reporting and deployment guidance.

## Documentation

- [`docs/security.md`](docs/security.md) — security model, tool boundary, audit logging.
- [`docs/configuration.md`](docs/configuration.md) — full environment variable reference.
- [`docs/testing.md`](docs/testing.md) — what the mocked test suite covers and does not cover yet.
- [`docs/roles.md`](docs/roles.md) — `read_only` / `analyst_write` / `curator` / `admin` policy roles.
- [`docs/approval-flow.md`](docs/approval-flow.md) — the `approved=false` → `pending_approval` → `approved=true` write flow, with examples.
- [`docs/live-validation-plan.md`](docs/live-validation-plan.md) — live MISP validation checklist and remaining validation work.
- [`docs/openapi-inventory.md`](docs/openapi-inventory.md) — sample MISP OpenAPI endpoint classification (planning only).

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

## Known live validation limitations

The first positive live validation used historical OSINT data from 2016. This is useful for
proving MISP API compatibility and MCP workflow behavior, but it should not be treated as current
threat activity without telemetry correlation.

Future scoring improvements should consider stale-intel labeling or event-age weighting.

Controlled write execution has not yet been validated. Write testing must be performed only
against an isolated lab MISP instance with `AGENTIC_MISP_MCP_ENABLE_WRITE=true`.

## Roadmap

- Complete remaining live lab validation: pivot tools, warninglist edge cases, large-event behavior, controlled writes, and broader MISP version compatibility. (Error paths for unreachable `MISP_URL` and invalid `MISP_API_KEY` are now validated.)
- Add broader audit outcome tests for additional write tools and error paths.
- Add stale-intel labeling or event-age weighting for historical OSINT context.
- Compatibility notes for MISP version differences, especially warninglists and event shapes.
- Release tagging and packaging once the live validation story is documented.
- Additional controlled workflows only when they preserve the no-raw-proxy, policy-gated model.

## Contributing

Contributions are welcome, but keep the project boundary intact: no raw API proxy, no secret passthrough, no unaudited tool path, and no write behavior without policy and approval gates. Start by reading `PROJECT_STATE.md`, `docs/security.md`, and `src/agentic_misp_mcp/tools/registry.py`.
