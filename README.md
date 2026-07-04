# agentic-misp-mcp

**MISP workflows for agents — investigate, pivot, report, and propose controlled writes without turning your MCP server into a raw API proxy.**

`agentic-misp-mcp` is an early-stage MCP server for security analysts working with MISP threat intelligence. It gives AI agents a small set of analyst-oriented workflows: search an IOC, investigate context, pivot through related indicators, summarize events, generate reports, and prepare tightly controlled write proposals.

It exists because agents should not need unrestricted MISP API access to help with SOC work. Instead of exposing every endpoint, this project exposes opinionated workflows with bounded output, policy checks, and audit logging.

## Status

**`v0.2.0` is GA production-ready for the MCP server scope defined in this project**
(MCP server behavior, MISP API behavior, approval workflow, audit/redaction, config safety,
runtime/deployment docs) — it is not a SIEM/SOAR/SOC platform, case-management system, or a
broad enterprise-monitoring claim, and SIEM/SOAR/SOC integration remains optional future work,
not a GA requirement (see
[`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md)). Manual
audit-log review is the accepted control for this release, not automated SOC-grade
alerting/monitoring — see [`docs/production-readiness.md`](docs/production-readiness.md)'s
"Audit logging and manual review guidance." **MISP `2.5.42` is the validated GA baseline**; if
you run this against a different MISP version, run the validation checklist in
[`docs/live-validation-plan.md`](docs/live-validation-plan.md) and
[`docs/misp-compatibility.md`](docs/misp-compatibility.md) first — no other version is covered
by this GA claim. HTTP `429`/rate-limit handling has controlled/mocked test coverage only; a
live `429` was not reproduced (no safe way to trigger one in the lab — see
[`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md)).

- `main` contains `v0.2.0`, the first GA release. It builds on `v0.2.0-rc.1`
  (`propose_event`/`propose_attribute` payload validation, a MISP version compatibility matrix,
  a fixed dependency-update/Dependabot configuration) plus two fixes found during `v0.2.0-rc.1`'s
  live validation pass: `add_sighting_with_approval` now correctly reports a MISP-rejected
  sighting as `failed` instead of `executed`, and `check_warninglists` now correctly recognizes a
  real positive warninglist hit against MISP `2.5.42` instead of reporting `not_available`. See
  [`docs/misp-compatibility.md`](docs/misp-compatibility.md) and
  [`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md).
- Mocked test coverage exists for core workflows and policy paths (257 tests).
- Live validation has passed against MISP `2.5.42` (Docker, stdio transport, MCP Inspector),
  covering read-only workflows, all four controlled-write tools, `propose_event`/
  `propose_attribute` validation, TLS fail-closed, timeout, large-result truncation, a positive
  warninglist hit, warninglist miss/`not_available`, the full production approval lifecycle
  (including one real MISP write and replay/hash-mismatch/wrong-tool/expired/rejected redemption
  blocks), audit redaction/correlation, `config doctor` against safe and unsafe configs, and
  `approvals prune`. See [`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md).
- **Known limitations, explicitly not covered by GA:** only MISP `2.5.42` has been validated —
  see [`docs/misp-compatibility.md`](docs/misp-compatibility.md) for untested-version risk; a
  real HTTP `429` was verified via a mock transport only (no safe way to trigger one live in the
  lab); container-image/dependency/secret scanning and signed release artifacts are not yet part
  of CI/release — see [`docs/production-readiness.md`](docs/production-readiness.md) and
  [`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md) for the full list
  and the path beyond GA.
- `agentic-misp-mcp config doctor` (operational-readiness checks) and `agentic-misp-mcp approvals prune` (operator-CLI-only approval-store maintenance) are both live-validated; see [`docs/configuration.md`](docs/configuration.md) and [`docs/rollback.md`](docs/rollback.md).
- Current MCP tool count: **19**.
- Primary transport: **stdio**.
- HTTP transport exists but is experimental.
- Requires Python 3.11+.
- License: MIT.

## Quick start

There are two ways to run `agentic-misp-mcp`: **local** (Python/`uv`, no Docker needed) or
**Docker**. Pick one — both end up in the same place, an MCP server your client can talk to.

### Prerequisites

- A MISP instance you can reach, and an API key for it (`MISP_URL`, `MISP_API_KEY`).
- Python 3.11+ for the local path, **or** Docker for the Docker path.
- An MCP client to actually use it (Claude Desktop, Claude Code, MCP Inspector, etc.).

### Option A — Local install (Python / `uv`)

1. **Install:**

   ```bash
   pip install -e ".[dev]"
   # or, with uv:
   uv sync --extra dev
   ```

2. **Configure your MISP connection:**

   ```bash
   cp .env.example .env
   # edit .env — at minimum set MISP_URL and MISP_API_KEY
   ```

3. **Validate configuration** (no MISP connection is made; the API key is redacted):

   ```bash
   agentic-misp-mcp config-check
   # or: uv run agentic-misp-mcp config-check
   ```

4. **Run the server** over stdio (the primary supported transport):

   ```bash
   agentic-misp-mcp --transport stdio
   # or: uv run agentic-misp-mcp --transport stdio
   ```

5. **Point your MCP client at it.** Example config (works from any working directory, since `uv
   --directory` targets the repo explicitly):

   ```json
   {
     "mcpServers": {
       "agentic-misp-mcp": {
         "command": "uv",
         "args": [
           "--directory", "/path/to/agentic-misp-mcp",
           "run", "agentic-misp-mcp", "--transport", "stdio"
         ],
         "env": {
           "MISP_URL": "https://misp.example.local",
           "MISP_API_KEY": "your_misp_api_key_here"
         }
       }
     }
   }
   ```

   If you installed with `pip` into an environment already on your `PATH`, you can use
   `"command": "agentic-misp-mcp"` with `"args": ["--transport", "stdio"]` instead of the `uv`
   wrapper.

### Option B — Docker

1. **Build the image:**

   ```bash
   git clone https://github.com/hdyrawan/agentic-misp-mcp.git
   cd agentic-misp-mcp
   docker build -t agentic-misp-mcp:local .
   ```

2. **Create an env file outside the repository** (never commit real credentials) and a directory
   for audit logs:

   ```bash
   mkdir -p ~/.config/agentic-misp-mcp
   cp .env.example ~/.config/agentic-misp-mcp/.env
   # edit ~/.config/agentic-misp-mcp/.env — at minimum set MISP_URL and MISP_API_KEY
   mkdir -p ~/.local/state/agentic-misp-mcp/logs
   ```

   (Prefer Compose? `docker-compose.example.yml` does the same thing — see
   [`docs/configuration.md`](docs/configuration.md#docker-compose).)

3. **Validate configuration:**

   ```bash
   docker run --rm \
     --env-file ~/.config/agentic-misp-mcp/.env \
     -v ~/.local/state/agentic-misp-mcp/logs:/app/logs \
     agentic-misp-mcp:local config-check
   ```

4. **Run the server** over stdio:

   ```bash
   docker run --rm -i \
     --env-file ~/.config/agentic-misp-mcp/.env \
     -v ~/.local/state/agentic-misp-mcp/logs:/app/logs \
     agentic-misp-mcp:local --transport stdio
   ```

5. **Point your MCP client at it** (assumes your client can spawn `docker` on the same host — for
   a remote/headless Docker host, run the client there too, or see the SSH-tunnel note below):

   ```json
   {
     "mcpServers": {
       "agentic-misp-mcp": {
         "command": "docker",
         "args": [
           "run", "--rm", "-i",
           "--env-file", "/home/you/.config/agentic-misp-mcp/.env",
           "-v", "/home/you/.local/state/agentic-misp-mcp/logs:/app/logs",
           "agentic-misp-mcp:local",
           "--transport", "stdio"
         ]
       }
     }
   }
   ```

### Verify it's working

Either path: `config-check` should print `Configuration check: OK` with `MISP_API_KEY is set
([REDACTED])`. Then ask your MCP client to run a read-only tool — for example `search_ioc` with a
known indicator — and confirm you get a structured JSON result back. See "Testing against a live
MISP lab" below for a deeper validation walkthrough (MCP Inspector, SSH tunneling, a read-only
test checklist).

## Live lab validation status

The first live validation was performed against a controlled, non-production MISP lab. For the
most recent and most complete live validation pass (TLS fail-closed, timeout, large-result
truncation, a positive warninglist hit, and the full production approval lifecycle including one
real MISP write), see
[`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md).

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
| `submit_ioc_with_approval` | Passed | `pending_approval` then `executed` against a dedicated sandbox event; created attribute confirmed visible via `search_ioc`. |
| `add_sighting_with_approval` | Passed | Sighting recorded against the submitted attribute and confirmed visible in MISP. |
| `tag_event_with_approval` | Passed | Real tag (`tlp:white`) confirmed attached to the event; an unrecognized tag correctly reports `status: "failed"` (see Fixed below). |
| `publish_event_with_approval` | Passed | `analyst_write` correctly blocked (requires `curator`); `curator` published the sandbox event, confirmed via direct MISP query (`published: true`). |
| Controlled-write policy blocking | Passed | `read_only`/write-disabled and `analyst_write`-on-publish were both correctly blocked with no MISP call made. |
| Production deployment | Not validated | This project remains lab-tested, not production-certified. |

The first positive live IOC test used `54.87.87.13`, which matched MISP event `187`, `OSINT - NANHAISHU RATing the South China Sea`. The generated IOC report classified the IOC as `suspicious` with medium confidence based on live MISP matches, actionable `to_ids` attributes, related event context, and extracted related IOCs.

Additional read-only validation confirmed that domain-side searches for composite `domain|ip` attributes work, including `mines.port0.org` and `eholidays.mooo.com`. SHA256 lookup was also validated using a related payload-delivery hash from the same event.

Because the first positive live test used historical OSINT data, analyst workflows should correlate hits with current local telemetry before blocking or escalation.

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

Important approval limitation: lab approval mode and production approval mode are different. In
`AGENTIC_MISP_MCP_APPROVAL_MODE=lab` (the default), `approved=true` is only a programmatic lab gate;
`AGENTIC_MISP_MCP_APPROVAL_TOKEN` is an optional shared-secret control for that lab flow and is not
the production approval mechanism. In `AGENTIC_MISP_MCP_APPROVAL_MODE=production`, `approved=true`
alone never executes a write. Production execution requires a persisted `approval_request_id` that
was approved out of band with the operator CLI, is one-time-use, TTL-bound, and exact
operation-hash-bound.

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

- `submit_ioc_with_approval(..., approved=False, approval_token=None, approval_request_id=None)` — add an attribute only when policy and approval allow.
- `add_sighting_with_approval(..., approved=False, approval_token=None, approval_request_id=None)` — add a sighting only when policy and approval allow.
- `tag_event_with_approval(event_id, tag, approved=False, approval_token=None, approval_request_id=None)` — tag an event only when policy and approval allow.
- `publish_event_with_approval(event_id, approved=False, approval_token=None, approval_request_id=None)` — publish an event only for curator/admin roles and approval.

Write-tool results are explicit: `blocked`, `pending_approval`, or `executed`. There are no silent writes.

## Testing against a live MISP lab (optional)

Beyond the Quick start above, this section covers the deeper flow used for this project's own
live-lab validation (see the validation table below) — useful if you want to reproduce it, or run
the same checks against your own non-production MISP lab. It assumes you already completed the
Docker Quick start above (image built, env file and log directory created).

### Test MISP connectivity from inside the container

```bash
docker run --rm \
  --env-file ~/.config/agentic-misp-mcp/.env \
  --entrypoint python \
  agentic-misp-mcp:local \
  -c "import os, httpx; verify=os.environ.get('MISP_VERIFY_TLS','true').lower()=='true'; r=httpx.get(os.environ['MISP_URL'].rstrip('/') + '/servers/getVersion', headers={'Authorization': os.environ['MISP_API_KEY'], 'Accept':'application/json'}, verify=verify, timeout=10); print('STATUS:', r.status_code); print(r.text[:1000])"
```

A `STATUS: 200` response confirms the container can reach the MISP API before running any MCP tools.

### Run with MCP Inspector

Against Docker:

```bash
npx @modelcontextprotocol/inspector@0.22.0 \
  docker run --rm -i \
    --env-file ~/.config/agentic-misp-mcp/.env \
    -v ~/.local/state/agentic-misp-mcp/logs:/app/logs \
    agentic-misp-mcp:local --transport stdio
```

Against a local (non-Docker) install:

```bash
npx @modelcontextprotocol/inspector@0.22.0 \
  uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp --transport stdio
```

For headless/CI use (no browser UI), pass `--cli` and `--method`:

```bash
npx -y @modelcontextprotocol/inspector --cli \
  uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp \
  --method tools/list
```

### Headless host access with SSH tunnel

MCP Inspector's browser UI serves its client and proxy on ports 6274 and 6277. When Inspector runs
on a headless Linux host, forward both ports over SSH and open the UI from your workstation
browser:

```bash
ssh -L 6274:localhost:6274 -L 6277:localhost:6277 user@mcp-host.example.local
```

Then browse to `http://localhost:6274` on the workstation. (The `--cli` mode above avoids needing
this entirely.)

### Check audit logs

```bash
tail -n 20 ~/.local/state/agentic-misp-mcp/logs/audit.jsonl | jq .
```

Audit entries are JSONL, with sanitized arguments and policy decision fields. Successful calls,
validation failures, runtime errors, blocked write attempts, and MISP-side write rejections
(`outcome: "failed"`) are all recorded — see [`docs/security.md`](docs/security.md) for the full
outcome semantics.

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
known-good indicators from your own lab dataset. For the controlled-write path
(`propose_event`/`propose_attribute`/the four `_with_approval` tools), see
[`docs/approval-flow.md`](docs/approval-flow.md) and
[`docs/live-validation-plan.md`](docs/live-validation-plan.md) — never run write testing against
anything but an isolated lab.

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
| `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` | No | `true` | Lab-mode gate requiring explicit `approved=true`; production mode still requires `approval_request_id` even if this is `false`. |
| `AGENTIC_MISP_MCP_APPROVAL_TOKEN` | No | unset | Optional lab/shared-secret hardening. When set in lab mode, approved write calls must include the matching `approval_token`; audit logs redact it. Not the production approval mechanism. |
| `AGENTIC_MISP_MCP_APPROVAL_MODE` | No | `lab` | `lab` preserves the legacy `approved=true` flow; `production` requires persisted operator-approved request IDs. |
| `AGENTIC_MISP_MCP_APPROVAL_STORE_PATH` | No | `./approvals.sqlite3` | SQLite store for production approval records; the agent must not have write access to it. |
| `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS` | No | `900` | Production approval lifetime before pending/approved records expire. |
| `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES` | No | unset | Optional production guardrail for submitted attribute types. |
| `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES` | No | unset | Optional production guardrail for submitted attribute categories. |
| `AGENTIC_MISP_MCP_ALLOWED_TAGS` | No | unset | Optional production guardrail for event tags; entries ending in `*` act as prefixes. |
| `AGENTIC_MISP_MCP_ENABLE_PUBLISH` | No | `false` | Dedicated publish kill switch; production publish also requires curator/admin role and approval. |
| `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` | No | `5242880` | Maximum MISP HTTP response body size, enforced before JSON parsing. |
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | No | `false` | Allows experimental HTTP transport to bind `0.0.0.0`; keep false unless behind authenticated TLS termination. |

See `docs/configuration.md` for more examples.

## Production deployment

**`v0.2.0` is a GA release, evidence-based on the live validation in
[`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md) — but
it is not the same as full production-readiness certification against
[`docs/production-readiness.md`](docs/production-readiness.md)'s broader, stricter checklist**
(which additionally requires broader MISP version compatibility, a live HTTP `429`
reproduction, and supply-chain/release hygiene — container image scanning, dependency
vulnerability scanning, secret scanning, and a signed release tag — none of which are done yet).
See that document for the full scope, requirements, and the acceptance criteria that must pass
before that broader certification changes. This section shows the conservative deployment shape
for the one target that document is scoped against first: **read-only** investigation and
reporting (`AGENTIC_MISP_MCP_ROLE=read_only`, `AGENTIC_MISP_MCP_ENABLE_WRITE=false`) over
**stdio**, via Docker.

1. **Build the image:**

   ```bash
   git clone https://github.com/hdyrawan/agentic-misp-mcp.git
   cd agentic-misp-mcp
   docker build -t agentic-misp-mcp:local .
   ```

2. **Configure a production env file outside the repository**, starting from the
   production-oriented template (placeholders only — see
   [`.env.production.example`](.env.production.example) for the full file with inline guidance):

   ```bash
   mkdir -p /path/to/agentic-misp-mcp-runtime/logs
   cp .env.production.example /path/to/agentic-misp-mcp-runtime/.env
   # edit /path/to/agentic-misp-mcp-runtime/.env — set MISP_URL and MISP_API_KEY;
   # leave MISP_VERIFY_TLS=true, AGENTIC_MISP_MCP_ROLE=read_only,
   # AGENTIC_MISP_MCP_ENABLE_WRITE=false, and AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true as-is.
   ```

3. **Run `config-check`** before starting the server, every time the configuration changes:

   ```bash
   docker run --rm \
     --env-file /path/to/agentic-misp-mcp-runtime/.env \
     -v /path/to/agentic-misp-mcp-runtime/logs:/app/logs \
     agentic-misp-mcp:local config-check
   ```

   This validates configuration and confirms the audit-log path is writable. It does not connect
   to MISP.

   Then run `agentic-misp-mcp config doctor` (same invocation, swap the final argument) for a
   deeper operational-readiness check: write/approval-mode pairing, publish/role pairing,
   approval-store and audit-log permission safety, allowlist coverage, approval TTL length, and
   temporary-directory paths. It also does not connect to MISP, never prints secrets, and exits
   nonzero on any `FAIL`. See [`docs/configuration.md`](docs/configuration.md#operational-readiness-doctor-v020-beta2).

4. **Test MISP connectivity** before wiring up an MCP client, to confirm the deployment can
   actually reach MISP with the configured TLS settings:

   ```bash
   docker run --rm \
     --env-file /path/to/agentic-misp-mcp-runtime/.env \
     --entrypoint python \
     agentic-misp-mcp:local \
     -c "import os, httpx; verify=os.environ.get('MISP_VERIFY_TLS','true').lower()=='true'; r=httpx.get(os.environ['MISP_URL'].rstrip('/') + '/servers/getVersion', headers={'Authorization': os.environ['MISP_API_KEY'], 'Accept':'application/json'}, verify=verify, timeout=10); print('STATUS:', r.status_code)"
   ```

   Expect `STATUS: 200`. A TLS or connection error here means fix the deployment's network/CA
   configuration before proceeding — do not fall back to `MISP_VERIFY_TLS=false` to make this
   pass; that setting is lab-only (see [`docs/production-readiness.md`](docs/production-readiness.md#tls-requirements)).

5. **Run the server over stdio**, with the audit log directory mounted so logs persist across
   container restarts:

   ```bash
   docker run --rm -i \
     --env-file /path/to/agentic-misp-mcp-runtime/.env \
     -v /path/to/agentic-misp-mcp-runtime/logs:/app/logs \
     agentic-misp-mcp:local --transport stdio
   ```

   Point your MCP client at this same `docker run` invocation (see the Docker Quick start above
   for an example client config) — the client, not this container, decides when to start/stop
   the process, so there is no separate "daemon" to manage.

**HTTP transport is not the default recommendation for production.** It is experimental, has no
built-in authentication or TLS, and refuses to bind `0.0.0.0` unless
`AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true` is explicitly set. If you use it in production at
all, it must sit behind an authenticated, TLS-terminating gateway (reverse proxy or service mesh)
that terminates TLS and enforces authentication before any traffic reaches this server — stdio
remains the primary supported production transport.

Before treating any deployment as production, review
[`docs/production-readiness.md`](docs/production-readiness.md)'s Docker hardening checklist
(read-only root filesystem, resource limits, base-image patching) and release/sign-off checklist
in full — this section covers the conservative deployment shape, not the complete readiness bar.

## Security notes

- Use stdio by default.
- Treat HTTP transport as experimental. Binding to `0.0.0.0` is refused by default because HTTP mode has no built-in auth/TLS; use `127.0.0.1` or place it behind authenticated TLS termination and explicitly opt in.
- Keep `.env`, audit logs, and API keys out of git.
- Automated tests still use mocked MISP responses.
- First manual read-only live lab validation has passed against MISP `2.5.42`; controlled-write validation has since passed against the same lab. Broader MISP version compatibility remains pending.
- A read-only write-block test confirmed that `approved=true` does not bypass disabled write mode or the `read_only` role.
- Blocked policy decisions are audited with `allowed=false`, `success=false`, and `outcome=blocked`.
- Successful allowed calls are audited with `outcome=success`; runtime failures are audited with `outcome=error`; a controlled write that reaches MISP but is rejected by MISP itself (`saved`/`published: false`) is audited with `outcome=failed`.
- Approval tokens and other sensitive values are redacted in audit logs.
- See `SECURITY.md` and `docs/security.md` for reporting and deployment guidance.

## Documentation

- [`docs/security.md`](docs/security.md) — security model, tool boundary, audit logging.
- [`docs/configuration.md`](docs/configuration.md) — full environment variable reference.
- [`docs/testing.md`](docs/testing.md) — what the mocked test suite covers and does not cover yet.
- [`docs/roles.md`](docs/roles.md) — `read_only` / `analyst_write` / `curator` / `admin` policy roles.
- [`docs/approval-flow.md`](docs/approval-flow.md) — lab approval flow plus the `v0.2.0-beta.1` production approval flow.
- [`docs/live-validation-plan.md`](docs/live-validation-plan.md) — completed lab validation evidence and remaining validation work.
- [`docs/live-beta-validation-v0.2.0-beta.1.md`](docs/live-beta-validation-v0.2.0-beta.1.md) — live beta validation checklist before tagging `v0.2.0-beta.1`.
- [`docs/live-beta-validation-v0.2.0-beta.2.md`](docs/live-beta-validation-v0.2.0-beta.2.md) — live validation checklist for the `v0.2.0-beta.2` operational-readiness hardening release.
- [`docs/live-beta-validation-v0.2.0-rc.1.md`](docs/live-beta-validation-v0.2.0-rc.1.md) — live validation checklist for the `v0.2.0-rc.1` release candidate (now executed; see the report below).
- [`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md) — the executed `v0.2.0-rc.1` live validation report: results, two blockers found and fixed, and evidence for the `v0.2.0` GA decision.
- [`docs/misp-compatibility.md`](docs/misp-compatibility.md) — MISP version compatibility matrix: tested versions, assumptions, untested versions, and known risks.
- [`docs/production-readiness.md`](docs/production-readiness.md) — production-readiness scope, requirements, and release/sign-off acceptance criteria (broader/stricter than the `v0.2.0` GA claim — see "Production deployment" above).
- [`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md) — the phased plan for reaching a GA production-readiness claim; `v0.2.0` GA has been reached per this project's evidence-based criteria, though some items in this plan remain open (see "Roadmap" above).
- [`docs/rollback.md`](docs/rollback.md) — rollback playbook for a mistaken controlled write: finding it in the audit log, correlating it with its approval record, and why a mistaken publish is not fully reversible.
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

Controlled write execution has been validated against an isolated lab (see the table above).
Two real bugs surfaced during that pass and are now fixed:

- A present-but-empty `AGENTIC_MISP_MCP_APPROVAL_TOKEN` (e.g. `KEY=` in a `.env` file) was parsed
  as a configured empty-string token rather than "no token configured," silently blocking every
  controlled-write execution. Blank/whitespace-only tokens now normalize to unset.
- `tag_event_with_approval` and `publish_event_with_approval` reported `status: "executed"` even
  when MISP itself rejected the operation (`saved`/`published: false` on an HTTP 200 response,
  e.g. an unrecognized tag name). They now report a distinct `status: "failed"`, with a matching
  `outcome: "failed"` audit entry, so a caller cannot mistake a MISP-side rejection for a real
  write. See [`docs/approval-flow.md`](docs/approval-flow.md#executed-vs-failed).

## Roadmap

As of `v0.2.0` GA: warninglist hit/miss/`not_available`, large-result truncation, TLS fail-closed,
timeout, `propose_event`/`propose_attribute` payload validation, and the full production approval
lifecycle (including one real MISP write) are all live-validated — see
[`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md). What
remains open beyond GA:

- A live (non-mocked) HTTP `429`/rate-limit reproduction — no safe way to trigger one in the lab
  without a load-testing setup, which is out of scope (no DoS-style testing).
- Validate against a second MISP version beyond `2.5.42` (`docs/misp-compatibility.md`).
- Add broader audit outcome tests for additional write tools and error paths.
- Add stale-intel labeling or event-age weighting for historical OSINT context.
- Strengthen approval-operator separation beyond filesystem permissions (see
  `docs/production-readiness.md`'s GA backlog).
- Container image scanning, dependency vulnerability scanning, secret scanning, and a signed
  release tag (`docs/production-readiness.md`, `docs/ga-production-readiness-plan.md`).
- Additional controlled workflows only when they preserve the no-raw-proxy, policy-gated model.

## Contributing

Contributions are welcome, but keep the project boundary intact: no raw API proxy, no secret passthrough, no unaudited tool path, and no write behavior without policy and approval gates. Start by reading `PROJECT_STATE.md`, `docs/security.md`, and `src/agentic_misp_mcp/tools/registry.py`.

Commits should be attributed to their human author only — do not add AI co-author trailers (for example `Co-Authored-By: <AI assistant>`) to commits in this repository, regardless of what tooling was used to help write them.


### v0.2.0-beta.1 production-write beta candidate

The current `main` branch contains the `v0.2.0-beta.1` production-write beta candidate. It is suitable for isolated pilot validation, not GA production use. The default approval mode remains `AGENTIC_MISP_MCP_APPROVAL_MODE=lab`, preserving the existing `approved=true` lab flow. A new opt-in `production` mode adds persisted SQLite approvals for the four existing write-executing tools only: `submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, and `publish_event_with_approval`. No new MISP endpoints, raw proxy behavior, or admin tools are exposed.

In production mode, `approved=true` alone is blocked, even if `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=false`. Execution requires an operator-approved `approval_request_id` from `agentic-misp-mcp approvals ...`; no MCP tool can approve or reject. Each production approval is one-time-use, TTL-bound by `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS`, and bound to the exact canonical operation hash. The LLM/agent must not have shell access to the approval CLI or write access to the SQLite approval database. If redemption succeeds but the later MISP write fails, the approval remains consumed; the operator must approve a new request for any retry. Publishing is disabled by default with `AGENTIC_MISP_MCP_ENABLE_PUBLISH=false`; additional production guardrails include `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES`, `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES`, and `AGENTIC_MISP_MCP_ALLOWED_TAGS`.

See `docs/production-write.md` for the full beta deployment guidance and approval-store permission requirements.

### v0.2.0-beta.2 operational-readiness hardening

`v0.2.0-beta.2` builds on the `v0.2.0-beta.1` production-write beta with operator tooling and closed test gaps. It adds no new MCP tools, no new MISP write capability, and is still a beta, not GA production-ready.

- `agentic-misp-mcp config doctor` — a deeper operational-readiness check beyond `config-check`: validates write/approval-mode pairing, publish/role pairing, approval-store and audit-log permission safety, production write allowlist coverage, approval TTL length, temporary-directory paths, and leftover lab approval tokens in production mode. Outputs `PASS`/`WARN`/`FAIL` per check, never prints secrets, and exits nonzero on any `FAIL`.
- `agentic-misp-mcp approvals prune --older-than <duration> [--vacuum]` — operator-CLI-only maintenance that deletes old terminal (`used`/`rejected`/`expired`) approval records past an age threshold (`7d`, `30d`, `24h`, `3600s`-style durations), optionally followed by SQLite `VACUUM`. Never deletes `pending`/`approved` records. Not exposed through any MCP tool.
- [`docs/rollback.md`](docs/rollback.md) — a rollback playbook for a mistaken controlled write.
- Closed four `v0.2.0-beta.1` live-validation gaps with mocked/controlled tests: HTTP `429`, large-response truncation, a positive warninglist hit, and warninglist `not_available`, each exercised through the full registered-tool and audit path. See [`docs/live-validation-report-v0.2.0-beta.2.md`](docs/live-validation-report-v0.2.0-beta.2.md) for what was additionally validated live (the two new CLI commands, plus a read-only regression smoke test).

### v0.2.0-rc.1 GA-readiness release candidate

`v0.2.0-rc.1` builds on `v0.2.0-beta.2` and is a **release candidate for GA review**, not a GA
claim. It adds no new MCP tools, no new MISP write capability, and no raw proxy/admin behavior.

- `propose_event`/`propose_attribute` now validate the proposed payload before building it:
  required fields, `distribution`/`threat_level_id`/`analysis` value ranges, tag list shape, and a
  known-vocabulary allowlist of standard MISP attribute types/categories
  (`src/agentic_misp_mcp/policy/proposal_validation.py`). A malformed or unsupported payload
  returns a new `status: "invalid"` (audited as `outcome: "invalid"`, never `success`) with a
  `validation_errors` list, instead of a proposal. Both tools still never call MISP either way.
- Fixed `.github/dependabot.yml`, whose `package-ecosystem` was previously blank (no dependency
  updates were actually running); it now tracks `pip` and `github-actions`.
- Added [`docs/misp-compatibility.md`](docs/misp-compatibility.md): the MISP version compatibility
  matrix (tested versions, assumptions, untested versions, and known risks).
- Added [`docs/live-beta-validation-v0.2.0-rc.1.md`](docs/live-beta-validation-v0.2.0-rc.1.md): the
  live validation checklist for this release candidate.
- This remains a release candidate: live edge-case evidence (TLS fail-closed, timeout, a real
  HTTP `429`, large-result truncation at realistic scale, a positive warninglist hit against real
  data), live cross-checking of `propose_event`/`propose_attribute` payload shapes against a real
  MISP instance, broader MISP version compatibility, and supply-chain/release hygiene items
  (container image scanning, dependency vulnerability scanning, secret scanning, a signed release
  tag) all remain open — see [`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md).
  **Update:** the live validation this section describes as open was subsequently executed — see
  the "v0.2.0 GA" section below and
  [`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md).
  Broader MISP version compatibility and the supply-chain/release hygiene items remain open.

### v0.2.0 GA

`v0.2.0` is the first GA release. It builds on `v0.2.0-rc.1` plus two fixes found during that
release candidate's live validation pass against a real MISP `2.5.42` lab (see
[`docs/live-validation-report-v0.2.0-rc.1.md`](docs/live-validation-report-v0.2.0-rc.1.md) for
full evidence):

- Fixed `add_sighting_with_approval` reporting a MISP-rejected sighting as `status: "executed"`
  (audited as `outcome: "success"`) instead of `"failed"`.
- Fixed `check_warninglists` silently reporting `not_available` for a real positive warninglist
  hit against MISP `2.5.42`, instead of `hit: true` with the real match.
- Live-validated (previously only mocked/unit-tested): TLS fail-closed, timeout, large-result
  truncation, a positive warninglist hit, and the full production approval lifecycle end-to-end,
  including one real MISP write and blocked replay/hash-mismatch/wrong-tool/expired/rejected
  redemption attempts.
- No new MCP tools, no new MISP write capability, no raw proxy/admin behavior were added at any
  point from `v0.2.0-rc.1` to `v0.2.0` GA.

**GA still does not mean zero limitations.** Explicitly out of scope for this GA claim: broader
MISP version compatibility beyond `2.5.42` (see
[`docs/misp-compatibility.md`](docs/misp-compatibility.md)), a live (non-mocked) HTTP `429`
reproduction (no safe way to trigger one in the lab), and supply-chain/release hygiene items
(container image scanning, dependency vulnerability scanning, secret scanning, a signed release
tag) — see [`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md) for
what's next beyond GA.
