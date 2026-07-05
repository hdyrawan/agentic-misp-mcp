# agentic-misp-mcp

**MISP workflows for agents — investigate, pivot, report, and propose controlled writes without
turning your MCP server into a raw API proxy.**

`agentic-misp-mcp` is an MCP (Model Context Protocol) server that lets AI agents work with
[MISP](https://www.misp-project.org/) threat intelligence safely. Instead of exposing the whole
MISP API, it exposes **25 bounded, analyst-oriented workflows**: search an IOC, investigate its
context, pivot through related indicators, summarize events, check warninglists, observe feed
health, generate reports, and prepare tightly controlled write proposals.

The safety model is simple and enforced in code:

- **Read-first.** Every investigation tool is read-only; writes are disabled by default.
- **Approval-gated writes.** The four write tools require write mode, a permitted role, and an
  explicit approval step — in production mode, a one-time operator-approved request ID.
- **Audit logging.** Every tool call (allowed, blocked, failed, or errored) is written to a
  JSONL audit log with sanitized arguments.
- **Redaction.** API keys, approval tokens, and feed secrets never appear in responses or logs.
- **Role policy.** `read_only` / `analyst_write` / `curator` / `admin` roles bound what any
  agent session can even attempt.

**Compatibility baseline:** live-validated against **MISP `2.5.42`** (most recently the
`v0.3.0` release, 14/14 live checks — see
[`docs/live-validation-report-v0.3.0.md`](docs/live-validation-report-v0.3.0.md)). Other MISP
versions are untested; see [`docs/misp-compatibility.md`](docs/misp-compatibility.md).

## Who is this for?

- **SOC analysts** — ask an agent to investigate an IOC and get verdict, confidence, freshness,
  related events, and next steps instead of raw JSON dumps.
- **Threat intelligence analysts** — pivot, correlate, and produce Markdown/JSON reports from
  live MISP data.
- **Detection engineers** — extract actionable (`to_ids`) indicators and event context with
  bounded, predictable output.
- **Security automation teams** — wire MISP into agent workflows without handing the agent an
  unrestricted API key surface.
- **Regulated / banking environments** — every call is audited, writes need out-of-band
  operator approval, and the write surface is small and explicit.

## What can it do?

| Workflow | Tools involved |
| --- | --- |
| IOC investigation | `search_ioc`, `investigate_ioc`, `check_warninglists`, `pivot_ioc`, `find_related_iocs` |
| Event search and context | `search_events`, `summarize_event`, `explain_event_context`, `extract_event_iocs`, `find_events_by_tag` |
| Sightings | `get_ioc_sightings` (read), `add_sighting_with_approval` (gated write) |
| Warninglist checks | `check_warninglists`, plus automatic checks inside `investigate_ioc` |
| Feed observability (read-only) | `list_feeds`, `get_feed_status`, `summarize_feed_health` |
| Markdown / JSON reporting | `generate_ioc_report`, `generate_event_report`, `generate_markdown_ioc_report`, `generate_markdown_event_report` |
| Approval-gated writes | `submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval` |
| Age-aware scoring / stale-intel labeling | `investigate_ioc`, `generate_ioc_report`, `pivot_ioc` — see [Scoring behavior](#scoring-behavior) |

## The 25 tools

Access levels: **read-only** (never writes to MISP), **dry-run** (builds a reviewable payload,
never calls a MISP write endpoint), **approval-gated write** (blocked unless write mode, role,
and approval all allow it).

### Investigation and read tools

| Tool | Access | What it does |
| --- | --- | --- |
| `search_ioc(value, limit)` | read-only | Find normalized MISP attribute matches for an indicator. |
| `investigate_ioc(value, limit)` | read-only | Verdict, confidence, freshness, warninglists, related events, next steps. |
| `pivot_ioc(value, limit)` | read-only | Pivot from one IOC into related context. |
| `find_related_iocs(value, limit)` | read-only | Rank related indicators worth hunting. |
| `summarize_event(event_id)` | read-only | Bounded event summary (never full raw event JSON). |
| `explain_event_context(event_id)` | read-only | What an event appears to represent. |
| `extract_event_iocs(event_id, limit)` | read-only | Extract supported IOC types from an event. |
| `find_events_by_tag(tag, limit)` | read-only | Events associated with a tag. |
| `search_events(date_from, date_to, published, org, limit)` | read-only | Discover events by bounded date/publication/org filters. |
| `get_ioc_sightings(value, limit)` | read-only | Bounded sighting summaries for an IOC. |
| `check_warninglists(value)` | read-only | Check an IOC against MISP warninglists. |
| `get_misp_status()` | read-only | MISP version and warninglist capability status. |

### Feed observability

| Tool | Access | What it does |
| --- | --- | --- |
| `list_feeds(limit, enabled)` | read-only | List configured feeds with bounded, **redacted** metadata. |
| `get_feed_status(feed_id)` | read-only | One feed's redacted status and fetch/cache age. |
| `summarize_feed_health(limit)` | read-only | Group feeds by health label (fresh/stale/never-fetched/disabled). |

Feed enable/disable/fetch/cache/edit/delete remain operator-only MISP admin actions and are
**not** exposed as MCP tools. See [`docs/feed-observability.md`](docs/feed-observability.md).

### Reporting

| Tool | Access | What it does |
| --- | --- | --- |
| `generate_ioc_report(value)` | read-only | Deterministic structured (JSON) IOC report. |
| `generate_event_report(event_id)` | read-only | Deterministic structured (JSON) event report. |
| `generate_markdown_ioc_report(value)` | read-only | Markdown IOC report for notes/escalation. |
| `generate_markdown_event_report(event_id)` | read-only | Markdown event report. |

### Proposal (dry-run) tools

| Tool | Access | What it does |
| --- | --- | --- |
| `propose_event(...)` | dry-run | Build and validate an event-creation proposal. Never writes to MISP. |
| `propose_attribute(...)` | dry-run | Build and validate an attribute-creation proposal. Never writes to MISP. |

### Approval-gated write tools

| Tool | Access | What it does |
| --- | --- | --- |
| `submit_ioc_with_approval(...)` | approval-gated write | Add an attribute to an event. |
| `add_sighting_with_approval(...)` | approval-gated write | Record a sighting. |
| `tag_event_with_approval(...)` | approval-gated write | Tag an event. |
| `publish_event_with_approval(...)` | approval-gated write | Publish an event (curator/admin roles only). |

Write-tool results are explicit: `blocked`, `invalid`, `pending_approval`, `executed`, or
`failed` (MISP itself rejected the write). There are no silent writes. See
[`docs/approval-flow.md`](docs/approval-flow.md).

## Quick start

Prerequisites: Python 3.11+ and [`uv`](https://docs.astral.sh/uv/) (or Docker — see
[Docker](#docker)), a reachable MISP instance, and a MISP API key.

```bash
# 1. Clone and install
git clone https://github.com/hdyrawan/agentic-misp-mcp.git
cd agentic-misp-mcp
uv sync --extra dev

# 2. Configure (at minimum MISP_URL and MISP_API_KEY)
cp .env.example .env
# edit .env

# 3. Validate configuration (no MISP connection is made; the API key is redacted)
uv run agentic-misp-mcp config-check

# 4. Run the test suite
uv run --extra dev pytest -q

# 5. Start the MCP server over stdio (the primary supported transport)
uv run agentic-misp-mcp --transport stdio
```

Then:

6. **Connect an MCP client** — see [MCP client examples](#mcp-client-examples) below.
7. **Run a first read-only tool** — `get_misp_status` is a good zero-risk smoke test; it
   confirms connectivity and reports the MISP version.
8. **Review the audit output**:

   ```bash
   tail -n 20 logs/audit.jsonl | jq .
   ```

A good first-five sequence for a new operator, all read-only: `get_misp_status` →
`check_warninglists` → `investigate_ioc` → `search_events` → `summarize_feed_health`.

### Docker

```bash
docker build -t agentic-misp-mcp:local .

# keep the env file outside the repository; never commit real credentials
mkdir -p /path/to/runtime/logs
cp .env.example /path/to/runtime/.env   # edit it

docker run --rm --env-file /path/to/runtime/.env \
  -v /path/to/runtime/logs:/app/logs \
  agentic-misp-mcp:local config-check

docker run --rm -i --env-file /path/to/runtime/.env \
  -v /path/to/runtime/logs:/app/logs \
  agentic-misp-mcp:local --transport stdio
```

Prefer Compose? See `docker-compose.example.yml` and
[`docs/configuration.md`](docs/configuration.md#docker-compose).

## Configuration

All configuration is via environment variables (or an `.env` file). Placeholders below are
fake — never commit real credentials.

### Required

| Variable | Example | Notes |
| --- | --- | --- |
| `MISP_URL` | `https://misp.example.local` | Base URL of your MISP instance. |
| `MISP_API_KEY` | `your_misp_api_key_here` | Runtime-only automation key. Loaded from the environment only; never passed as a tool argument. |

### Connection and output bounds (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `MISP_VERIFY_TLS` | `true` | **Keep `true` in production.** `false` is for isolated labs with self-signed certificates only — prefer adding your internal CA to the trust store instead. |
| `MISP_TIMEOUT_SECONDS` | `30` | HTTP timeout, > 0 and <= 300. |
| `MISP_DEFAULT_LIMIT` | `20` | Default result limit. |
| `MISP_MAX_LIMIT` | `100` | Maximum accepted result limit. |
| `MISP_EVENT_ATTRIBUTE_LIMIT` | `50` | Attribute cap for event summaries/investigations. |
| `MISP_RELATED_EVENT_LIMIT` | `5` | Related-event expansion cap. |
| `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` | `5242880` | Max MISP HTTP response body size, enforced (fail-closed) before JSON parsing. |

### Safety and policy (optional)

| Variable | Default | Notes |
| --- | --- | --- |
| `AGENTIC_MISP_MCP_ROLE` | `read_only` | `read_only`, `analyst_write`, `curator`, or `admin` — see [`docs/roles.md`](docs/roles.md). |
| `AGENTIC_MISP_MCP_ENABLE_WRITE` | `false` | Global write-mode gate. Leave `false` unless you need writes. |
| `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` | `true` | Lab-mode gate requiring explicit `approved=true`; production mode requires an `approval_request_id` regardless. |
| `AGENTIC_MISP_MCP_APPROVAL_MODE` | `lab` | `lab` = programmatic `approved=true` flow; `production` = persisted, operator-approved, one-time-use request IDs. |
| `AGENTIC_MISP_MCP_APPROVAL_TOKEN` | unset | Optional lab shared-secret hardening; redacted in audit logs. Not the production approval mechanism. |
| `AGENTIC_MISP_MCP_APPROVAL_STORE_PATH` | `./approvals.sqlite3` | SQLite store for production approvals. The agent must not have write access to it. Persist it. |
| `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS` | `900` | Production approval lifetime. |
| `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES` | unset | Production guardrail: allowlist of submittable attribute types. |
| `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES` | unset | Production guardrail: allowlist of attribute categories. |
| `AGENTIC_MISP_MCP_ALLOWED_TAGS` | unset | Production guardrail: allowlist of event tags (`*` suffix = prefix match). |
| `AGENTIC_MISP_MCP_ENABLE_PUBLISH` | `false` | Dedicated publish kill switch; publish also requires curator/admin role and approval. |
| `AGENTIC_MISP_MCP_AUDIT_LOG_PATH` | `./logs/audit.jsonl` | JSONL audit log path. Persist it (mount a volume under Docker). |
| `AGENTIC_MISP_MCP_LOG_LEVEL` | `INFO` | Application log level. |
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | `false` | Experimental HTTP transport refuses non-loopback binds unless this is set. Keep `false`. |

### Age-aware scoring and feed freshness (optional, v0.3.0+)

| Variable | Default | Notes |
| --- | --- | --- |
| `AGENTIC_MISP_MCP_AGE_WEIGHTING` | `true` | Age-aware IOC scoring. `false` reproduces v0.2.x scoring exactly (the `freshness` block is emitted either way). |
| `AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS` | `30` | Newest signal at or below this age is `fresh`. |
| `AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS` | `90` | Upper bound for `aging`. |
| `AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS` | `365` | Upper bound for `stale`; older is `expired`. |
| `AGENTIC_MISP_MCP_AGE_WEIGHTS` | `1.0,0.75,0.4,0.15` | Score multipliers for fresh/aging/stale/expired, each 0–1. |
| `AGENTIC_MISP_MCP_FEED_FRESH_DAYS` | `7` | Feed fetch/cache age at or below this is fresh. |
| `AGENTIC_MISP_MCP_FEED_STALE_DAYS` | `30` | Feed fetch/cache age above this is stale. |

Full reference and examples: [`docs/configuration.md`](docs/configuration.md). Before any
production run, also use the deeper check:

```bash
uv run agentic-misp-mcp config doctor
```

It validates write/approval-mode pairing, approval-store and audit-log permission safety,
allowlist coverage, and more — without connecting to MISP or printing secrets.

## MCP client examples

All examples use the stdio transport (the primary supported transport) and generic paths —
replace `/path/to/agentic-misp-mcp` with your checkout (e.g. `/home/user/agentic-misp-mcp` or
`/opt/agentic-misp-mcp`).

### MCP Inspector (smoke testing)

```bash
npx @modelcontextprotocol/inspector \
  uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp --transport stdio
```

Headless/CI mode (no browser):

```bash
npx -y @modelcontextprotocol/inspector --cli \
  uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp \
  --method tools/list
```

On a headless host, either use `--cli` mode or forward the Inspector UI ports over SSH:
`ssh -L 6274:localhost:6274 -L 6277:localhost:6277 user@mcp-host.example.local`.

### Claude Code

```bash
claude mcp add agentic-misp-mcp -s local -- \
  uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp --transport stdio
```

Verify with `claude mcp list` (should show `✔ Connected`), then start a **new** Claude Code
session — tools appear in sessions started after the `add`. Remove with
`claude mcp remove agentic-misp-mcp -s local`. Avoid `-s project` unless every teammate has the
same paths, since it writes a shared `.mcp.json` verbatim.

### Claude Desktop

Add to `claude_desktop_config.json`:

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

Prefer `--env-file`/OS-level secrets over inlining the key when your client supports it, and
never commit a client config containing a real key.

### Hermes Agent

```bash
hermes mcp add agentic-misp-mcp \
  --command uv \
  --args --directory /path/to/agentic-misp-mcp run agentic-misp-mcp --transport stdio
```

Hermes performs a live discovery handshake and prompts to enable tools — answer `y` for all 25,
or use `select` to enable a read-only subset (everything except the four `_with_approval` and
two `propose_*` tools). Verify with `hermes mcp list` / `hermes mcp test agentic-misp-mcp`,
then start a new Hermes session.

### OpenCode (or similar local agent CLIs)

```json
{
  "mcp": {
    "agentic-misp-mcp": {
      "type": "local",
      "command": [
        "uv", "--directory", "/path/to/agentic-misp-mcp",
        "run", "agentic-misp-mcp", "--transport", "stdio"
      ],
      "environment": {
        "MISP_URL": "https://misp.example.local",
        "MISP_API_KEY": "your_misp_api_key_here"
      }
    }
  }
}
```

Any MCP client that can spawn a stdio subprocess works the same way: run
`uv --directory /path/to/agentic-misp-mcp run agentic-misp-mcp --transport stdio` (or the
`docker run --rm -i ... --transport stdio` equivalent from [Docker](#docker)).

**Transport note:** stdio is the recommended production transport. The HTTP transport is
experimental, has no built-in auth or TLS, and refuses to bind a non-loopback host unless
`AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true`; if you must use it, put it behind an
authenticated TLS-terminating gateway.

## Production checklist

Before pointing agents at a production MISP:

- [ ] Create a **dedicated least-privilege MISP API key** for this server (not a personal or
      site-admin key).
- [ ] Keep `AGENTIC_MISP_MCP_ROLE=read_only` and `AGENTIC_MISP_MCP_ENABLE_WRITE=false` for
      normal agent use; enable writes only when a workflow genuinely needs them.
- [ ] If writes are enabled, use `AGENTIC_MISP_MCP_APPROVAL_MODE=production` and keep the
      approval CLI and approval database out of the agent's reach.
- [ ] **Persist audit logs** (`AGENTIC_MISP_MCP_AUDIT_LOG_PATH`; mount a volume under Docker).
- [ ] **Persist the approval store** (`AGENTIC_MISP_MCP_APPROVAL_STORE_PATH`).
- [ ] Protect `MISP_API_KEY` — environment/secrets manager only; keep `.env` files out of git
      and out of client configs that get shared.
- [ ] Keep `MISP_VERIFY_TLS=true`; fix certificate problems with your internal CA, don't
      disable verification.
- [ ] Run `agentic-misp-mcp config-check` and `agentic-misp-mcp config doctor` after every
      config change.
- [ ] Run the test suite (`uv run --extra dev pytest -q`) on the deployed revision.
- [ ] Smoke test with MCP Inspector (`tools/list`, then `get_misp_status`).
- [ ] Review `audit.jsonl` after the first real tool calls, and periodically thereafter
      (manual audit review is the accepted control — there is no built-in alerting).
- [ ] Keep feed administration (enable/fetch/cache) in the MISP UI/API, outside MCP.

Deeper guidance: [`docs/production-readiness.md`](docs/production-readiness.md),
[`docs/production-write.md`](docs/production-write.md),
[`docs/rollback.md`](docs/rollback.md).

## Safety boundaries

These are design boundaries, enforced in code and preserved across releases:

- **No raw MISP API proxy.** Only the 25 workflow tools exist; there is no generic
  endpoint-passthrough tool.
- **No feed mutation.** No feed enable/disable/fetch/cache/edit/delete tools exist. Feed
  observability (`list_feeds`, `get_feed_status`, `summarize_feed_health`) is strictly
  read-only, with URLs and header/token-like fields redacted.
- **No approval-store exposure.** No MCP tool can create, approve, reject, or read approval
  records; production approvals happen only through the operator CLI.
- **No ungated writes.** Every write path goes through role policy, the write-mode gate, and
  the approval gate; results are explicit (`blocked`/`pending_approval`/`executed`/`failed`).
- **No hidden mutation in read tools.** Read tools call read endpoints only.
- **`propose_*` tools are dry-run only.** They build and validate payloads; they never invoke
  a MISP write endpoint.
- **No secret passthrough.** API keys, tokens, passwords, and authorization headers are never
  accepted as tool arguments and are redacted from audit logs.
- No shell execution or unrestricted filesystem tools; no user/org/server/settings admin tools.

See [`docs/security.md`](docs/security.md) for the full security model and audit semantics.

## Scoring behavior

Since `v0.3.0`, IOC scoring is **age-aware by default**. `investigate_ioc`,
`generate_ioc_report`, and `pivot_ioc` responses include a `freshness` block that labels the
intel behind a verdict:

| Label | Meaning (defaults) |
| --- | --- |
| `fresh` | Newest signal ≤ 30 days old. |
| `aging` | 31–90 days. |
| `stale` | 91–365 days. |
| `expired` | Older than 365 days. |
| `unknown` | No usable timestamps found. |

How it affects scores:

- **Old intel scores lower by default.** Positive score factors are discounted by intel age
  (default weights `1.0 / 0.75 / 0.4 / 0.15` for fresh/aging/stale/expired).
- **Penalties are never age-discounted.** Warninglist hits and benign-tag penalties apply at
  full strength regardless of age.
- **Expired intel cannot become `likely_malicious`** on its own — expired-only intel is capped
  below that threshold and needs fresh corroboration to cross it.
- **`AGENTIC_MISP_MCP_AGE_WEIGHTING=false`** restores exact v0.2.x scoring (the `freshness`
  block is still reported).

This is a confidence-quality improvement, not a replacement for analyst judgment: a `fresh`
hit on a 10-year-old OSINT event that was recently re-published still deserves human
correlation with current telemetry before blocking or escalation.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Connection error, `MISPClientError` | Wrong `MISP_URL`, or MISP unreachable from where the server runs | Verify the URL (scheme + host, no trailing API path); test `curl https://misp.example.local/servers/getVersion -H "Authorization: <key>"` from the same host/container. |
| Authentication error, `MISPAuthenticationError` | Invalid or revoked `MISP_API_KEY` | Regenerate the automation key in MISP; confirm the env var actually reaches the process (`config-check` shows whether it is set, redacted). |
| TLS verification failure | Self-signed or internal-CA certificate | Add the CA to the system trust store. `MISP_VERIFY_TLS=false` is an isolated-lab escape hatch only — never production. |
| MISP returns permission denied | The API key's MISP role lacks the needed permission | Grant the minimal MISP permission the workflow needs (e.g. sighting creation for sightings), keeping the key least-privilege. |
| Tool returns `blocked` | Policy working as intended: role or write-mode gate | Check `AGENTIC_MISP_MCP_ROLE` and `AGENTIC_MISP_MCP_ENABLE_WRITE`. The audit log records `outcome=blocked` with the reason. |
| Write returns `pending_approval` | Approval required (the default) | Lab mode: re-call with `approved=true` (plus `approval_token` if configured). Production mode: an operator must approve via `agentic-misp-mcp approvals ...` and the call must present the resulting `approval_request_id`. |
| `config-check` fails on audit path | Audit log directory missing or not writable | Create the directory / fix permissions; under Docker, mount a writable volume at the audit path. |
| Approvals disappear after restart | Approval DB not persisted | Point `AGENTIC_MISP_MCP_APPROVAL_STORE_PATH` at persistent storage (Docker: a mounted volume). |
| "Response too large" error | MISP response exceeded `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` (fail-closed by design) | Narrow the query (smaller `limit`, tighter date range). Raising the cap is a last resort. |
| MCP client can't spawn the server | Wrong command/path in the client config | Use absolute paths (`uv --directory /path/to/agentic-misp-mcp ...`); test the exact command in a terminal first; restart the client session after registering. |
| Import errors / wrong Python | Wrong environment or Python < 3.11 | Use `uv run` (which pins the project env), or re-run `uv sync --extra dev`; check `python --version` ≥ 3.11. |

## Release status

- **Latest release:** `v0.3.1` — documentation/operator-readability patch on `v0.3.0`
  (no MCP tool, scoring, or write-surface changes). See [`CHANGELOG.md`](CHANGELOG.md).
- **Functional baseline:** `v0.3.0` — age-aware scoring, six new read-only tools (sightings,
  event search, status, feed observability), read-tool response envelope.
- **Supported MISP baseline:** `2.5.42`, live-validated 14/14 —
  [`docs/live-validation-report-v0.3.0.md`](docs/live-validation-report-v0.3.0.md).
- **Latest pre-merge review findings:**
  [`docs/review-v0.3.0-findings.md`](docs/review-v0.3.0-findings.md).
- **Tool count:** 25. **Tests:** 353 (mocked MISP responses; live validation is a separate
  manual pass).
- **Scope of the production claim:** `v0.2.0` was declared GA **for the MCP-server scope of
  this project only** (server behavior, MISP API behavior, approval workflow, audit/redaction,
  config safety) — not a SIEM/SOAR/SOC platform claim. `v0.3.x` extends that same scope. See
  [`docs/ga-production-readiness-plan.md`](docs/ga-production-readiness-plan.md).
- **Known limitations:** only MISP `2.5.42` is validated; a live HTTP `429` has mocked coverage
  only (no safe way to trigger one in the lab); container/dependency/secret scanning and signed
  release artifacts are not yet part of CI/release; HTTP transport is experimental; historical
  OSINT hits should be correlated with current telemetry (mitigated but not removed by
  age-aware scoring).

## Development

```bash
uv run --extra dev ruff check .
uv run --extra dev ruff format --check .
uv run --extra dev pytest -q
```

Equivalent Make targets: `make lint`, `make format-check`, `make test`, `make check`.
CI runs the same checks on Python 3.11 and 3.12.

## Documentation

- [`docs/configuration.md`](docs/configuration.md) — full environment-variable reference,
  Docker/Compose, client config shapes, `config doctor`.
- [`docs/security.md`](docs/security.md) — security model, tool boundary, audit semantics.
- [`docs/roles.md`](docs/roles.md) — role policy matrix.
- [`docs/approval-flow.md`](docs/approval-flow.md) — lab and production approval flows.
- [`docs/production-write.md`](docs/production-write.md) — production write deployment guidance.
- [`docs/production-readiness.md`](docs/production-readiness.md) — the broader readiness
  checklist and what it still requires.
- [`docs/feed-observability.md`](docs/feed-observability.md) — feed tools and the feed safety
  boundary.
- [`docs/testing.md`](docs/testing.md) — what the mocked suite covers.
- [`docs/misp-compatibility.md`](docs/misp-compatibility.md) — MISP version matrix.
- [`docs/live-validation-report-v0.3.0.md`](docs/live-validation-report-v0.3.0.md) — latest
  live validation evidence (earlier reports live alongside it in `docs/`).
- [`docs/rollback.md`](docs/rollback.md) — rollback playbook for a mistaken controlled write.

## Contributing

Contributions are welcome, but keep the project boundary intact: no raw API proxy, no secret
passthrough, no unaudited tool path, and no write behavior without policy and approval gates.
Start with `PROJECT_STATE.md`, [`docs/security.md`](docs/security.md), and
`src/agentic_misp_mcp/tools/registry.py`.

Commits should be attributed to their human author only — do not add AI co-author trailers
(for example `Co-Authored-By: <AI assistant>`) to commits in this repository, regardless of
what tooling was used to help write them.

## License

MIT.
