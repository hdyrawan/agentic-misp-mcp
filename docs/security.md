# Security model

This MIT-licensed project is intentionally workflow-first and in early development. It has not been
validated against a live MISP instance and should not be treated as production-ready.

## Read-only by default; controlled write behind policy and approval

The server ships read-only by default. Phase 8 adds exactly six controlled, policy-gated write
tools (see below); no raw MISP API proxying, generic admin tools, shell execution, or
unrestricted filesystem access are implemented, and none are planned.

This boundary is part of the MCP security model for the project: tools expose analyst workflows,
not arbitrary MISP endpoints or host capabilities. Tool registration is centralized in
`src/agentic_misp_mcp/tools/registry.py`, and each registered tool must go through the shared
audit wrapper.

## Policy and approval enforcement

Phase 7 added policy enforcement primitives; Phase 8 wires them into real, gated write
workflows. The runtime policy environment variables are:

- `AGENTIC_MISP_MCP_ROLE=read_only` by default. Supported roles are `read_only`,
  `analyst_write`, `curator`, and `admin`.
- `AGENTIC_MISP_MCP_ENABLE_WRITE=false` by default. With write mode disabled, all `write` and
  `publish` actions are blocked even for elevated roles, and `admin`/`dangerous` actions remain
  unavailable regardless of this setting (no tool uses those action categories).
- `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` by default. Role-allowed write/publish actions
  require explicit approval when this is enabled.

The original 13 read tools are classified as `read` and remain allowed under `read_only`.

### Write tool behavior

- `propose_event` and `propose_attribute` build a MISP event/attribute creation payload and
  **never** write to MISP. They return the proposed payload, a risk level, the required role,
  and whether approval would be required, plus a `blocked` status if the current
  role/write-mode does not even allow proposing the write.
- `submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, and
  `publish_event_with_approval` each accept an `approved: bool = False` argument (explicit
  approval input). Each call returns one of:
  - `blocked` — write mode disabled, or role does not permit the action. No MISP call is made.
  - `pending_approval` — role permits the action but approval is required and `approved` was
    not set. Returns a sanitized `ApprovalRequest` proposal. No MISP call is made.
  - `executed` — role permits the action and (approval not required, or `approved=True` was
    explicitly passed). Only in this branch is the corresponding MISP write method called.
- `publish_event_with_approval` uses a dedicated `publish` policy action restricted to
  `curator`/`admin` roles, is always classified `high` risk, and is always approval-gated when
  `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`.
- No write ever happens silently: every branch above (including `blocked`) is audited, and only
  the `executed` branch invokes a MISP write method (`create_event`, `add_attribute`,
  `add_sighting`, `tag_event`, `publish_event` in `misp/client.py`). There is no generic request
  proxy — each write tool maps to exactly one narrow MISP write method.

## MCP tool boundary

Nineteen tools are exposed. The original 13 read-only tools:

- `search_ioc`
- `investigate_ioc`
- `summarize_event`
- `check_warninglists`
- `generate_ioc_report`
- `pivot_ioc`
- `find_related_iocs`
- `extract_event_iocs`
- `explain_event_context`
- `find_events_by_tag`
- `generate_event_report`
- `generate_markdown_ioc_report`
- `generate_markdown_event_report`

Plus six Phase 8 controlled write tools:

- `propose_event`
- `propose_attribute`
- `submit_ioc_with_approval`
- `add_sighting_with_approval`
- `tag_event_with_approval`
- `publish_event_with_approval`

All tools must be registered through `tools/registry.py` and audited through the shared audit
wrapper. There is no raw MISP API proxy tool, and no user/organisation/server/settings-style
admin tools exist.

## Credential handling

`MISP_API_KEY` must come from the environment. It is injected into HTTP headers by the MISP client and must never be accepted as a tool argument, logged, or returned in errors.

Use `agentic-misp-mcp config-check` to validate that `MISP_API_KEY` is present. The command
redacts the key and does not connect to MISP.

MCP tool schemas must not include API key, token, password, authorization header, or other
credential parameters. Do not use a tool call as a token passthrough mechanism; rotate any real
secret that is accidentally sent in a prompt, issue, test fixture, audit log, or CI log.

## TLS

TLS verification is enabled by default with `MISP_VERIFY_TLS=true`. Disabling TLS verification is unsafe for production.

## Audit logging

Every MCP tool call writes one JSONL audit record, including failures. Audit records include tool name, sanitized arguments, policy decision fields, status, duration, and error type/message. They do not include authorization headers or API keys.

The audit log path is validated at startup. Its parent directory must already be writable or be
creatable by the runtime user. Container examples mount `./logs` into `/app/logs` so logs persist
without baking secrets or runtime state into the image.

## Runtime and deployment safety

- Run `agentic-misp-mcp config-check` before starting the server.
- Keep `.env` files out of git and pass them only at runtime.
- The Docker image runs as a non-root user.
- The Docker image exposes port `8000` only for optional experimental HTTP mode; stdio remains the
  primary supported transport.
- Do not bake `MISP_URL` or `MISP_API_KEY` into Dockerfiles, images, or committed config.
- Treat HTTP transport as experimental. If enabled, bind it only on a trusted interface or place it
  behind an authenticated, TLS-terminating gateway. Do not expose it directly to the internet.

## Output limits

All event- and IOC-oriented tools (`investigate_ioc`, `summarize_event`, `pivot_ioc`,
`find_related_iocs`, `extract_event_iocs`, `explain_event_context`, `find_events_by_tag`,
`generate_ioc_report`, `generate_event_report`, `generate_markdown_ioc_report`,
`generate_markdown_event_report`) summarize MISP data and do not return full raw MISP event
JSON. They respect `MISP_EVENT_ATTRIBUTE_LIMIT` and `MISP_RELATED_EVENT_LIMIT`, and each tool's
own `limit` argument. The two Markdown report tools return deterministic, bounded text — no
LLM call is made to generate them.

## OpenAPI inventory (planning only)

`agentic-misp-mcp openapi-inventory` classifies endpoints from a MISP OpenAPI spec into
`read`/`write`/`admin`/`sync`/`dangerous`/`unknown` categories with a risk level and
recommended role, to help plan future controlled-write work. It is a local, offline,
read-only-of-the-spec-file operation: it does not call MISP, does not expose any MISP API
endpoint as an MCP tool, and does not change the tool boundary above. See
`docs/openapi-inventory.md` for a generated sample.

## Warninglist behavior

MISP warninglist endpoint behavior can vary between deployments and versions. This project isolates this logic in `misp/warninglists.py`. If the warninglist check is unavailable or the response shape is not recognized, the tool returns a structured `not_available` state rather than pretending the check succeeded.
