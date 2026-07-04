# Security model

This project is intentionally read-only, workflow-first, and in early development. It has not
been validated against a live MISP instance and should not be treated as production-ready.

## Read-only boundary

The server does not implement event creation, attribute creation, sighting submission, tagging, publishing, raw MISP API proxying, write/admin tools, shell execution, or unrestricted filesystem access.

## Policy and approval foundation

Phase 7 adds policy enforcement primitives for future controlled-write workflows without adding
write/admin MCP tools. The runtime policy environment variables are:

- `AGENTIC_MISP_MCP_ROLE=read_only` by default. Supported roles are `read_only`,
  `analyst_write`, `curator`, and `admin`.
- `AGENTIC_MISP_MCP_ENABLE_WRITE=false` by default. With write mode disabled, all future
  `write`, `admin`, `sync`, and `dangerous` actions are blocked even for elevated roles.
- `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` by default. Future role-allowed write/admin/sync
  actions require approval when this is enabled.

The current 13 tools are classified as `read` and remain allowed under `read_only`. Approval
request data models exist only as an in-memory foundation; Phase 7 does not add persistent
approval storage and cannot execute approved writes.

## MCP tool boundary

Only these tools are exposed:

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

All tools must be registered through `tools/registry.py` and audited through the shared audit wrapper.

## Credential handling

`MISP_API_KEY` must come from the environment. It is injected into HTTP headers by the MISP client and must never be accepted as a tool argument, logged, or returned in errors.

Use `agentic-misp-mcp config-check` to validate that `MISP_API_KEY` is present. The command
redacts the key and does not connect to MISP.

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
endpoint as an MCP tool, and does not change the current read-only tool boundary above. See
`docs/openapi-inventory.md` for a generated sample.

## Warninglist behavior

MISP warninglist endpoint behavior can vary between deployments and versions. This project isolates this logic in `misp/warninglists.py`. If the warninglist check is unavailable or the response shape is not recognized, the tool returns a structured `not_available` state rather than pretending the check succeeded.
