# Security model

This project is intentionally read-only, workflow-first, and in early development. It has not
been validated against a live MISP instance and should not be treated as production-ready.

## Read-only boundary

The server does not implement event creation, attribute creation, sighting submission, tagging, publishing, raw MISP API proxying, write/admin tools, shell execution, or unrestricted filesystem access.

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

## TLS

TLS verification is enabled by default with `MISP_VERIFY_TLS=true`. Disabling TLS verification is unsafe for production.

## Audit logging

Every MCP tool call writes one JSONL audit record, including failures. Audit records include tool name, sanitized arguments, status, duration, and error type/message. They do not include authorization headers or API keys.

## Output limits

All event- and IOC-oriented tools (`investigate_ioc`, `summarize_event`, `pivot_ioc`,
`find_related_iocs`, `extract_event_iocs`, `explain_event_context`, `find_events_by_tag`,
`generate_ioc_report`, `generate_event_report`, `generate_markdown_ioc_report`,
`generate_markdown_event_report`) summarize MISP data and do not return full raw MISP event
JSON. They respect `MISP_EVENT_ATTRIBUTE_LIMIT` and `MISP_RELATED_EVENT_LIMIT`, and each tool's
own `limit` argument. The two Markdown report tools return deterministic, bounded text — no
LLM call is made to generate them.

## Warninglist behavior

MISP warninglist endpoint behavior can vary between deployments and versions. This project isolates this logic in `misp/warninglists.py`. If the warninglist check is unavailable or the response shape is not recognized, the tool returns a structured `not_available` state rather than pretending the check succeeded.
