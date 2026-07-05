# Testing

`agentic-misp-mcp`'s automated test suite uses **mocked MISP responses**. No test in this repository
calls a live MISP instance, and none should be added without going through the live lab
validation phase described in [`docs/live-validation-plan.md`](live-validation-plan.md).

This document exists so reviewers and contributors can see exactly what the mocked suite does
and does not cover, without having to read every test file.

## How mocking works

`tests/test_misp_client.py` uses `httpx.MockTransport` to intercept requests made by
`MISPClient` (`src/agentic_misp_mcp/misp/client.py`) and return canned JSON responses. Every
other workflow/tool test uses a hand-written fake client class (`FakeClient` /
`FakeWriteClient`) that implements the same async method signatures as `MISPClient` and returns
already-parsed model instances, so those tests exercise workflow and policy logic without going
through HTTP at all.

## Mocked MISP-like endpoints

These are the only MISP HTTP endpoints exercised anywhere in the test suite, all in
`tests/test_misp_client.py`:

| Endpoint | Method | Client method | Covered response shapes |
| --- | --- | --- | --- |
| `/attributes/restSearch` | POST | `search_attributes` | `{"response": [{"Attribute": {...}}]}` with `Tag` list |
| `/events/view/{id}` | GET | `get_event` | `{"Event": {..., "Attribute": [...]}}`, attribute-limit truncation |
| `/events/restSearch` | POST | `search_events_by_tag` | `{"response": [{"Event": {..., "Tag": [...]}}]}` |
| `/warninglists/checkValue` | POST | `check_warninglists` | 404 → `not_available` fallback |
| `/attributes/add/{event_id}` | POST | `add_attribute` | `{"Attribute": {...}}` |
| `/sightings/add` | POST | `add_sighting` | `{"Sighting": {...}}` |
| `/events/addTag/{event_id}` | POST | `tag_event` | `{"saved": true, "message": "..."}` |
| `/events/publish/{event_id}` | POST | `publish_event` | `{"name": "...", "message": "..."}` (no `errors` key) |

HTTP error normalization covered:

- `401` / `403` → `MISPAuthenticationError` (`test_auth_error_normalized`)
- `404` → `MISPNotFoundError` (`test_not_found_normalized`), and a dedicated `not_available`
  fallback for the warninglist endpoint specifically (`test_warninglist_not_available_on_404`)

Request bodies and the `Authorization` header are asserted on for the search,
add-attribute, and tag-event cases, confirming the API key is sent as a header and never leaks
into the request body or a logged value.

## Workflows and tools tested with mocks

Every read-only workflow has a dedicated test module under `tests/workflows/`:

- `test_search_ioc.py`, `test_investigate_ioc.py`, `test_summarize_event.py`,
  `test_check_warninglists.py`
- `test_pivot_ioc.py`, `test_find_related_iocs.py`, `test_extract_event_iocs.py`,
  `test_explain_event_context.py`, `test_find_events_by_tag.py`
- `test_generate_ioc_report.py`, `test_generate_event_report.py`,
  `test_generate_markdown_ioc_report.py`, `test_generate_markdown_event_report.py`

The six controlled write workflows are unit-tested directly against
`src/agentic_misp_mcp/workflows/controlled_write.py` in `tests/workflows/test_controlled_write.py`,
using hand-constructed `PolicyDecision` values to exercise `blocked` / `proposal` /
`pending_approval` / `executed` branches for each tool without depending on the registry.

At the MCP tool boundary:

- `tests/test_tools_contract.py` registers all 25 tools against a fake MCP object and asserts
  the exact tool set, the audit record shape for a read tool, and that no raw-proxy or
  user/organisation/server/settings-style admin tool name exists.
- `tests/test_controlled_write_tools.py` drives the six write tools end-to-end through
  `register_tools`, covering: default `read_only` blocks all six; write mode disabled blocks
  even an `admin`-role caller; `analyst_write` can propose and can only submit with
  `approved=true`; `curator`/`admin` can only publish with `approved=true`;
  `analyst_write` cannot publish; a `pending_approval` response is returned when approval is
  missing; the mocked MISP write method is only called once `approved=true` and policy allows
  it; and no secret (`MISP_API_KEY`) ever appears in the audit log.
- `tests/test_policy.py` unit-tests `PolicyEngine.decide()` directly for every `Action`
  (`read`, `write`, `publish`, `admin`, `sync`, `dangerous`) across all four roles, including
  write-mode-disabled and dangerous-action-always-blocked cases.
- `tests/test_audit.py` covers successful and failing audit records, including secret
  redaction.
- `tests/test_cli.py` covers `--help`, `--version`, transport validation, `config-check`
  (including that it never prints the API key), and `openapi-inventory`.
- `tests/test_settings.py` covers environment parsing defaults, a missing API key, and limit
  clamping.
- `tests/openapi/` covers the OpenAPI endpoint classifier and inventory report generation.

Run the full suite with:

```bash
uv run --extra dev pytest -q
```

## What is not covered yet

The following are known gaps in the mocked suite, called out explicitly rather than left
implicit:

- **Rate limiting.** `MISPRateLimitError` (HTTP `429`) is implemented in `misp/client.py` but
  has no dedicated mocked test.
- **Malformed/non-JSON responses.** The `MISPClientError("MISP returned non-JSON response")`
  path is not exercised by a mocked test.
- **Timeouts.** `httpx.TimeoutException` and other transport-level failures are not simulated;
  only `httpx.HTTPError` is asserted to map to `MISPClientError` conceptually via existing tests.
- **Large/paginated results.** Tests use small, hand-built fixtures (a handful of attributes or
  events). Behavior at realistic scale — thousands of attributes on one event, results near
  `MISP_MAX_LIMIT` — is not exercised.
- **MISP version/shape drift.** Only one canonical response shape per endpoint is mocked.
  Real MISP deployments vary in Galaxy/Object nesting, tag formats, and optional fields; this is
  called out as a known limitation in `docs/security.md` and `CHANGELOG.md`.
- **Concurrent/parallel tool calls.** The audit logger's file-append lock is not
  stress-tested under concurrent writers.
- **HTTP transport end-to-end behavior.** The experimental `--transport http` path is not
  covered by an end-to-end test; only the CLI argument validation is tested.
- **Approval persistence across calls.** The `approved` argument is checked per-call; there is
  no test (or implementation) of a persisted approval store, multi-approver workflow, or
  approval expiry, because none of that exists yet. See
  [`docs/approval-flow.md`](approval-flow.md) for the current, intentionally simple contract.

## Live MISP validation: read-only and core controlled-write passed, edge cases pending

Separately from this mocked suite, `agentic-misp-mcp` has also been run against a real,
non-production MISP lab (`2.5.42`) via MCP Inspector. Live read-only tools, policy-blocking
behavior, and the four core controlled-write tools (`submit_ioc_with_approval`,
`add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval`) have all
passed, including two real bugs found and fixed during that pass (a blank approval-token
handling bug, and a silent tag/publish failure that used to report `status: "executed"` even
when MISP rejected the write). See `README.md`'s "Live lab validation status" table for the full
evidence summary.

This live validation is still narrower than the gaps listed above, though — none of the following
have been exercised against a real MISP instance yet, and are tracked in
[`docs/live-validation-plan.md`](live-validation-plan.md):

- Rate limiting (`429`), and real request timeouts.
- TLS behavior against an untrusted certificate with `MISP_VERIFY_TLS=true` (should fail closed).
- Large/paginated results at realistic scale (an event with attributes well above
  `MISP_EVENT_ATTRIBUTE_LIMIT`, a search near `MISP_MAX_LIMIT`).
- Warninglist endpoint compatibility across MISP versions, and the warninglist
  hit/miss/`not_available` structured-result behavior specifically.
- `propose_event`/`propose_attribute` payload-shape validation against a real MISP `/events/add`
  and `/attributes/add/{event_id}`.
- MISP version/shape drift beyond `2.5.42`.
- Final sign-off (`docs/live-validation-plan.md` section 9).

Live-lab evidence is not a substitute for the mocked suite or for production certification — see
[`docs/production-readiness.md`](production-readiness.md) for what remains before this project is
considered production-ready.
