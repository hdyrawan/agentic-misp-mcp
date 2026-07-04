# Live beta validation checklist — v0.2.0-beta.1

`main` contains the `v0.2.0-beta.1` production-write beta candidate. This checklist is the live validation evidence to complete before tagging `v0.2.0-beta.1`.

Status target: **production-write beta suitable for isolated pilot validation only**. Passing this checklist does **not** make the project GA production-ready.

## Ground rules

- Use an isolated non-production MISP instance or an explicitly approved pilot MISP scope.
- Use scoped test data and a dedicated sandbox event for all write checks.
- Do not add new MISP write capabilities, raw proxy behavior, admin tools, or approval-administration MCP tools during validation.
- Keep lab mode available and backward compatible, but do not treat `approved=true` alone as production-safe.
- Treat `approval_token` only as optional lab/shared-secret behavior. Production approval uses CLI-approved `approval_request_id` records.
- Capture command/config snippets, timestamps, MISP version, tool responses, and sanitized audit-log excerpts for release notes.
- Do not include `MISP_API_KEY`, `approval_token`, bearer tokens, cookies, authorization headers, or other secrets in evidence.

## Environment matrix

Record one row per environment used.

| Item | Value |
| --- | --- |
| Date/time | TBD |
| Validator | TBD |
| Git commit | TBD |
| Package version | `0.2.0-beta.1` |
| MISP version | TBD |
| Deployment shape | local / Docker stdio / other |
| Role | read_only / analyst_write / curator / admin |
| Approval mode | lab / production |
| Write enabled | true / false |
| Publish enabled | true / false |
| Audit log path | sanitized path |
| Approval DB path | sanitized path |

## 1. Read-only validation checks

Use `AGENTIC_MISP_MCP_ROLE=read_only` and `AGENTIC_MISP_MCP_ENABLE_WRITE=false` unless a check explicitly says otherwise.

| Check | Required evidence | Status |
| --- | --- | --- |
| TLS fail-closed with `MISP_VERIFY_TLS=true` | Connect to a MISP endpoint with an untrusted/self-signed cert and confirm the call fails closed; audit outcome is `error`; no fallback to insecure TLS. | [ ] |
| Invalid/revoked API key | Confirm clean authentication failure; no key echoed in tool response or audit log. | [ ] |
| Timeout behavior | Use a slow/unresponsive endpoint or controlled network delay; confirm bounded wait, clear timeout error, and audit `outcome=error`. | [ ] |
| Rate-limit / HTTP 429 behavior, if feasible | Trigger or simulate MISP 429; confirm no crash, clear error/status, and sanitized audit record. If not feasible, document why. | [ ] |
| Large event/result truncation | Query a large event/result set; confirm configured response-size and result-limit behavior is bounded and documented. | [ ] |
| Warninglist hit | Use an IOC expected to hit a loaded warninglist; confirm deterministic hit result. | [ ] |
| Warninglist miss | Use an IOC expected not to hit; confirm deterministic miss result. | [ ] |
| Warninglist `not_available` | Disable/unload warninglists or use a MISP version/endpoint shape where warninglists are unavailable; confirm graceful `not_available`. | [ ] |
| `pivot_ioc` | Run against known related data; confirm bounded, useful response. | [ ] |
| `find_related_iocs` | Run against known related data; confirm bounded, useful response. | [ ] |
| `extract_event_iocs` | Run against a known event; confirm extracted IOC types/values are correct and bounded. | [ ] |
| `explain_event_context` | Run against a known event; confirm summary is accurate and no raw secrets appear. | [ ] |
| `generate_event_report` | Run against a known event; confirm deterministic report structure. | [ ] |
| `generate_markdown_ioc_report` | Run against a known IOC; confirm Markdown renders and is bounded. | [ ] |
| `generate_markdown_event_report` | Run against a known event; confirm Markdown renders and is bounded. | [ ] |

## 2. Production-write beta validation checks

Use `AGENTIC_MISP_MCP_ENABLE_WRITE=true`, `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`, and `AGENTIC_MISP_MCP_APPROVAL_MODE=production`. Use separate deployments/API keys for `analyst_write` and `curator`/`admin` checks.

| Check | Required evidence | Status |
| --- | --- | --- |
| Production mode blocks `approved=true` alone | Call a write tool with `approved=true` but no `approval_request_id`; confirm `blocked`, no MISP write, and audit records approval status. | [ ] |
| First call creates `pending_approval` | Call one write tool without approval; confirm persisted request ID, `operation_hash`, sanitized proposed arguments, and no MISP write. | [ ] |
| CLI can list the approval | Run `agentic-misp-mcp approvals list`; confirm the pending request appears. | [ ] |
| CLI can show the approval | Run `agentic-misp-mcp approvals show <request_id>`; confirm tool name, role/action, operation hash, proposed args, and timestamps. | [ ] |
| CLI can approve the request | Run `agentic-misp-mcp approvals approve <request_id> --approved-by <operator>`; confirm status changes to `approved`. | [ ] |
| Second call with `approval_request_id` executes once | Re-call the same tool with same business arguments and approved ID; confirm exactly one MISP write and approval status becomes `used`. | [ ] |
| Same `approval_request_id` replay is blocked | Repeat the same call with the used ID; confirm `blocked`, no second write, and audit indicates already used/replay. | [ ] |
| Modified payload after approval is blocked | Approve request, then alter any business argument while using the same ID; confirm hash mismatch and no MISP write. | [ ] |
| Expired approval is blocked | Use a short TTL or stale record; confirm expired status and no MISP write. | [ ] |
| Rejected approval is blocked | Reject a pending request using CLI; confirm redemption is blocked and no MISP write. | [ ] |
| Wrong tool cannot redeem another tool’s approval | Create/approve one tool’s request, then attempt redemption from a different write tool; confirm wrong-tool block and no MISP write. | [ ] |
| Publish blocked when `AGENTIC_MISP_MCP_ENABLE_PUBLISH=false` | With curator/admin role and production approval mode, confirm publish proposal/execution is blocked by the publish kill switch. | [ ] |
| Publish works only with curator/admin plus `AGENTIC_MISP_MCP_ENABLE_PUBLISH=true` | Enable publish in isolated sandbox, approve by CLI, and confirm only curator/admin can publish. | [ ] |
| `analyst_write` cannot publish | Confirm `analyst_write` publish attempt is blocked even with production approval mode. | [ ] |
| Type allowlist blocks out-of-policy attribute writes | Set `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES`; confirm a disallowed type is blocked before MISP write. | [ ] |
| Category allowlist blocks out-of-policy attribute writes | Set `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES`; confirm a disallowed category is blocked before MISP write. | [ ] |
| Tag allowlist blocks out-of-policy tag writes | Set `AGENTIC_MISP_MCP_ALLOWED_TAGS`; confirm a disallowed tag is blocked before MISP write. | [ ] |
| Audit log contains approval correlation | Confirm audit entries include `approval_request_id`, `operation_hash`, and `approval_status` for pending/approved/used/blocked outcomes. | [ ] |
| Audit log redacts secrets | Grep/sanitize-check audit log for `MISP_API_KEY`, `approval_token`, bearer tokens, cookies, and authorization headers; confirm none appear. | [ ] |

## 3. Evidence summary for release notes

Complete this before tagging.

- Read-only validation result: TBD
- Production-write beta validation result: TBD
- MISP versions validated: TBD
- Known limitations discovered during validation: TBD
- Bugs fixed during validation: TBD
- Remaining beta risks accepted for tag: TBD
- Explicit statement for release notes: `v0.2.0-beta.1` is a production-write beta for isolated pilot validation, not GA production-ready.

## 4. Stop conditions

Do not tag `v0.2.0-beta.1` until any failed item is either fixed or explicitly documented as a beta limitation with a release-note entry. Do not tag if any validation evidence shows secret leakage, unapproved production-mode writes, replayable approvals, payload-swap execution, or publish bypassing the kill switch/role checks.
