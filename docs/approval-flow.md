# Controlled write approval flow

This page documents both approval modes. The historical `approved=true` flow below is **lab mode** (`AGENTIC_MISP_MCP_APPROVAL_MODE=lab`, the default). The `v0.2.0-beta.1` production-write beta candidate on `main` adds production approval mode, where `approved=true` alone is never sufficient and the caller must redeem a CLI-approved `approval_request_id`.


This document describes exactly how the four `_with_approval` MCP tools
(`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`,
`publish_event_with_approval`) behave, so an agent (or a human reading its output) knows what to
expect at each step. `propose_event` and `propose_attribute` are simpler — they always build a
proposal and never call MISP, regardless of any approval argument — so they are not part of this
flow; see `docs/security.md` and `docs/roles.md` for those two.

## The contract in one sentence

**Lab mode:** a write tool only calls MISP when the configured role/write-mode allow the action _and_ the caller passes `approved=true` on that specific call. **Production mode:** `approved=true` alone is blocked; a write tool only calls MISP when the configured role/write-mode allow the action and the caller redeems a CLI-approved, one-time-use, unexpired `approval_request_id` bound to the same tool and operation hash. Every other outcome is `blocked` or `pending_approval`, and every outcome — including `blocked` — is audited.

## Lab mode step by step

1. **First call: `approved=false` (the default).** The agent calls a write tool with its normal
   arguments and does not set `approved` (or explicitly sets it to `false`). This is the safe
   default — never assume approval.
2. **Policy is evaluated.** `PolicyEngine.decide()` checks write mode
   (`AGENTIC_MISP_MCP_ENABLE_WRITE`), role, and (for publish) the dedicated `publish` action.
   - If not allowed → the tool returns `status: "blocked"` immediately. No MISP call is made,
     and there is nothing to approve.
   - If allowed and `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` (the default) → the tool builds a
     sanitized `ApprovalRequest` (via `policy/approvals.py::build_approval_request`) and returns
     `status: "pending_approval"` with that proposal. **No MISP call is made at this point.**
   - If allowed and approval is not required (`AGENTIC_MISP_MCP_REQUIRE_APPROVAL=false`) → the
     tool executes immediately. This is a valid but less safe configuration; the default keeps
     approval required.
3. **The agent presents the proposal to the user.** The `pending_approval` response contains
   everything needed to make an informed decision: the tool name, the risk level, the required
   role, the full policy decision, and the proposed MISP payload (via `approval.proposed_arguments`).
   The agent should show this to the human verbatim or summarized — not silently re-call with
   `approved=true`.
4. **The user explicitly approves (or declines).** This is a human-in-the-loop decision made
   outside the MCP server. There is no persisted approval ticket to redeem: approval is
   expressed purely by the caller choosing to make a second tool call with `approved=true`. If
   the user declines, the agent simply does not make that second call.
5. **Second call: same arguments, `approved=true`.** The agent re-invokes the exact same tool
   with the same business arguments plus `approved=true`. Policy is evaluated again (it is not
   cached from step 2). If still allowed, the tool now calls the real MISP write method and
   returns `status: "executed"` with the MISP response — unless MISP itself rejected the
   operation (see below), in which case the tool returns `status: "failed"` instead.
6. **Audit logging.** Both calls (the `pending_approval` one and the `executed` one) produce
   independent JSONL audit records via `audit.py::audit_call`, each including the tool name,
   sanitized arguments (the `approved` boolean is logged; secrets like `MISP_API_KEY` never
   are), the policy decision fields (`role`, `action`, `allowed`, `approval_required`), success,
   duration, and error type/message if any. Reviewing the audit log after the fact shows both
   the proposal and the execution as two distinct, correlated entries (same tool name, same
   arguments except `approved`).

### `executed` vs `failed`

`tag_event_with_approval` and `publish_event_with_approval` call MISP endpoints
(`/events/addTag/{id}`, `/events/publish/{id}`) that can answer HTTP 200 while rejecting the
operation itself — MISP's response includes `saved`/`published: false` (for example an unknown
tag name, or a publish MISP declined). The tool distinguishes this from a real write:

- `status: "executed"` — MISP confirmed the write (`saved`/`published` was `true`).
- `status: "failed"` — the MISP write method was called and did not raise, but MISP rejected the
  operation. The `result` field still contains MISP's response (including its `message`, when
  present) so the caller can see why.

Both are audited distinctly too: `executed` is `outcome: "success"`, `failed` is
`outcome: "failed"` (not `"success"` and not `"blocked"` — the policy allowed the call and MISP
was actually reached, but the write did not take effect). Always check the tool's `status` field
(and, if relevant, `result.saved`/`result.published`) rather than assuming a non-`blocked` write
tool call means the data actually changed in MISP.

### What lab mode intentionally does *not* do

- **No persisted approval store in lab mode.** The `request_id` on a lab-mode `ApprovalRequest` is generated fresh each time and is not checked or redeemed on the follow-up call — the follow-up call is authorized purely by policy + the `approved=true` argument on that call, not by referencing the earlier `request_id`. Do not build production tooling around lab-mode `request_id` round-trips. Production approval mode is different: it uses a persisted `approval_request_id` in SQLite, approved/rejected by CLI only, with TTL, one-time redemption, same-tool checks, and exact operation-hash binding.
- **No multi-approver workflow.** Whoever can call the tool with `approved=true` can approve.
  There is no separate "who approved this" identity captured beyond the audit log's caller
  context (which is whatever the MCP host records).
- **No automatic approval by the agent.** An agent must never decide on its own that a proposal
  is safe and immediately re-call with `approved=true` in the same turn without a real human
  decision — that would defeat the purpose of the gate. Treat `approved=true` as equivalent to a
  human sign-off, because that is the only thing that makes the second call meaningful.

## Example: `submit_ioc_with_approval`

Configuration: `AGENTIC_MISP_MCP_ROLE=analyst_write`, `AGENTIC_MISP_MCP_ENABLE_WRITE=true`,
`AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` (default).

**Call 1 — proposal, no approval given:**

```
submit_ioc_with_approval(
    event_id=1234,
    type="ip-dst",
    value="203.0.113.10",
    category="Network activity",
    comment="C2 IP observed in phishing kit",
)
```

Response:

```json
{
  "tool_name": "submit_ioc_with_approval",
  "status": "pending_approval",
  "risk": "medium",
  "required_role": "analyst_write",
  "policy": {
    "role": "analyst_write",
    "action": "write",
    "allowed": true,
    "approval_required": true,
    "reason": "write action allowed by role and requires approval"
  },
  "approval": {
    "request_id": "5b9f...redacted-uuid",
    "tool_name": "submit_ioc_with_approval",
    "action": "write",
    "role": "analyst_write",
    "reason": "write action allowed by role and requires approval",
    "proposed_arguments": {
      "type": "ip-dst",
      "value": "203.0.113.10",
      "category": "Network activity",
      "comment": "C2 IP observed in phishing kit",
      "event_id": 1234
    },
    "requester": null,
    "created_at": "2026-01-01T00:00:00+00:00"
  }
}
```

The agent shows this to the analyst: *"I want to add `203.0.113.10` (ip-dst, Network activity)
to event 1234 with the comment above. Approve?"*

**Call 2 — after explicit human approval:**

```
submit_ioc_with_approval(
    event_id=1234,
    type="ip-dst",
    value="203.0.113.10",
    category="Network activity",
    comment="C2 IP observed in phishing kit",
    approved=True,
)
```

Response:

```json
{
  "tool_name": "submit_ioc_with_approval",
  "status": "executed",
  "risk": "medium",
  "policy": {
    "role": "analyst_write",
    "action": "write",
    "allowed": true,
    "approval_required": true,
    "reason": "write action allowed by role and requires approval"
  },
  "result": {
    "id": "9001",
    "event_id": 1234,
    "type": "ip-dst",
    "category": "Network activity",
    "value": "203.0.113.10",
    "comment": "C2 IP observed in phishing kit",
    "to_ids": null,
    "tags": []
  }
}
```

Only this second call invokes `MISPClient.add_attribute`.

## Example: `publish_event_with_approval`

Configuration: `AGENTIC_MISP_MCP_ROLE=curator` (or `admin`), `AGENTIC_MISP_MCP_ENABLE_WRITE=true`,
`AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` (default). Publishing is always `high` risk and — with
an `analyst_write` role — always `blocked`, since publish requires curator/admin (see
`docs/roles.md`).

**Call 1 — proposal, no approval given:**

```
publish_event_with_approval(event_id=4321)
```

Response:

```json
{
  "tool_name": "publish_event_with_approval",
  "status": "pending_approval",
  "risk": "high",
  "required_role": "curator",
  "policy": {
    "role": "curator",
    "action": "publish",
    "allowed": true,
    "approval_required": true,
    "reason": "publish action allowed by curator/admin role and requires approval"
  },
  "approval": {
    "request_id": "8f3e...redacted-uuid",
    "tool_name": "publish_event_with_approval",
    "action": "publish",
    "role": "curator",
    "reason": "publish action allowed by curator/admin role and requires approval",
    "proposed_arguments": { "event_id": 4321 },
    "requester": null,
    "created_at": "2026-01-01T00:05:00+00:00"
  }
}
```

Because publishing broadcasts the event to any configured sync/feed partners and is effectively
irreversible in most MISP deployments, the agent should flag this explicitly as high-risk and
make sure the human understands the consequence before approving — not just relay the JSON.

**Call 2 — after explicit human approval:**

```
publish_event_with_approval(event_id=4321, approved=True)
```

Response:

```json
{
  "tool_name": "publish_event_with_approval",
  "status": "executed",
  "risk": "high",
  "policy": {
    "role": "curator",
    "action": "publish",
    "allowed": true,
    "approval_required": true,
    "reason": "publish action allowed by curator/admin role and requires approval"
  },
  "result": {
    "event_id": 4321,
    "published": true,
    "message": "Job queued"
  }
}
```

Only this second call invokes `MISPClient.publish_event`.

## Safe usage checklist for agents

- Always default to `approved=false` (i.e. omit the argument) on the first call for any of the
  four `_with_approval` tools.
- Always surface the full `pending_approval` payload — risk, required role, and proposed
  arguments — to the human before making a second call.
- In lab mode, never synthesize or guess a human approval. Only pass `approved=true` after
  receiving an explicit "yes"/approve instruction for that specific proposed action. In
  production mode, do not rely on `approved=true`; use only an operator-approved
  `approval_request_id`.
- Treat `publish_event_with_approval` with extra caution: it is the only `high`-risk tool and
  the only one requiring `curator`/`admin`.
- Expect — and check — an audit log entry for every call, including `blocked` ones.


## Production approval mode (`v0.2.0-beta.1`)

The lab flow above remains the default under `AGENTIC_MISP_MCP_APPROVAL_MODE=lab`. `AGENTIC_MISP_MCP_APPROVAL_TOKEN` is only an optional lab/shared-secret control; it is not the production approval mechanism. Production pilots must explicitly set `AGENTIC_MISP_MCP_APPROVAL_MODE=production`. In production mode, `approved=true` alone is blocked and never executes a MISP write, even if `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=false`. The caller must provide an operator-approved `approval_request_id` for execution.

A first production-mode call without `approval_request_id` creates a pending SQLite approval record and returns `approval_request_id`, `operation_hash`, and `approval_status: pending`. The operation hash is computed from the canonical business operation object (`tool` plus normalized arguments), not audit-sanitized data and not timestamp/request metadata.

Only the operator CLI can approve or reject records:

```bash
agentic-misp-mcp approvals list --status pending
agentic-misp-mcp approvals show <request_id>
agentic-misp-mcp approvals approve <request_id> --approved-by NAME
agentic-misp-mcp approvals reject <request_id> --reason "..."
```

On redemption, the store atomically marks an approved matching record as `used` before calling MISP. Wrong tool, changed payload (`hash_mismatch`), replay (`already_used`), rejected, expired, pending, and unknown approvals return `blocked` and do not call MISP. If MISP later fails or rejects the write, the approval remains consumed; this is intentional replay-safe behavior and retry requires a new operator approval. The LLM/agent must not have shell access to the approval CLI or write access to the approval SQLite database. See `docs/production-write.md` for deployment and permission requirements, including `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES`, `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES`, `AGENTIC_MISP_MCP_ALLOWED_TAGS`, and `AGENTIC_MISP_MCP_ENABLE_PUBLISH`.
