# Production write beta

The current `main` branch contains the `v0.2.0-beta.1` production-write beta candidate. It is suitable for isolated pilot validation only; it is not GA production-ready.

`v0.2.0-beta.1` adds a production approval mode for the four existing write-executing approval tools only:

- `submit_ioc_with_approval`
- `add_sighting_with_approval`
- `tag_event_with_approval`
- `publish_event_with_approval`

It does not add new MISP write capabilities, raw proxy behavior, admin tools, or new MISP endpoints. `propose_event` and `propose_attribute` remain proposal-only.

## Modes

### Lab approval mode

`AGENTIC_MISP_MCP_APPROVAL_MODE=lab` remains the default for backward compatibility. In lab mode the existing `approved=true` flow is preserved. `AGENTIC_MISP_MCP_APPROVAL_TOKEN`, when configured, is only a lab/shared-secret hardening control for that flow; it is not the production approval mechanism. Lab mode is useful for local demos and controlled non-production validation, but `approved=true` alone should not be treated as production-safe human approval.

### Production approval mode

`AGENTIC_MISP_MCP_APPROVAL_MODE=production` opts into persisted approval requests. In production mode, `approved=true` alone never executes a write, even when `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=false`. Execution requires an `approval_request_id` that references a persisted record approved by the operator CLI. That record is one-time-use, expires after `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS`, and is bound to the exact canonical operation hash for the same tool and business arguments.

## Production approval lifecycle

1. The MCP caller invokes one of the four write tools without `approval_request_id`.
2. The tool builds the canonical business operation, computes `operation_hash`, persists a pending SQLite approval record, and returns `status: "pending_approval"`.
3. A human operator reviews the request out of band.
4. The operator approves or rejects using `agentic-misp-mcp approvals ...` CLI commands.
5. The MCP caller retries the same tool with the same business arguments and the approved `approval_request_id`.
6. The store atomically redeems the record using `UPDATE ... WHERE status='approved' AND operation_hash=?` semantics and marks it `used` before the MISP write is attempted.

Approval records are one-time-use and expire after `AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS`. Rejected, expired, already used, wrong-tool, and hash-mismatch redemptions are blocked and do not call MISP. If redemption succeeds but the subsequent MISP write fails or is rejected by MISP, the approval is already consumed (`used`). This is intentional replay-safe behavior: retrying requires the operator to review and approve a new request.

## Operator CLI

```bash
agentic-misp-mcp approvals list [--status pending|approved|used|rejected|expired]
agentic-misp-mcp approvals show <request_id>
agentic-misp-mcp approvals approve <request_id> [--approved-by NAME]
agentic-misp-mcp approvals reject <request_id> --reason "..."
```

No MCP tool can approve, reject, or modify approval state. MCP tools can only create pending requests as part of the normal write approval flow.

## Required configuration

```env
AGENTIC_MISP_MCP_ENABLE_WRITE=true
AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true
AGENTIC_MISP_MCP_APPROVAL_MODE=production
AGENTIC_MISP_MCP_APPROVAL_STORE_PATH=/var/lib/agentic-misp-mcp/approvals.sqlite3
AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS=900
AGENTIC_MISP_MCP_ENABLE_PUBLISH=false
```

Optional defense-in-depth allowlists:

```env
AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES=ip-dst,ip-src,url,domain
AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES=Network activity,Payload delivery
AGENTIC_MISP_MCP_ALLOWED_TAGS=tlp:*,misp-galaxy:*
```

Production guardrails are deliberately layered: `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES` limits submitted attribute types, `AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES` limits submitted attribute categories, and `AGENTIC_MISP_MCP_ALLOWED_TAGS` limits tags accepted by `tag_event_with_approval` (entries ending in `*` act as prefixes). `AGENTIC_MISP_MCP_ENABLE_PUBLISH=false` is the default publish kill switch. Publishing requires `AGENTIC_MISP_MCP_ENABLE_PUBLISH=true`, a `curator` or `admin` role, and production approval.

## Approval store permissions

The approval store uses Python stdlib `sqlite3`. In production mode the server and CLI refuse to use an approval database or parent directory that is group/world writable. Prefer a dedicated OS user and a directory like:

```bash
install -d -m 700 -o agentic-misp-mcp -g agentic-misp-mcp /var/lib/agentic-misp-mcp
```

The database is created with mode `0600`.

Old terminal (`used`/`rejected`/`expired`) records can accumulate over time. Prune them
periodically with the operator-CLI-only maintenance command:

```bash
agentic-misp-mcp approvals prune --older-than 30d [--vacuum]
```

This never deletes `pending` or `approved` records regardless of age, and is not reachable
through any MCP tool. See [`docs/configuration.md`](configuration.md#approval-store-maintenance-v020-beta2) for duration syntax.

## Critical trust boundary

Production approval mode is meaningful only if the LLM agent cannot run the approval CLI and cannot write to the approval SQLite database. If the agent has shell access as the operator user, write access to the approval database, or control over the host, it can bypass the human approval boundary. Use separate OS users, filesystem permissions, and process boundaries.

This beta does not solve compromised-host or compromised-operator scenarios. MISP-side RBAC and scoped API keys are still required.

Run `agentic-misp-mcp config doctor` before enabling any production write deployment; it checks
this trust boundary's operational preconditions (write/approval mode pairing, approval-store and
audit-log permission safety, allowlist coverage, approval TTL length) and exits nonzero on any
unsafe combination. See [`docs/configuration.md`](configuration.md#operational-readiness-doctor-v020-beta2).

If a controlled write turns out to be a mistake, see [`docs/rollback.md`](rollback.md) for how to
find it in the audit log, correlate it with its approval record, and roll it back directly in
MISP — including why a mistaken publish is not fully reversible.

## Audit fields

Top-level audit `outcome` values remain stable: `success`, `blocked`, `failed`, and `error`.

Production approval paths may add:

- `approval_request_id`
- `operation_hash`
- `approval_status`

`approval_status` may include `pending`, `approved`, `used`, `rejected`, `expired`, `not_found`, `wrong_tool`, `hash_mismatch`, `already_used`, and `not_yet_approved`.
