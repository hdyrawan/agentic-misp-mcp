# Rollback playbook

This project has no delete/unpublish/retract MCP tool by design (see
[`docs/security.md`](security.md)'s "no raw MISP API proxy" boundary and
[`docs/production-readiness.md`](production-readiness.md)'s explicit non-goals). Undoing a
mistaken controlled write always means acting directly against MISP, outside this project's tool
boundary. This document is the operator playbook for that: how to find what happened, how to
correlate it in the audit log, and what is and is not reversible.

## Scope

This playbook covers the four write-executing controlled-write tools:
`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, and
`publish_event_with_approval`. `propose_event` and `propose_attribute` never write to MISP, so
they never need rollback.

## Step 1: Confirm what actually happened

A tool call reaching `status: "executed"` means MISP accepted the write. A tool call reaching
`status: "failed"` means MISP rejected it (for example `saved`/`published: false`) — nothing to
roll back. A tool call reaching `status: "blocked"` never reached MISP. Only investigate rollback
for a confirmed `executed` result.

Run `agentic-misp-mcp config doctor` first if you are unsure whether the deployment you are
investigating is even configured the way you expect (write/approval mode, publish role, allowlist
coverage) — it is a fast, read-only sanity check before you start digging through logs.

## Step 2: Find the audit record

Every tool call writes exactly one JSONL audit record to `AGENTIC_MISP_MCP_AUDIT_LOG_PATH`. Find
the record for the mistaken write:

```bash
grep '"tool":"submit_ioc_with_approval"' /path/to/audit.jsonl | tail -20
```

Each record includes `tool`, sanitized `arguments`, `policy` fields (`role`, `action`, `allowed`,
`approval_required`), `outcome`, `duration_ms`, and — for production approval mode —
`approval_request_id`, `operation_hash`, and `approval_status`. Use the sanitized `arguments` to
identify exactly what was submitted: the event ID, attribute type/value, sighting details, tag
name, or published event ID.

## Step 3: Correlate with the approval record (production mode only)

In `AGENTIC_MISP_MCP_APPROVAL_MODE=production`, the `approval_request_id` in the audit record
maps to a persisted approval record. Look it up with the operator CLI:

```bash
agentic-misp-mcp approvals show <approval_request_id>
```

This shows who approved the request (`approved_by`, if set), when it was approved, and the exact
sanitized `proposed_arguments` that were redeemed. Cross-reference this against the audit record's
`arguments` — they describe the same operation, since the store binds redemption to the exact
canonical operation hash.

Do not prune approval records you are actively investigating. `agentic-misp-mcp approvals prune`
only removes old terminal (`used`/`rejected`/`expired`) records past the age threshold you pass
via `--older-than`; run it as routine maintenance, not during an active incident review.

## Step 4: Roll back directly in MISP

This project intentionally has no delete/unpublish/retract tool. Use the MISP UI or MISP's own
API/automation directly, outside this project's scope:

- **Mistaken attribute (`submit_ioc_with_approval`)** — delete or soft-delete the attribute in the
  MISP UI (Event view → attribute row → delete), or via MISP's own
  `/attributes/delete/{id}` API using an operator credential, not this server's API key.
- **Mistaken sighting (`add_sighting_with_approval`)** — delete the sighting from the MISP UI
  (Event view → Sightings) or via MISP's sighting deletion API.
  Sightings are lower-risk metadata but still worth cleaning up if they misrepresent detection
  history.
- **Mistaken tag (`tag_event_with_approval`)** — remove the tag from the MISP UI (Event view →
  remove tag) or via MISP's tag-removal API.
- **Mistaken publish (`publish_event_with_approval`)** — see "Publish is not reversible" below
  before assuming this can be undone the same way.

## Publish is not reversible

Publishing an event notifies MISP feed subscribers, syncing peers, and any downstream consumer
of published events. Once `publish_event_with_approval` returns `status: "executed"`:

- The event may have already been synced to other MISP instances, feeds, or subscribers outside
  your control. There is no reliable way to retract it everywhere it may have propagated.
- MISP's own "unpublish" action (if your MISP version and role support it) only affects the local
  instance's publish flag going forward; it does not retract copies already synced or fetched
  elsewhere.
- Treat a mistaken publish as an incident, not a quick fix: identify what was published (the audit
  record's sanitized arguments plus the MISP event itself), assess downstream exposure (which
  feeds/syncs/subscribers could have already pulled it), and communicate to affected consumers if
  the published content was sensitive or wrong.
- This is exactly why `publish_event_with_approval` is `curator`/`admin`-only, always `high` risk,
  and gated by `AGENTIC_MISP_MCP_ENABLE_PUBLISH` (default `false`) — see
  [`docs/production-write.md`](production-write.md). Keep publish disabled except for a deliberate,
  explicitly signed-off curator/admin publish deployment, and treat every publish audit record as
  worth a manual look (see "Audit logging and manual review guidance" in
  [`docs/production-readiness.md`](production-readiness.md)).

## Operator review checklist after any rollback

- [ ] Confirm the audit record's `outcome` and sanitized `arguments` match what you rolled back.
- [ ] Confirm the MISP-side deletion/tag-removal/unpublish action succeeded (re-check the event).
- [ ] For production approval mode, confirm the approval record you correlated in Step 3 is not
      still `approved` and redeemable elsewhere — a rollback does not itself expire or invalidate
      an approval record; it only reverts the MISP-side effect. Once a record is `used`, it is
      already one-time-use and cannot be redeemed again regardless.
- [ ] For a mistaken publish, document downstream exposure (feeds/syncs/subscribers) even if you
      cannot fully retract it, since this project cannot do that for you.
- [ ] If the mistake indicates a misconfiguration (wrong role, missing allowlist, approval TTL too
      long, etc.) rather than a one-off human error, re-run `agentic-misp-mcp config doctor` and
      fix the underlying `FAIL`/`WARN` before resuming write-enabled operation.
