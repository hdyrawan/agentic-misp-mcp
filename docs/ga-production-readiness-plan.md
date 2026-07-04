# GA production-readiness plan

**Status: plan only. Not implemented. Requires explicit approval before any GA work begins.**

This document translates the actual, current state of the project — after `v0.2.0-beta.1`
(production-write approval beta) and `v0.2.0-beta.2` (operational-readiness hardening) — into a
concrete, phased plan for reaching a GA production-readiness claim. It does not authorize any
code change by itself. Nothing in `docs/production-readiness.md`'s explicit non-goals is revisited
here (no raw MISP API proxy, no SIEM/SOAR/SOC/case-management integration as a baseline
requirement, no admin tools, no new MISP write endpoints beyond the existing six controlled-write
tools, no relaxing of default-safe settings).

## Baseline this plan starts from

As of `v0.2.0-beta.2`:

- 19 MCP tools (13 read, 6 controlled-write), tool boundary unchanged since Phase 8.
- 217 mocked/controlled tests pass; `ruff check`/`ruff format --check` clean.
- Live read-only and core controlled-write validation passed against a non-production MISP
  `2.5.42` lab (`docs/live-validation-plan.md`, `docs/live-beta-validation-v0.2.0-beta.1.md`).
- `v0.2.0-beta.2` added `config doctor`, `approvals prune`, `docs/rollback.md`, and closed four
  live-validation gaps (HTTP 429, large-result truncation, positive warninglist hit, warninglist
  `not_available`) with **mocked/controlled tests only** — see
  `docs/live-validation-report-v0.2.0-beta.2.md`. None of the four has live evidence yet.
- Manual audit-log review (see `docs/production-readiness.md`'s "Audit logging and manual review
  guidance") is the accepted control for both betas. This plan treats manual review as sufficient
  for an initial GA baseline too — a SIEM/log-forwarding integration is an optional future
  enhancement, not a GA blocker (see "Explicitly out of scope for GA" below).

## What is actually blocking a GA claim

Pulled directly from `docs/production-readiness.md`'s release/sign-off checklist and GA backlog,
reconciled against what beta.2 actually closed:

1. **Live edge-case evidence**, still open after beta.2 (mocked-only closure so far):
   - TLS fail-closed with `MISP_VERIFY_TLS=true` against an untrusted certificate.
   - Timeout behavior against a real slow/unresponsive MISP endpoint.
   - HTTP 429/rate-limit behavior against a real (or realistically simulated) MISP.
   - Large event/result-set truncation at realistic scale against real MISP data.
   - A positive warninglist hit against real MISP warninglist data (miss/`available` was already
     validated live in beta.1; a true hit was not).
2. **`propose_event`/`propose_attribute` payload-shape validation** against real MISP
   `/events/add` and `/attributes/add/{event_id}` endpoints. These tools never call MISP
   themselves, but their proposed payload shape has never been cross-checked against a live
   instance.
3. **Broader MISP version compatibility** beyond `2.5.42` — no second MISP version has been
   tested against this project at all.
4. **Approval-operator separation** beyond filesystem permissions (documented separate
   users/hosts, or an operator-only administrative container/image).
5. **Supply-chain and release hygiene**: container image scanning, dependency vulnerability
   scanning, and secret scanning are not yet part of CI/release; no signed release tag exists yet.
6. **A tagged release** with a finalized `CHANGELOG.md` entry — no git tag exists for this project
   as of this document.

## Phased plan

### Phase A — Live edge-case validation

Goal: turn the five still-open live items above from mocked-only into live-validated.

- **TLS fail-closed**: point `MISP_URL` at a MISP (or any HTTPS) endpoint with a deliberately
  untrusted/self-signed certificate while `MISP_VERIFY_TLS=true`; confirm the client fails closed
  with a clean `MISPClientError`-family exception, not a silent bypass.
- **Timeout**: introduce a controlled slow endpoint (a small proxy — e.g. `toxiproxy` or an nginx
  config with an artificial `proxy_read_timeout` delay — placed in front of the lab MISP, not a
  change to MISP itself) and confirm `MISP_TIMEOUT_SECONDS` is honored with a clean, bounded
  failure.
- **HTTP 429**: use the same controlled-proxy approach to return a real `429` response for a
  request, rather than attempting to actually rate-limit-trigger the lab MISP (which risks an
  unintentional DoS-adjacent test against shared lab infrastructure). Confirm the existing
  `MISPRateLimitError` path (already unit-tested in beta.2 at the tool/audit layer) behaves the
  same when the `429` genuinely comes over the wire.
- **Large result truncation**: seed the lab MISP with enough attributes/events to exceed
  `AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES` at its default, or temporarily lower the setting against
  realistic-size data, and confirm bounded/truncated behavior with no oversized audit record —
  mirroring `tests/test_operational_gap_closure.py`'s mocked assertions, but against real MISP
  response bytes.
- **Positive warninglist hit**: seed or use an existing MISP warninglist entry and query that
  exact value through `check_warninglists`/`investigate_ioc`; confirm `hit: true` with real
  `matches` content, not just the mocked shape already covered.
- Record all of the above in a `docs/live-validation-report-v0.2.0-beta.3.md`-style report (or
  whatever the next release version ends up being), following the same redaction rules as the
  beta.1/beta.2 reports.

### Phase B — Controlled-write payload validation

- Manually validate (not via an MCP tool call) that `propose_event`'s and `propose_attribute`'s
  proposed payload shapes are accepted by a real MISP `/events/add` and
  `/attributes/add/{event_id}` call, using a direct API call (`curl`/Postman/a throwaway script)
  against the lab, not by adding a new write-executing MCP tool. Document any shape mismatch and
  fix `misp/queries.py`'s payload builders if needed.

### Phase C — Broader MISP version compatibility

- Stand up at least one additional MISP version (an older and/or newer release than `2.5.42`) and
  re-run the read-only and controlled-write validation checklists against it.
- Document any version-specific differences, especially in warninglist response shapes (already
  isolated in `misp/warninglists.py` for exactly this reason) and event/attribute JSON shapes.
- Publish a compatibility matrix (MISP version → validated/not validated, known differences).

### Phase D — Operational and supply-chain hardening

- Strengthen approval-operator separation: document (and ideally provide an example of) running
  the operator CLI (`agentic-misp-mcp approvals ...`, `config doctor`) from a separate OS
  user/host/container than the one running the MCP server process itself, so a compromised
  MCP/agent process cannot reach the approval CLI or database even with a shared filesystem.
- Add container image scanning (for example Trivy or Grype) to CI/release. Not present in
  `.github/workflows/ci.yml` as of this document.
- Fix and enable dependency vulnerability scanning: `.github/dependabot.yml` exists but its
  `package-ecosystem` value is currently blank/invalid, so it is not actually running. Fix it (for
  example `"pip"` and `"github-actions"` ecosystem entries) or add `pip-audit` to CI as a more
  immediate check.
- Add secret scanning (for example `gitleaks` or `trufflehog`) across repository history and
  release artifacts; none is currently configured in CI.

### Phase E — Release

- Create a signed release tag once Phases A-D are complete and documented.
- Finalize `CHANGELOG.md` with a dated GA entry; update `PROJECT_STATE.md` and
  `docs/production-readiness.md`'s release/sign-off checklist to reflect all items checked.
- Attach the completed live validation report(s) to release notes.

## Explicitly out of scope for GA (carried forward, not revisited by this plan)

Everything already listed as a permanent non-goal in `docs/production-readiness.md` remains a
non-goal for GA too: a raw MISP API proxy, shell/filesystem MCP tools, generic admin tools,
accepting secrets as tool arguments, a built-in audit-log forwarder/rotation mechanism, a generic
multi-approver workflow, a delete/unpublish/retract tool, and weakening any default-safe setting.

In addition, per this project's current scope:

- **SIEM/SOAR/SOC/case-management integration is optional future work, not a GA requirement.**
  Manual audit-log review (as already documented) is treated as sufficient for the initial GA
  baseline. Revisit only if real operational usage at scale makes manual review impractical.
- No new MCP tools, no raw proxy, and no additional MISP write capability are part of this plan.
  If a future need arises for either, it should go through its own scoped design and approval,
  the same way Phase 8's six controlled-write tools did.

## Approval gate

This plan is a proposal for review, not a work order. Do not begin Phase A-E implementation work
until this plan has been explicitly reviewed and approved.
