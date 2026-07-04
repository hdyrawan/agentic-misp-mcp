# GA production-readiness plan

**Status: plan document. Phase B's code/test-level portion and part of Phase C/D have been
implemented in `v0.2.0-rc.1` (see the update note in each phase below); the remaining phases and
the GA claim itself still require explicit review before proceeding.**

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
   `/events/add` and `/attributes/add/{event_id}` endpoints. **Partially closed in `v0.2.0-rc.1`**:
   required-field, value-range, and known-attribute-type/category-vocabulary validation is now
   implemented and tested (`policy/proposal_validation.py`,
   `tests/test_proposal_validation.py`) — malformed/unsupported payloads never build a proposal.
   These tools still never call MISP themselves, and their proposed payload shape has still never
   been cross-checked against a live instance (see `docs/live-beta-validation-v0.2.0-rc.1.md`).
3. **Broader MISP version compatibility** beyond `2.5.42` — no second MISP version has been
   tested against this project at all. **Partially addressed in `v0.2.0-rc.1`**: a compatibility
   matrix now exists (`docs/misp-compatibility.md`) documenting assumptions and risks, but it
   still records exactly one tested version.
4. **Approval-operator separation** beyond filesystem permissions (documented separate
   users/hosts, or an operator-only administrative container/image).
5. **Supply-chain and release hygiene**: container image scanning, dependency vulnerability
   scanning, and secret scanning are not yet part of CI/release; no signed release tag exists yet.
   **Partially addressed in `v0.2.0-rc.1`**: `.github/dependabot.yml`'s previously-blank
   `package-ecosystem` (which meant no dependency updates were actually running) is fixed, and the
   dependency-update process plus the three still-open scans are documented as explicit release
   checklist items in `docs/production-readiness.md`. The scans themselves are still not
   automated in CI.
6. **A tagged release** with a finalized `CHANGELOG.md` entry. `v0.2.0-beta.1` and
   `v0.2.0-beta.2` are both tagged and pushed to `origin`; no tag exists yet for `v0.2.0-rc.1` or
   any GA release, and this project does not tag/push a release as a side effect of implementation
   work — tagging is a separate, explicitly requested step.

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

- **Code/test-level validation done in `v0.2.0-rc.1`**: `propose_event`/`propose_attribute` now
  reject missing required fields, out-of-range `distribution`/`threat_level_id`/`analysis`
  values, and unsupported attribute types/categories before building a payload, returning
  `status: "invalid"` with `validation_errors`. See `policy/proposal_validation.py` and
  `tests/test_proposal_validation.py`.
- **Still open**: manually validate (not via an MCP tool call) that `propose_event`'s and
  `propose_attribute`'s proposed payload shapes are accepted by a real MISP `/events/add` and
  `/attributes/add/{event_id}` call, using a direct API call (`curl`/Postman/a throwaway script)
  against the lab, not by adding a new write-executing MCP tool. Document any shape mismatch and
  fix `misp/queries.py`'s payload builders if needed.

### Phase C — Broader MISP version compatibility

- **Matrix published in `v0.2.0-rc.1`**: see `docs/misp-compatibility.md` for tested versions,
  API-shape assumptions, and known risks. It records exactly one tested version (`2.5.42`).
- **Still open**: stand up at least one additional MISP version (an older and/or newer release
  than `2.5.42`) and re-run the read-only and controlled-write validation checklists against it.
- Document any version-specific differences, especially in warninglist response shapes (already
  isolated in `misp/warninglists.py` for exactly this reason) and event/attribute JSON shapes, as
  an update to `docs/misp-compatibility.md`.

### Phase D — Operational and supply-chain hardening

- Strengthen approval-operator separation: document (and ideally provide an example of) running
  the operator CLI (`agentic-misp-mcp approvals ...`, `config doctor`) from a separate OS
  user/host/container than the one running the MCP server process itself, so a compromised
  MCP/agent process cannot reach the approval CLI or database even with a shared filesystem.
- Add container image scanning (for example Trivy or Grype) to CI/release. Not present in
  `.github/workflows/ci.yml` as of this document.
- **Fixed in `v0.2.0-rc.1`**: `.github/dependabot.yml`'s `package-ecosystem` value was blank, so
  it was not actually running any dependency updates. It now tracks `"pip"` and `"github-actions"`
  ecosystem entries. Still open: add `pip-audit` (or equivalent) to CI as an active vulnerability
  check, not just version-update PRs. The dependency-update review process and the
  still-open scans are documented as release-checklist items in `docs/production-readiness.md`'s
  "Dependency update process and supply-chain release checklist".
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

This plan was a proposal for review, not a self-executing work order. The code/test-level portion
of Phase B, the initial compatibility matrix in Phase C, and the Dependabot fix plus documented
release-checklist process in Phase D were explicitly authorized and implemented as `v0.2.0-rc.1`.
The remaining items in every phase — all live edge-case validation in Phase A, the live
cross-check in Phase B, a second tested MISP version in Phase C, approval-operator separation and
the three automated scans in Phase D, and Phase E's signed release tag — still require their own
explicit review and authorization before proceeding. Nothing in this document, including the
`v0.2.0-rc.1` work already done, constitutes a GA production-readiness claim by itself.
