# Live validation checklist — v0.2.0-rc.1

`v0.2.0-rc.1` is a release candidate on top of `v0.2.0-beta.2`. It adds
`propose_event`/`propose_attribute` payload validation, a MISP compatibility matrix
(`docs/misp-compatibility.md`), and a fixed Dependabot config. It does not change any existing
MCP tool's write behavior, add MISP write capability, or touch the policy/approval/audit code
paths validated in `v0.2.0-beta.1`/`v0.2.0-beta.2`.

**Status: this checklist has not been executed as of this document.** Everything below is
pending, not passed. Do not treat any item here as validated until it is explicitly checked off
with dated evidence, following the same ground rules as the `v0.2.0-beta.1`/`v0.2.0-beta.2`
checklists. A `docs/live-validation-report-v0.2.0-rc.1.md` should only be created once this
checklist is actually run against a real MISP lab — creating one without real evidence would be
fabricating validation, which this project's documentation practice explicitly avoids.

## Ground rules

Same ground rules as
[`docs/live-beta-validation-v0.2.0-beta.2.md`](live-beta-validation-v0.2.0-beta.2.md): use an
isolated non-production MISP instance, scoped test data, no new write capability, and never
include `MISP_API_KEY`, `approval_token`, bearer tokens, cookies, or authorization headers in
evidence. Use generic/placeholder hostnames and paths in any recorded evidence, not real internal
lab addresses.

## What is in scope for this checklist

This release's only functional change is the new proposal-validation layer, so this checklist is
narrow rather than repeating the full read-only/controlled-write checklist:

| Check | Required evidence | Status |
| --- | --- | --- |
| `propose_event` accepts a well-formed payload against a real MISP instance's `/events/add` shape expectations (confirmed by a direct, non-write `curl`/script comparison — not by adding a write-executing tool) | Confirm the proposed payload shape (`info`, `distribution`, `threat_level_id`, `analysis`, `Tag`) matches what a real MISP `/events/add` call expects, per `docs/ga-production-readiness-plan.md` Phase B. | [ ] |
| `propose_attribute` accepts a well-formed payload against a real MISP instance's `/attributes/add/{event_id}` shape expectations | Same approach as above, for `type`/`value`/`category`/`comment`/`to_ids`. | [ ] |
| `propose_event`/`propose_attribute` reject a malformed payload with `status: "invalid"` in a real deployment | Call each tool through a real MCP client (e.g. MCP Inspector) with a blank `info`/unsupported `type` and confirm `status: "invalid"` with a `validation_errors` list, and that `outcome: "invalid"` appears in the audit log, not `success`. | [ ] |
| The curated `MISP_ATTRIBUTE_TYPES`/`MISP_ATTRIBUTE_CATEGORIES` allowlist does not falsely reject types/categories the target MISP instance actually supports | Compare the allowlist in `policy/proposal_validation.py` against the target instance's configured attribute type/category taxonomy (including any custom taxonomy); note any mismatch. | [ ] |
| Read-only regression smoke test | Confirm `search_attributes`/`check_warninglists` (unmodified in this release) still succeed against the live lab MISP instance, since this release only touches `propose_event`/`propose_attribute` and CI config. | [ ] |
| `.github/dependabot.yml` fix does not require live MISP validation | N/A — this is a CI/repo-config change with no runtime behavior; confirm only that a Dependabot run (or `dependabot.yml` schema validation) succeeds in GitHub. | [ ] |

## Explicit non-goals for this checklist

- This checklist does not re-run the `v0.2.0-beta.1`/`v0.2.0-beta.2` read-only or controlled-write
  checklists; those remain valid from prior passes (see `docs/live-validation-plan.md`,
  `docs/live-beta-validation-v0.2.0-beta.1.md`, `docs/live-beta-validation-v0.2.0-beta.2.md`).
- This checklist does not attempt to reproduce a real HTTP `429`, a large-result truncation at
  realistic scale, a positive warninglist hit, or a TLS/timeout failure — those remain tracked in
  `docs/ga-production-readiness-plan.md` Phase A as separate, still-open GA blockers.
- This checklist does not attempt broader MISP version compatibility testing — see
  `docs/misp-compatibility.md` and `docs/ga-production-readiness-plan.md` Phase C.

## Stop conditions

Do not tag `v0.2.0-rc.1` as validated, and do not create a
`docs/live-validation-report-v0.2.0-rc.1.md`, until every row above is actually executed with
dated, redacted evidence. Mocked/controlled test coverage for the new validation layer
(`tests/test_proposal_validation.py`, `tests/workflows/test_controlled_write.py`,
`tests/test_controlled_write_tools.py`) is a separate, already-complete signal — it does not
substitute for the live checks above.
