# Live MISP lab validation plan

This is a checklist for live validation of `agentic-misp-mcp` against a real, non-production
MISP instance. This document is the plan and running checklist, not a full report — see
`README.md`'s "Live lab validation status" table for a summary of what has passed so far. Read-only
and policy-blocking items have been validated in stages; controlled writes remain unvalidated. Do
not run any of the controlled write checklist items against a shared or production MISP instance.

See [`docs/testing.md`](testing.md) for what the mocked test suite already covers, and
[`docs/roles.md`](roles.md) / [`docs/approval-flow.md`](approval-flow.md) for the policy and
approval behavior being validated below.

## Prerequisites

- [ ] A dedicated, isolated, non-production MISP instance ("the lab"). Never point this
      checklist at a shared or production MISP.
- [ ] A lab-only organisation and a lab-only automation API key, scoped so that mistakes during
      validation cannot affect real data or real sync partners.
- [ ] `AGENTIC_MISP_MCP_ENABLE_WRITE` left at `false` for the read/report/pivot sections below;
      only flipped to `true` for the controlled-write section, and only against the lab.

## Evidence to record for every section

For each checklist item below, record:

- MISP core version and build/commit (`Administration → Server Settings → Diagnostics`, or the
  Docker image tag used).
- Deployment method (see next section).
- Date/time of the test run.
- The `agentic-misp-mcp` commit hash under test.
- Redacted request/response pairs (or audit log excerpts) that support a pass/fail conclusion —
  never record a real `MISP_API_KEY` value.
- Pass/fail per item, and for any failure: what assumption in the mocked tests
  (`docs/testing.md`) turned out to be wrong, and what code change (if any) is needed.

## 1. Environment record

- [ ] **MISP version tested:** record the exact MISP core version (and PyMISP/API version if
      relevant).
- [ ] **Deployment method:** record how the lab MISP was deployed (e.g. official
      `misp-docker` compose stack, VM install, existing internal lab instance) and how
      `agentic-misp-mcp` was run against it (local process, `docker run`, `docker compose`).
- [ ] **API key permissions:** record which MISP role/org the lab API key belongs to, and
      confirm it is the minimum needed for the sections being tested (a read-only key for
      section 2, a write-capable key only when reaching section 8).
- [ ] **Warninglists loaded / not loaded:** run the read-tool section once with the default
      MISP warninglists imported, and — if feasible — once with no warninglists imported, to
      confirm `check_warninglists` degrades to a structured `not_available` result rather than
      erroring (see `misp/warninglists.py`).

## 2. Read tools

`AGENTIC_MISP_MCP_ROLE=read_only`, `AGENTIC_MISP_MCP_ENABLE_WRITE=false`.

- [ ] `search_ioc` against at least one IOC known to exist in the lab, and one known not to.
- [ ] `investigate_ioc` against the same IOCs; confirm verdict/confidence/next-steps fields are
      populated sensibly against real data shapes.
- [ ] `summarize_event` against a real event; confirm no full raw event JSON leaks through.
- [ ] `check_warninglists` against a known-listed value and a known-clean value, in both the
      warninglists-loaded and warninglists-not-loaded configurations from section 1.

## 3. Report tools

- [ ] `generate_ioc_report` against a real IOC.
- [ ] `generate_event_report` against a real event.
- [ ] `generate_markdown_ioc_report` and `generate_markdown_event_report` — confirm the
      Markdown renders sensibly and stays within expected bounds for a real event size.

## 4. Pivot tools

- [ ] `pivot_ioc` against an IOC with several related events in the lab.
- [ ] `find_related_iocs` — confirm ranking and limit behavior against real related-IOC volume.
- [ ] `extract_event_iocs` against an event with a mix of supported/unsupported attribute types.
- [ ] `explain_event_context` against a tagged event (galaxy/threat-actor tags if available).
- [x] `find_events_by_tag` against a real, non-trivial tag. Validated 2026-07-04 via MCP
      Inspector CLI against the lab, tag `OSINT`, returning 3 real events.

## 5. Large event / result-set testing

- [ ] An event with attribute count well above `MISP_EVENT_ATTRIBUTE_LIMIT` (default `50`) —
      confirm truncation behavior (`attribute_count` vs `attributes_returned`) matches
      expectations and does not error.
- [ ] A search whose true match count exceeds `MISP_MAX_LIMIT` (default `100`) — confirm the
      tool truncates rather than erroring or hanging.
- [ ] `find_related_iocs` / `pivot_ioc` against an IOC with a large number of related events —
      confirm `MISP_RELATED_EVENT_LIMIT` (default `5`) is respected and response time stays
      reasonable.

## 6. Rate limit / timeout / error-path testing

Mocked tests do not cover these (see `docs/testing.md`); this section is the first time they
are exercised against something real.

- [ ] Trigger (or simulate via lab config) an HTTP `429` from MISP and confirm it surfaces as a
      clear `MISPRateLimitError`-driven failure, not a hang or a silent empty result.
- [ ] Set `MISP_TIMEOUT_SECONDS` low enough to trigger a real timeout against a slow/large
      request; confirm a clean, informative error rather than a crash.
- [x] Point `MISP_URL` at a wrong/unreachable host temporarily; confirm a clean connection-error
      message. Validated 2026-07-04 via MCP Inspector CLI: `search_ioc` returned `isError: true`
      with a clean `ConnectError` message, no crash; audit log recorded `outcome=error`,
      `error_type=MISPClientError`.
- [x] Test with an invalid/revoked API key; confirm `MISPAuthenticationError` behavior matches
      the mocked `401`/`403` expectations. Validated 2026-07-04 via MCP Inspector CLI: `search_ioc`
      returned a clean authentication error with no key echoed; audit log recorded
      `outcome=error`, `error_type=MISPAuthenticationError`.
- [ ] If feasible, test against a MISP TLS endpoint with an untrusted certificate with
      `MISP_VERIFY_TLS=true` (should fail closed) and document that `MISP_VERIFY_TLS=false` is
      lab-only and never for production.

## 7. Warninglist behavior testing

- [ ] Confirm the real `/warninglists/checkValue`-equivalent endpoint (or whatever this MISP
      version actually exposes) is exercised, and note if the endpoint name/shape differs from
      the mocked assumption in `misp/queries.py::warninglist_check_payload` /
      `misp/warninglists.py`.
- [ ] Confirm a warninglist hit and a warninglist miss both produce the expected structured
      result, not just a boolean.
- [ ] Confirm behavior on a MISP version where the warninglist check endpoint is missing or
      shaped differently still degrades to `not_available` rather than raising.

## 8. Controlled write tools — lab only, never production

Only run this section with `AGENTIC_MISP_MCP_ENABLE_WRITE=true` against the isolated lab
instance, using a lab-only event/org. Follow the two-call approval flow described in
[`docs/approval-flow.md`](approval-flow.md) for every item — never skip straight to
`approved=true` without inspecting the `pending_approval` response first.

- [ ] `propose_event` — confirm the proposed payload shape is a payload MISP would actually
      accept (cross-check field names/types against this MISP version's `/events/add`).
- [ ] `propose_attribute` — same, against `/attributes/add/{event_id}`.
- [ ] `submit_ioc_with_approval` with `AGENTIC_MISP_MCP_ROLE=analyst_write` — confirm
      `pending_approval` then `executed` against a real lab event, and confirm the created
      attribute is visible in the MISP UI/API afterward.
- [ ] `add_sighting_with_approval` — confirm a real sighting is recorded and queryable.
- [ ] `tag_event_with_approval` — confirm the tag is actually attached to the event afterward.
- [ ] `publish_event_with_approval` with `AGENTIC_MISP_MCP_ROLE=curator` (or `admin`) — confirm
      the event is actually published/visible to sync in the lab, and confirm `analyst_write`
      is still blocked from this tool in the same lab.
- [ ] Re-run the `read_only` and write-disabled blocking checks from `docs/roles.md` against the
      live instance to confirm policy blocking behaves identically to the mocked tests — no
      write should ever happen when blocked, verified by checking the lab event afterward, not
      just by trusting the tool's returned `status`.

## 9. Sign-off

- [ ] All sections above have recorded evidence and a pass/fail outcome.
- [ ] Any mismatch between mocked assumptions and live MISP behavior has a linked follow-up
      (issue, PR, or `CHANGELOG.md` entry).
- [ ] `PROJECT_STATE.md` and `README.md` roadmap are updated to reflect what was actually
      validated, and what (if anything) remains before considering a tagged release.
