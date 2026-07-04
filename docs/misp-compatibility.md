# MISP compatibility matrix

This document tracks which MISP versions `agentic-misp-mcp` has actually been validated
against, what this project assumes about MISP's API/response shapes, and what is still untested.
It exists because broader MISP version compatibility is an explicit open item for GA (see
[`docs/ga-production-readiness-plan.md`](ga-production-readiness-plan.md) Phase C) — this is the
first version of that matrix, not a completed compatibility survey.

## Tested versions

| MISP version | How it was tested | Status |
| --- | --- | --- |
| `2.5.42` | Live lab validation (Docker, stdio transport, MCP Inspector) — read-only tools, error paths (unreachable `MISP_URL`, invalid/revoked `MISP_API_KEY`), policy-blocking behavior, and all four `_with_approval` controlled-write tools (`submit_ioc_with_approval`, `add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval`), plus `config doctor`/`approvals prune` and a read-only regression smoke test in `v0.2.0-beta.2`. | Validated. See `docs/live-validation-plan.md`, `docs/live-beta-validation-v0.2.0-beta.1.md`, `docs/live-beta-validation-v0.2.0-beta.2.md`, `docs/live-validation-report-v0.2.0-beta.1.md`, `docs/live-validation-report-v0.2.0-beta.2.md`. |

No second MISP version has been stood up and tested against this project as of `v0.2.0-rc.1`.
This is the single largest gap in this matrix.

## Assumptions this project makes about the MISP API

These are the response/endpoint shapes the code currently assumes. Anything not listed here that
differs across MISP versions is a compatibility risk this project has not yet characterized.

- **Attribute/event envelopes.** `misp/client.py` accepts both a MISP-standard
  `{"response": {"Attribute": [...]}}`/`{"response": {"Event": {...}}}` envelope and a bare
  list/object, and falls back to an empty result rather than raising when neither shape matches.
- **`/attributes/restSearch`, `/events/restSearch`, `/events/view/{id}`** — used for search,
  event-tag search, and event fetch respectively. Assumed stable across MISP 2.4.x/2.5.x per
  MISP's own REST API documentation, but only exercised live against `2.5.42`.
  Standard MISP REST API documentation.
- **`/warninglists/checkValue`** — the exact endpoint path and response shape for warninglist
  checking is known to vary by MISP version. This is why the check is isolated in
  `misp/warninglists.py` and why a `404`/unrecognized-shape response is mapped to a structured
  `not_available` result rather than raising or silently reporting a false miss (see
  `docs/security.md`'s "Warninglist behavior"). Only `2.5.42`'s shape (including a positive hit,
  a miss, and `not_available`) has mocked/controlled coverage plus a live miss/`not_available`
  check; a live positive hit against real warninglist data has not been performed on any version.
- **`/attributes/add/{event_id}`, `/sightings/add`, `/events/addTag/{event_id}`,
  `/events/publish/{event_id}`** — the four controlled-write endpoints. Response parsing assumes
  a `saved`/`published` boolean (or an `errors` key for publish) to distinguish a real MISP-side
  acceptance from an HTTP 200 that MISP itself rejected (see `models/misp.py`'s
  `parse_tag_result`/`parse_publish_result`, and the `executed` vs `failed` distinction found
  during `2.5.42` live validation). Only validated against `2.5.42`.
- **Attribute type/category vocabulary.** `policy/proposal_validation.py`'s
  `MISP_ATTRIBUTE_TYPES`/`MISP_ATTRIBUTE_CATEGORIES` allowlists are a curated subset of MISP's
  standard core-format taxonomy (`misp-core-format`), not a live-fetched, per-instance list. A
  MISP instance with a customized or extended attribute-type/category taxonomy (which MISP
  supports via its own configuration) may reject a payload this project considers valid, or this
  project may reject a type/category a given instance actually supports. This allowlist has not
  been cross-checked against any live instance's actual configured taxonomy.

## Untested versions

Any MISP version other than `2.5.42` — older releases (2.4.x line), newer releases past
`2.5.42`, and any fork or heavily customized deployment. No claim is made about behavior on any
of these; treat compatibility as unknown until validated.

## Known risks of broader version differences

- **Warninglist endpoint/response shape drift** is the highest-risk area, since MISP has changed
  warninglist-related endpoints across versions historically. `misp/warninglists.py` is
  deliberately isolated so this can be patched per-version without touching the rest of the
  client, but no second version's shape has been captured yet.
- **Attribute/category taxonomy drift**, especially for instances with custom taxonomies/object
  templates — see "Attribute type/category vocabulary" above. A validation failure here is a
  proposal-tool `status: "invalid"` (safe, does not touch MISP) or a guardrail block (also safe),
  never a silent write, but it may produce false-positive rejections against a customized
  instance.
- **Event/attribute JSON shape drift** across major versions (field renames, additional wrapper
  levels) could cause `parse_event`/`parse_attribute` to silently under-populate fields rather
  than fail loudly, since those parsers are intentionally lenient about missing keys. This has
  not been stress-tested against a second version.
- **Sighting/tag/publish response shape drift** — the `saved`/`published`/`errors` heuristics in
  `models/misp.py` are based on `2.5.42`'s observed behavior only.

## Validation needed for broader support

Per `docs/ga-production-readiness-plan.md` Phase C:

1. Stand up at least one additional MISP version (ideally one older and one newer than `2.5.42`).
2. Re-run the read-only and controlled-write live validation checklists
   (`docs/live-validation-plan.md`, `docs/live-beta-validation-v0.2.0-beta.1.md`,
   `docs/live-beta-validation-v0.2.0-beta.2.md`) against it.
3. Specifically re-verify: warninglist endpoint shape (including a positive hit), attribute/event
   JSON shape, sighting/tag/publish response shape, and whether the curated attribute
   type/category allowlist in `policy/proposal_validation.py` needs to become configurable or
   instance-aware rather than a fixed curated list.
4. Record findings in an update to this document (add a row to "Tested versions" and update
   "Known risks" with anything version-specific found), not just in a live-validation report.

This document will be updated as additional versions are tested. Until then, treat any MISP
version other than `2.5.42` as unvalidated.
