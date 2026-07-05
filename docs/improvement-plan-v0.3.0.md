# Improvement plan — v0.3.0 (tool maturity + age-aware scoring)

Status: **proposal / roadmap** — approved design work for the next minor release, not yet
implemented. Written 2026-07-05 against `v0.2.1` (270 tests, 19 tools, live-validated on MISP
`2.5.42`). Everything here is additive; no existing tool is renamed, removed, or reshaped.

Grounding: every MISP field this plan depends on was probed live against the `2.5.42` lab on
2026-07-05: attribute `timestamp` is always present (epoch string); attribute
`first_seen`/`last_seen` exist but are frequently empty; events expose `date`, `timestamp`,
`publish_timestamp`, and `published`; `/sightings/restSearch` works and returns
`{"response": [{"Sighting": {"date_sighting": "<epoch>", "source": ..., ...}}]}`.

---

## Part 1 — MCP tool maturity

### 1.1 Consistency review of the current 19 tools (findings)

| Area | Finding | Action |
|------|---------|--------|
| Naming | Conventions are already coherent: read tools are verb-first (`search_`, `investigate_`, `generate_`, `find_`, `extract_`, `explain_`, `check_`, `pivot_`, `summarize_`), dry-run builders are `propose_*`, gated writes are `*_with_approval`. | No renames (renames are breaking). Codify the convention in `docs/security.md` so future tools follow it. |
| Response shape | Write tools share a stable envelope (`tool_name`, `status`, `risk`, `policy`). Read tools return ad-hoc dicts with no common fields, and the two `generate_markdown_*` tools return a bare `str`. | Additive fix: add `tool_name` and `schema_version: 1` to every read-tool dict response. Markdown tools stay `str` (agents consume them as documents; wrapping them is breaking). |
| Agent-friendliness | Read tools echo resolved `limit`, errors are typed + redacted, verdict/confidence enums are documented. Good baseline. | Add `schema_version` (above) so agents can detect the scoring-field additions in Part 2. |
| Timestamps | **Gap:** `MISPAttributeSummary` parses no timestamp at all; `MISPEventSummary` keeps only `date`. Agents cannot currently tell 2016 OSINT from last week's incident — the root cause of the false-confidence problem in Part 2. | Fix in Part 2 model additions. |

### 1.2 New tools — minimal production-safe set (all read-only)

1. **`get_ioc_sightings(value, limit=50)`** — `POST /sightings/restSearch` by value. Returns
   `{ioc, sighting_count, newest_sighting_at, oldest_sighting_at, sightings: [{event_id,
   attribute_id, type, source, date_sighting}]}` (bounded, no raw dump). Analyst gap it closes:
   sightings are writable today (`add_sighting_with_approval`) but not readable, so an agent
   cannot answer "has anyone actually seen this recently?" — also the Phase-2 scoring input.
2. **`search_events(date_from=None, date_to=None, published=None, org=None, limit=20)`** —
   `POST /events/restSearch` with bounded filters, returning the same event-summary shape as
   `find_events_by_tag`. Closes the "review recent events" gap (today the only event discovery
   path is tag search or a known event id).
3. **`get_misp_status()`** — `GET /servers/getVersion` plus a warninglist-endpoint probe.
   Returns `{misp_version, tested_baseline: "2.5.42", version_tested: bool,
   warninglists_available: bool}`. Lets agents and `config doctor`-style checks gate behavior on
   the runtime MISP version instead of assuming the lab baseline.

All three: registered through the same `_audit_read_tool` policy+audit wrapper, `read` action,
allowed under `read_only` role, response-size-bounded by the existing client.

### 1.3 Considered and rejected (do not implement without a new decision)

- **MCP read access to the approval store** — stays operator-CLI-only; exposing approvals to the
  agent loop weakens the two-party control.
- **Raw API proxy, event edit/delete, feed/server admin tools** — outside the project's safety
  boundary, unchanged.
- **New write tools in v0.3.0** — the write surface stays frozen at the current six; freshness
  work does not need new writes.

---

## Part 2 — age-aware scoring (stale-intel labeling + event-age weighting)

### 2.1 Model additions (additive, `models/misp.py`)

- `MISPAttributeSummary` += `timestamp: datetime | None`, `first_seen: datetime | None`,
  `last_seen: datetime | None` (parse epoch strings and ISO strings; empty string → `None`).
- `MISPEventSummary` += `timestamp: datetime | None`, `publish_timestamp: datetime | None`,
  `published: bool | None`.

### 2.2 Freshness labeling (new module `workflows/intel_freshness.py`)

Per investigated IOC, compute `newest_signal` = max over all matches of
(`attribute.last_seen`, `attribute.timestamp`, `event.publish_timestamp`, `event.timestamp`),
ignoring `None`s. Label by age in days against configurable thresholds:

| Label | Default window | Env var |
|-------|----------------|---------|
| `fresh` | ≤ 30 days | `AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS=30` |
| `aging` | 31–90 days | `AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS=90` |
| `stale` | 91–365 days | `AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS=365` |
| `expired` | > 365 days | (beyond stale threshold) |
| `unknown` | no timestamp parseable | — |

Settings validation: `fresh < aging < stale`, all ≥ 1, else startup `ValidationError`.

### 2.3 Age weighting in `calculate_score`

Master switch: `AGENTIC_MISP_MCP_AGE_WEIGHTING` (default `true`; `false` reproduces today's
scoring exactly — the regression-test anchor). Weights, configurable as
`AGENTIC_MISP_MCP_AGE_WEIGHTS="1.0,0.75,0.4,0.15"` (fresh, aging, stale, expired):

- The weight multiplies the **positive** factors only: `misp_matches`, `to_ids`,
  `related_events`, `threat_tags`, `related_iocs` (rounded, floor 1 point per non-empty factor
  so evidence never disappears entirely).
- **Penalties are never age-discounted**: `warninglist_hit` (−30) and `benign_tags` (−20) apply
  at full strength regardless of age.
- `unknown` label → weight 1.0 plus a 0-point `intel_age_unknown` factor (visible, but absence
  of a timestamp must not manufacture confidence in either direction).
- **Recency override:** any signal inside the fresh window keeps the label `fresh` even when
  other matches are ancient (newest-signal semantics already give this; stated as an invariant).
- **High-confidence floor:** if any match has `to_ids=true` **and** a threat-actor or malware
  tag is present, the effective weight floors at the `stale` weight (0.4) even when `expired` —
  curated actionable intel ages slower than uncorroborated OSINT.
- **Verdict guard:** when the label is `expired` (and no high-confidence floor applies), the
  final score caps at 60 — expired-only intel can reach `suspicious` but never
  `likely_malicious` without fresh corroboration. The cap is recorded as a
  `intel_age_cap` factor for explainability.

Verdict/confidence enums and thresholds (75/45, 75/40) are unchanged.

### 2.4 New response fields (additive; `investigate_ioc`, `generate_ioc_report`, `pivot_ioc`)

```json
"freshness": {
  "label": "stale",
  "newest_signal_age_days": 412,
  "age_weight": 0.4,
  "signals": {
    "attribute_last_seen": null,
    "attribute_timestamp": "2025-05-19T09:14:00+00:00",
    "event_publish_timestamp": "2025-05-20T07:02:11+00:00"
  },
  "thresholds_days": {"fresh": 30, "aging": 90, "stale": 365}
}
```

Plus: an `intel_age` entry in `confidence_reasons`/`factors`, and Markdown reports gain a
"Intel freshness" line in the assessment section.

### 2.5 Phase-2 enhancements (optional, after the minimal design ships)

1. **Sighting-aware refresh** — reuse `get_ioc_sightings`; a sighting inside the fresh window
   promotes the label one step (max `fresh`). Costs one extra MISP call per investigation —
   gate behind `AGENTIC_MISP_MCP_SIGHTING_REFRESH=false` (default off) for latency control.
2. **MISP decaying-models passthrough** — `includeDecayScore` on `restSearch` where the server
   supports it; surface as `misp_decay_score` alongside (never replacing) our deterministic
   score. Experimental; needs live probing per MISP version.
3. **Source/feed quality weights** — optional operator map
   `AGENTIC_MISP_MCP_ORG_WEIGHTS="CIRCL:1.0,OldFeed:0.5"` multiplying per-match contributions.
   Off unless configured.

### 2.6 Audit, config-surface, and compatibility notes

- New env vars appear in `config-check` output and get a `config doctor` sanity check
  (threshold ordering, weight range 0–1, warn when age weighting is disabled in a production
  write deployment). None are secrets; no redaction changes needed.
- `freshness` fields flow through `sanitize_for_audit` unchanged (plain timestamps/labels).
- All MISP fields used are confirmed present on `2.5.42` (probe above); `first_seen`/`last_seen`
  empty-string handling is mandatory since the lab returns them empty.
- Score *values* will shift when weighting is on — that is the point — but no field is removed
  or retyped. Ship as `v0.3.0-beta.1` with the kill switch documented in the CHANGELOG.

### 2.7 Test cases (acceptance list)

1. Label boundaries: ages 29/30/31, 89/90/91, 364/365/366 days map to the right labels.
2. Threshold misordering (`fresh >= aging`) fails settings validation.
3. Weight application: a 3-match, to_ids, threat-tagged IOC scores identically with
   `AGE_WEIGHTING=false` vs today's engine (byte-identical factors) — the no-regression anchor.
4. Expired cap: expired-only intel with score ≥ 75 pre-cap lands at 60 / `suspicious`, with an
   `intel_age_cap` factor present.
5. High-confidence floor: expired + to_ids + threat-actor tag uses weight 0.4, no cap bypass.
6. Warninglist penalty is not discounted for stale intel.
7. `unknown` label: no timestamps → weight 1.0, `intel_age_unknown` factor, verdict unchanged.
8. Parsing: epoch-string timestamps, ISO `first_seen`, empty-string `first_seen` → `None`.
9. New read tools: policy (`read` allowed under `read_only`), audit record shape, bounded
   output, and `get_misp_status` version-mismatch flag.
10. Live checklist additions (lab): sightings read-back of the v0.2.1 validation sighting on
    event 1641; freshness label sanity on a 2016 OSINT IOC (`expired`) vs a fresh sandbox
    attribute (`fresh`); `search_events` date-range filter.

---

## Part 3 — roadmap task list (beta → GA)

**M1 — models + freshness core** (target `v0.3.0-beta.1`)
- [ ] Parse attribute/event timestamps in `models/misp.py` (+ tests, incl. empty-string cases)
- [ ] `workflows/intel_freshness.py` with label + weight computation (+ boundary tests)
- [ ] Settings: 3 threshold vars, weights var, `AGE_WEIGHTING` switch, validation (+ tests)

**M2 — scoring integration** (target `v0.3.0-beta.1`)
- [ ] Wire weights/cap/floor into `investigation_engine.calculate_score` behind the switch
- [ ] `freshness` response block + `intel_age` factors in `investigate_ioc`,
      `generate_ioc_report`, `pivot_ioc`; Markdown report line
- [ ] `schema_version: 1` + `tool_name` on read-tool responses
- [ ] No-regression test: switch off ⇒ current outputs byte-identical

**M3 — new read tools** (target `v0.3.0-beta.2`)
- [ ] `get_ioc_sightings` (+ client method, queries, contract/audit/policy tests)
- [ ] `search_events` (+ bounded filters, tests)
- [ ] `get_misp_status` (+ version-gate field, tests)
- [ ] Update tool-count references (19 → 22) across README/llms.txt/docs

**M4 — docs + beta validation** (target `v0.3.0-beta.2`)
- [ ] `docs/configuration.md` + `docs/security.md` + README: freshness config and semantics
- [ ] Live validation checklist run on the `2.5.42` lab (test-case list §2.7 item 10)
- [ ] CHANGELOG behavior-change notice (scores shift when weighting is on)

**GA gate for `v0.3.0`**
- [ ] All M1–M4 done, live checklist passed with no unresolved blockers
- [ ] Phase-2 items (§2.5) explicitly deferred or scoped into `v0.4.0` — not GA blockers
- [ ] Same scoped-GA framing as `v0.2.0`: MCP-server-scope claim, limitations documented
