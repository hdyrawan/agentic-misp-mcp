# Live validation report — v0.2.1 (2026-07-05)

End-to-end live validation of the `v0.2.1` security-review hardening release against the
non-production MISP `2.5.42` lab, run after tagging `v0.2.1` (commit `c176fa1`, hardening fixes
in `191589e`). Method: MCP Inspector `--cli` (headless) driving the server over stdio with
config sourced from the operator's local live env file; direct MISP API queries used only to
verify post-write state and endpoint behavior. All paths/hosts below are genericized.

Runtime policy for read-only checks: `AGENTIC_MISP_MCP_ROLE=read_only`,
`AGENTIC_MISP_MCP_ENABLE_WRITE=false`, `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`, lab approval
mode. Controlled-write checks used a session-scoped override (`analyst_write`,
`ENABLE_WRITE=true`, `REQUIRE_APPROVAL=true`, lab approval mode) against the dedicated sandbox
event `1641` only.

## Results

| # | Check | Result |
|---|-------|--------|
| 1 | `config-check` with live config | PASS (OK; API key shown as `[REDACTED]`) |
| 2 | `config doctor` with live config | PASS (2 expected WARNs: lab TLS off, temp audit path for this run) |
| 3 | `tools/list` | PASS (19 tools) |
| 4 | `search_ioc("8.8.8.8")` | PASS (3 matches, normalized ipv4) |
| 5 | `investigate_ioc("8.8.8.8")` | PASS (verdict `suspicious`, confidence `medium`) |
| 6 | `check_warninglists("10.1.2.3")` positive hit | PASS (`hit: true`, "List of RFC 1918 CIDR blocks")¹ |
| 7 | Read-only write block: `submit_ioc_with_approval(approved=true)` under `read_only` | PASS (`blocked`, "write mode is disabled"; audit `outcome=blocked`, `success=false`) |
| 8 | **v0.2.1** HTTP bind gate: `--transport http --host ::` | PASS (refused, exit 2) |
| 9 | **v0.2.1** HTTP bind gate: `--host 0.0.0.0` | PASS (refused, exit 2) |
| 10 | **v0.2.1** HTTP bind gate: `--host <LAN address>` | PASS (refused, exit 2) |
| 11 | **v0.2.1** `submit_ioc_with_approval` with unrecognized `type` | PASS (`status: invalid` with `validation_errors`; MISP never contacted) |
| 12 | **v0.2.1** `add_sighting_with_approval` with no target | PASS (`status: invalid`, "at least one of value, event_id, or attribute_id is required") |
| 13 | Happy-path regression: valid submit `approved=false` → `pending_approval` | PASS |
| 14 | Happy-path regression: valid submit `approved=true` → `executed` | PASS (attribute confirmed present in event `1641` via direct MISP API query) |
| 15 | Happy-path regression: `add_sighting_with_approval` on that value → `executed` | PASS (`saved: true`) |
| 16 | Audit log outcomes for the whole session | PASS (`success`/`blocked`/`invalid` all recorded correctly; `success=false` for blocked/invalid) |
| 17 | Audit log secret scan | PASS (API key appears 0 times) |

¹ The lab's warninglists had been disabled since the `v0.2.0-rc.1` validation (raw
`/warninglists/checkValue` returned `[]` for both a private IP and `8.8.8.8`). The miss path was
verified first (`status: available`, `hit: false` — correct parsing of `[]`), then warninglist
id 88 (RFC 1918 CIDR blocks) was re-enabled via the MISP API and the positive-hit path
re-verified through the MCP tool. The warninglist was left enabled, matching its state during
the rc.1 validation.

## Verdict

No bugs found. All four `v0.2.1` hardening changes behave as designed against a live MISP
instance, and the pre-existing read-only and controlled-write flows show no regression. Writes
were confined to the sandbox event `1641` (one `ip-dst` attribute + one sighting, both
clearly labeled as validation data).
