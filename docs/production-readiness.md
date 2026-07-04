# Production readiness

**Current status: not production-ready.** Live read-only validation and core controlled-write
validation have both passed in a non-production MISP lab (see `README.md`'s "Live lab validation
status" table and [`docs/live-validation-plan.md`](live-validation-plan.md)). Production
deployment itself has not been validated, and several edge cases remain untested. This document
defines what "production-ready" means for this project, what is required to reach it, and the
explicit checklist that must be satisfied before any part of it is described as production-ready
in project docs.

This document is conservative by design: it distinguishes **validated in a lab** from
**production-ready**, and nothing here should be read as a production-readiness claim by itself.

## Production readiness scope

`agentic-misp-mcp` is a small, workflow-first MCP server, not a general-purpose MISP client.
Production readiness for this project means:

- The tool boundary and safety model documented in [`docs/security.md`](security.md) hold up
  under real MISP traffic, real error conditions, and real operational load — not just mocked
  tests and a single lab session.
- The failure modes that have not yet been exercised against a real MISP instance (rate limits,
  timeouts, TLS failures, large result sets, warninglist endpoint variance) behave the way the
  code claims they do.
- A deployer following this document's runtime configuration, TLS, secret-handling, and Docker
  guidance ends up with a safe-by-default deployment, without having to reverse-engineer safe
  defaults from the source.
- The release/sign-off checklist below is fully satisfied and recorded, with a tagged release and
  changelog entry.

Production readiness is being pursued incrementally, by scope, not as a single all-or-nothing
milestone — see the next section.

## Supported first production target: read-only MISP investigation/reporting

The first production target for this project is **read-only investigation and reporting only**:

- `AGENTIC_MISP_MCP_ROLE=read_only`
- `AGENTIC_MISP_MCP_ENABLE_WRITE=false`
- Tools in scope: `search_ioc`, `investigate_ioc`, `summarize_event`, `check_warninglists`,
  `pivot_ioc`, `find_related_iocs`, `extract_event_iocs`, `explain_event_context`,
  `find_events_by_tag`, `generate_ioc_report`, `generate_event_report`,
  `generate_markdown_ioc_report`, `generate_markdown_event_report`.

This is the narrowest, best-understood blast radius the project offers: no MISP state is ever
modified, and it is the configuration this project's own live validation has most thoroughly
exercised. It is the configuration to reach for first in any real deployment, and the one this
document's acceptance criteria (see "Release/sign-off checklist" below) are scoped against first.

Read-only production readiness is **not yet complete**. It requires, at minimum, the outstanding
edge-case validation listed in the acceptance criteria below (large event/result-set behavior,
timeout/rate-limit/TLS failure modes, warninglist endpoint compatibility) in addition to what has
already passed in the lab.

## Controlled-write production requirements

`v0.2.0-beta.1` introduces a narrow production-write pilot for the four existing MISP
write-executing approval tools only: `submit_ioc_with_approval`, `add_sighting_with_approval`,
`tag_event_with_approval`, and `publish_event_with_approval`. The beta keeps
`AGENTIC_MISP_MCP_APPROVAL_MODE=lab` as the default for backward compatibility and requires
explicit `AGENTIC_MISP_MCP_APPROVAL_MODE=production` to use persisted, one-time-use,
exact-payload-bound approval request IDs. `propose_event` and `propose_attribute` remain dry-run
proposal tools and are not part of production approval redemption. See
[`docs/production-write.md`](production-write.md) for the beta approval-store and operator-CLI
requirements.

The six controlled write tools (`propose_event`, `propose_attribute`, `submit_ioc_with_approval`,
`add_sighting_with_approval`, `tag_event_with_approval`, `publish_event_with_approval`) are
explicitly **out of scope** for the first production target above. Core controlled-write
validation has passed in a lab (see `docs/live-validation-plan.md` section 8), but that is not
sufficient for production use. Before considering controlled writes for any real deployment:

- `propose_event`/`propose_attribute` payload shapes must be validated against a real MISP
  `/events/add` and `/attributes/add/{event_id}` (still pending — these tools never call MISP,
  but their proposed payload shape has not been cross-checked against a live instance).
- `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` must remain enabled, and
  `AGENTIC_MISP_MCP_APPROVAL_TOKEN` should be configured so that `approved=true` alone cannot be
  used by an untrusted or autonomous caller to self-approve a write (see
  [`docs/approval-flow.md`](approval-flow.md)'s human-in-the-loop limitations).
- The MISP API key used for controlled writes must belong to a lab-scoped or otherwise
  blast-radius-limited MISP organisation/role — never a key with broad production MISP
  permissions, even once this project's own tool boundary is trusted.
- Audit logs for `outcome: "blocked"` and `outcome: "failed"` should be actively monitored (see
  "Audit logging and SIEM forwarding guidance" below), since both indicate either a
  misconfiguration or MISP rejecting a write the tool believed was valid.
- A rollback/incident-response plan should exist for a bad controlled write (a mistaken
  attribute, sighting, tag, or published event) before enabling writes against anything that
  matters — this project has no delete/unpublish/retract tool by design (see
  `docs/security.md`'s "no raw MISP API proxy" boundary), so undoing a write means using the MISP
  UI/API directly, outside this project's scope.
- Do not run any controlled-write path against a shared or production MISP instance until all of
  the above, and the read-only production target above, are satisfied first.

## Required runtime configuration

Production deployments must set the following. See
[`.env.production.example`](../.env.production.example) for a placeholder-only template with
these values pre-filled, and [`docs/configuration.md`](configuration.md) for the full variable
reference.

| Variable | Required production value | Why |
| --- | --- | --- |
| `MISP_URL` | your real MISP base URL | No default; required. |
| `MISP_API_KEY` | a real, scoped MISP API key, environment-only | Never in tool args, logs, or committed config. |
| `MISP_VERIFY_TLS` | `true` | See "TLS requirements" below. |
| `AGENTIC_MISP_MCP_ROLE` | `read_only` (for the first production target) | Controlled writes are out of scope until their own requirements above are met. |
| `AGENTIC_MISP_MCP_ENABLE_WRITE` | `false` (for the first production target) | Global write-mode kill switch; keep off unless the deployment has explicitly satisfied the controlled-write requirements above. |
| `AGENTIC_MISP_MCP_REQUIRE_APPROVAL` | `true` | Required whenever `AGENTIC_MISP_MCP_ENABLE_WRITE=true`; keep `true` even though it has no effect while writes are disabled. |
| `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND` | `false` | Keep off; see "TLS requirements" below. |
| `AGENTIC_MISP_MCP_AUDIT_LOG_PATH` | a persisted, host-writable path | Audit logs must survive container restarts; see the Docker hardening checklist below. |

## TLS requirements

- `MISP_VERIFY_TLS=true` is required for any production deployment. `MISP_VERIFY_TLS=false` is
  lab-only, for a self-signed certificate on an isolated non-production MISP instance, and must
  never be set for a real MISP instance.
- If your MISP instance uses a private CA, install or mount that CA bundle into the runtime
  environment (or container image) rather than disabling verification.
- This project's own MCP transport (stdio by default) has no TLS of its own — stdio runs over a
  local process pipe, which is the point of using it as the primary transport.
- The experimental `--transport http` mode has no built-in authentication or TLS. It refuses to
  bind `0.0.0.0` unless `AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND=true` is explicitly set, and
  even then it must sit behind an authenticated, TLS-terminating gateway (reverse proxy or
  service mesh sidecar) that terminates TLS and enforces authentication before traffic reaches
  this server. HTTP mode without that gateway is not a supported production configuration.
- **Acceptance criterion (not yet met):** a live test against a MISP TLS endpoint with an
  untrusted certificate, using `MISP_VERIFY_TLS=true`, has not yet been run to confirm the client
  actually fails closed rather than silently succeeding. See
  `docs/live-validation-plan.md` section 6.

## Secret handling

- `MISP_API_KEY` must come from the environment only. It is never accepted as an MCP tool
  argument, never logged, never returned in error messages, and never baked into a Docker image
  or committed config file.
- `AGENTIC_MISP_MCP_APPROVAL_TOKEN`, when configured, is the only token-shaped MCP tool
  parameter; it is redacted defensively from audit logs. A blank or whitespace-only value is
  treated the same as unset (see the settings-layer fix described in `CHANGELOG.md`) — but for
  clarity, either leave it unset entirely or set it to a real, non-blank random value. Do not
  leave a bare `AGENTIC_MISP_MCP_APPROVAL_TOKEN=` line in a committed or shared file, even though
  it is now handled safely at runtime.
- `.env` files (and `.env.production.example` once filled in) must never be committed. `.gitignore`
  excludes `.env` and `.env.*` except the two `*.example` templates.
- Rotate any real secret that is ever accidentally exposed in a prompt, issue, test fixture, audit
  log, or CI log.
- Docker images must never bake in `MISP_URL` or `MISP_API_KEY`; pass them at runtime only (via
  `--env-file`, orchestrator secrets, or an equivalent runtime secret store).

## Audit logging and SIEM forwarding guidance

Every MCP tool call writes one JSONL audit record. As of this document, the possible `outcome`
values are:

- `success` — the call was allowed and completed normally.
- `blocked` — policy did not allow the action (write mode disabled, role does not permit it, or
  approval-token mismatch). No MISP call was made.
- `failed` — a controlled-write tool reached MISP and did not raise an exception, but MISP itself
  rejected the operation (for example `saved`/`published: false` on an HTTP 200 response).
- `error` — a runtime exception occurred (network failure, authentication failure, timeout,
  malformed response, etc.).

Audit records include the tool name, sanitized arguments, policy decision fields (`role`,
`action`, `allowed`, `approval_required`), duration, and a safe error type/message when
applicable. They never include authorization headers, API keys, approval tokens, authkeys,
cookies, passwords, or raw backend response bodies.

For production use:

- **Forward the audit log to your SIEM or centralized logging pipeline.** This project does not
  ship a built-in forwarder; use a standard log-shipping agent (for example Filebeat, Fluent Bit,
  or an equivalent) tailing the JSONL file, or mount the log volume into your existing logging
  infrastructure.
- **Alert on `outcome: "blocked"` and `outcome: "failed"`.** A blocked write in a deployment that
  is not expected to attempt writes (a `read_only` deployment) indicates either a
  misconfiguration or a caller attempting an out-of-scope action. A `failed` write indicates MISP
  rejected an operation the tool believed was policy-valid and worth investigating.
- **Plan for log growth and rotation.** The audit log file grows without bound; this project does
  not rotate or truncate it. Use `logrotate`, your log-shipping agent's rotation support, or an
  equivalent, and ensure rotation does not race with the audit logger's append-only writes.
- **Treat the audit log itself as sensitive.** It contains sanitized arguments (IOC values, event
  IDs, tags) that may be sensitive in your environment even though secrets are redacted; apply
  the same access controls you would to any SOC-relevant log source.

## Docker hardening checklist

- [x] The image runs as a non-root user (`appuser`), not root.
- [x] Secrets are never baked into the image; `MISP_URL`/`MISP_API_KEY` are passed only via
      `--env-file` or equivalent runtime configuration.
- [x] The audit log directory is a mounted volume (`./logs:/app/logs` in
      `docker-compose.example.yml`), so logs persist across container restarts/recreation and are
      not baked into the image.
- [ ] Consider running the container with a read-only root filesystem (`docker run --read-only`
      or Compose's `read_only: true`), with only the audit-log volume writable. Not currently
      configured in the example Dockerfile/Compose file — evaluate before production use.
- [ ] Apply resource limits (`--memory`, `--cpus`, or the orchestrator equivalent) appropriate to
      your deployment. Not currently set in the example Compose file.
- [ ] Pin and periodically rebuild the base image (`python:3.11-slim`) to pick up security
      patches; this project does not currently automate base-image update tracking.
- [ ] Do not publish port `8000` unless you are intentionally running the experimental HTTP
      transport behind an authenticated TLS-terminating gateway (see "TLS requirements" above).
      The example Compose file's HTTP service is commented out by default.
- [ ] Run `agentic-misp-mcp config-check` as part of your deployment pipeline (a pre-flight check
      in CI/CD or an init container) before starting the server, to catch configuration mistakes
      before they reach production traffic.

## Live validation checklist

Full evidence and checklist state live in
[`docs/live-validation-plan.md`](live-validation-plan.md); this is a condensed status summary.

Passed:

- Read-only tools: `search_ioc`, `investigate_ioc`, `summarize_event`, `generate_ioc_report`,
  `find_events_by_tag`.
- Policy-blocking behavior: `read_only`/write-disabled blocks, and `analyst_write` blocked from
  `publish_event_with_approval`.
- Error paths: unreachable `MISP_URL`, invalid/revoked `MISP_API_KEY`.
- Core controlled-write flows: `submit_ioc_with_approval`, `add_sighting_with_approval`,
  `tag_event_with_approval`, `publish_event_with_approval` (including the `executed`/`failed`
  distinction described in `docs/security.md`).

Not yet passed / not yet attempted:

- `propose_event`, `propose_attribute` payload-shape validation against real MISP endpoints.
- `generate_event_report`, `generate_markdown_ioc_report`, `generate_markdown_event_report`
  against real data.
- `pivot_ioc`, `find_related_iocs`, `extract_event_iocs`, `explain_event_context`.
- Large event/result-set truncation behavior (`docs/live-validation-plan.md` section 5).
- Rate-limit (`429`) and timeout behavior (section 6).
- TLS-untrusted-certificate fail-closed behavior with `MISP_VERIFY_TLS=true` (section 6).
- Warninglist hit/miss/`not_available` behavior and endpoint compatibility across MISP versions
  (section 7).

## Release/sign-off checklist

Production-read-only cannot be marked complete in project docs until **all** of the following
are true. Status reflects this document's date of writing; re-verify before relying on it.

- [ ] Live TLS-verification test passes with `MISP_VERIFY_TLS=true` against an untrusted
      certificate, confirmed to fail closed. **Not yet done.**
- [ ] Timeout behavior is tested against a real slow/unresponsive MISP endpoint. **Not yet done.**
- [x] Invalid/revoked API key behavior is tested. **Done** — validated 2026-07-04; clean
      `MISPAuthenticationError`, no crash, no key echoed, audit `outcome=error`. See
      `docs/live-validation-plan.md` section 6.
- [ ] Large event/result truncation is tested against real MISP data at realistic scale. **Not
      yet done.**
- [ ] Warninglist hit/miss/`not_available` behavior is tested live, across the
      warninglists-loaded and warninglists-not-loaded configurations. **Not yet done** — mocked
      coverage exists (`docs/testing.md`), but not live evidence.
- [x] Audit logs are reviewed for `success`, `blocked`, `failed`, and `error` outcomes, each with
      at least one confirmed live example. **Done** — all four outcomes have been produced and
      inspected during live validation (see `docs/live-validation-plan.md` sections 2, 6, and 8).
- [x] Docs are internally consistent about current validation status. **Done as of this
      documentation pass** — re-verify at actual release time, since docs can drift again as new
      work lands.
- [ ] A release tag and `CHANGELOG.md` entry are prepared for the version being certified.
      **Not yet done** — no git tag has been created for this project as of this document.

## Explicit non-goals and out-of-scope items

These remain permanently out of scope, regardless of production-readiness progress — they are
project boundaries, not temporary gaps:

- A raw MISP API proxy tool of any kind.
- Shell execution or unrestricted filesystem access as an MCP tool.
- Generic user/organisation/server/settings-style MISP admin tools.
- Accepting `MISP_API_KEY`, passwords, authorization headers, cookies, or other secrets as normal
  MCP tool arguments. The only token-shaped tool parameter is the existing, redacted
  `approval_token` mechanism.
- A built-in audit-log forwarder, SIEM integration, or log-rotation mechanism — see "Audit
  logging and SIEM forwarding guidance" above for what deployers are expected to provide.
- A persisted approval store, multi-approver workflow, or approval-token expiry — the approval
  contract remains the simple two-call flow described in `docs/approval-flow.md`.
- A delete/unpublish/retract tool for controlled writes — undoing a mistaken write is out of
  scope and must be done directly against MISP.
- Weakening the read-only default, the write-mode kill switch, the approval-required default, or
  the audit-logging/redaction guarantees, for the sake of production convenience.
