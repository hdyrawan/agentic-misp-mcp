# Policy roles

`agentic-misp-mcp` gates the six controlled write tools behind a single configured role,
set via `AGENTIC_MISP_MCP_ROLE` (see `src/agentic_misp_mcp/policy/models.py::Role` and
`src/agentic_misp_mcp/policy/engine.py::PolicyEngine.decide`). There is exactly one role active
per running server process — this is not a multi-user permission system, and there is no login
or per-caller identity. Treat the role as a deployment-time configuration decision, not a
runtime-negotiable one.

**Read tools are unaffected by role.** All 13 read-only tools (`search_ioc`, `investigate_ioc`,
`summarize_event`, `check_warninglists`, `generate_ioc_report`, `pivot_ioc`, `find_related_iocs`,
`extract_event_iocs`, `explain_event_context`, `find_events_by_tag`, `generate_event_report`,
`generate_markdown_ioc_report`, `generate_markdown_event_report`) are classified as the `read`
action, which `PolicyEngine.decide()` always allows regardless of role. Role only changes
behavior for the six controlled write tools, and only when `AGENTIC_MISP_MCP_ENABLE_WRITE=true`.

## `read_only` (default)

- **Intended use:** default deployment posture; investigation, pivoting, and reporting only.
  Appropriate for any environment, including ones where write access has not been reviewed.
- **Allowed tool categories:** all 13 read tools.
- **Controlled write permissions:** none. All six write tools return `blocked` unconditionally
  for this role — even if `AGENTIC_MISP_MCP_ENABLE_WRITE=true` is also set. `PolicyEngine`
  checks `role is Role.READ_ONLY` immediately after the write-mode gate and blocks before any
  role-specific action logic runs.
- **Approval requirements:** not applicable; nothing to approve because nothing is allowed.
- **Important limitations:** this is the only role that cannot be paired with write mode to
  produce any effect. It is the safe default and should remain the default in any environment
  that has not explicitly opted into controlled write.

## `analyst_write`

- **Intended use:** an analyst (human-supervised agent session) who needs to propose and submit
  individual IOCs, sightings, and tags into MISP, but should not be able to broadcast
  (publish) an event to the wider MISP community/sync network.
- **Allowed tool categories:** all 13 read tools, plus write-tier controlled tools.
- **Controlled write permissions** (requires `AGENTIC_MISP_MCP_ENABLE_WRITE=true`):
  - `propose_event` — allowed (proposal only; never writes)
  - `propose_attribute` — allowed (proposal only; never writes)
  - `submit_ioc_with_approval` — allowed
  - `add_sighting_with_approval` — allowed
  - `tag_event_with_approval` — allowed
  - `publish_event_with_approval` — **blocked**. Publish uses a dedicated `publish` policy
    action restricted to `curator`/`admin`; `analyst_write` is not in that set.
- **Approval requirements:** when `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` (the default), every
  allowed write tool above returns `pending_approval` until called again with `approved=true`.
  See [`docs/approval-flow.md`](approval-flow.md).
- **Important limitations:** cannot publish events under any circumstances. If a workflow needs
  publish, it needs a `curator` or `admin` role configured instead — `analyst_write` cannot be
  escalated per-call.

## `curator`

- **Intended use:** an analyst or curator responsible for finalizing and publishing MISP events
  — for example, a threat-intel lead reviewing analyst-proposed content before it goes out to
  MISP sync partners.
- **Allowed tool categories:** all 13 read tools, plus all six write tools.
- **Controlled write permissions** (requires `AGENTIC_MISP_MCP_ENABLE_WRITE=true`): everything
  `analyst_write` can do, **plus** `publish_event_with_approval`.
- **Approval requirements:** same as `analyst_write` — every write tool, including publish,
  returns `pending_approval` until `approved=true` is passed, when
  `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true` (the default). Publish is always classified `high`
  risk (`RISK_BY_TOOL["publish_event_with_approval"] == "high"` in
  `workflows/controlled_write.py`), independent of the approval-required setting.
- **Important limitations:** `curator` in this project is a policy label for "may publish," not
  a MISP org-admin or sync-admin role. It does not unlock any additional MCP tool beyond the six
  listed above.

## `admin`

- **Intended use:** reserved for deployments that want the maximum policy tier available today.
  In the current tool set, `admin` behaves identically to `curator` — there is no admin-only
  MCP tool yet.
- **Allowed tool categories:** all 13 read tools, plus all six write tools (same effective set
  as `curator`).
- **Controlled write permissions:** identical to `curator`. `PolicyEngine` also defines an
  `Action.ADMIN` and `Action.SYNC` tier that only `admin` (`ADMIN`) or `curator`+`admin`
  (`SYNC`) can pass, but **no registered MCP tool currently uses `Action.ADMIN` or
  `Action.SYNC`** — they exist in the policy engine as forward-looking classifications for
  endpoints inventoried by `agentic-misp-mcp openapi-inventory`, not as active tool gates.
- **Approval requirements:** same as `curator`.
- **Important limitations — read carefully:**
  - **`admin` does not expose the raw MISP admin API.** Setting `AGENTIC_MISP_MCP_ROLE=admin`
    changes which of the six existing MCP tools are allowed; it does not add new tools, does
    not grant the MCP server any additional MISP API scope, and does not change what the
    configured `MISP_API_KEY` is authorized to do against the real MISP instance. MISP-side
    permissions are controlled entirely by the API key's own role in MISP, independently of
    this project.
  - **No user, organisation, server, or settings admin tools exist.** There is no
    `create_user`, `delete_org`, `update_server_settings`, or similar tool anywhere in
    `tools/registry.py`, regardless of configured role. This is enforced by
    `tests/test_tools_contract.py::test_no_admin_user_org_server_settings_tools_exist` and
    `test_no_raw_api_proxy_tool_exists`, and is a hard project rule (see `CLAUDE.md` and
    `PROJECT_STATE.md`): "Do not add event creation, attribute creation, sighting submission,
    tagging, publishing, raw MISP API proxying, shell execution, or unrestricted filesystem
    access" beyond the six narrow, approval-gated tools that already exist.
  - Because `admin` and `curator` are currently equivalent in tool access, prefer `curator` for
    any deployment that only needs publish — reserve `admin` for a future phase where an
    admin-tier tool is deliberately added and reviewed.

## Role selection quick reference

| Role | Read tools | Propose tools | Submit/sighting/tag | Publish |
| --- | --- | --- | --- | --- |
| `read_only` (default) | ✅ | ❌ | ❌ | ❌ |
| `analyst_write` | ✅ | ✅ | ✅ | ❌ |
| `curator` | ✅ | ✅ | ✅ | ✅ |
| `admin` | ✅ | ✅ | ✅ | ✅ (same as curator today) |

All ✅ write-tool cells above additionally require `AGENTIC_MISP_MCP_ENABLE_WRITE=true`, and
(when `AGENTIC_MISP_MCP_REQUIRE_APPROVAL=true`, the default) an explicit `approved=true` on a
second call — see [`docs/approval-flow.md`](approval-flow.md).
