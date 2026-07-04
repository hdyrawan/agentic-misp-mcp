from __future__ import annotations

from agentic_misp_mcp.audit import sanitize_for_audit
from agentic_misp_mcp.policy.models import Action, ApprovalRequest, Role


def build_approval_request(
    *,
    tool_name: str,
    action: Action | str,
    role: Role | str,
    reason: str,
    proposed_arguments: dict[str, object] | None = None,
    requester: str | None = None,
) -> ApprovalRequest:
    """Create a sanitized in-memory approval proposal for future write workflows."""

    sanitized = sanitize_for_audit(proposed_arguments or {})
    if not isinstance(sanitized, dict):
        sanitized = {}
    return ApprovalRequest(
        tool_name=tool_name,
        action=Action(str(action)),
        role=Role(str(role)),
        reason=reason,
        proposed_arguments=sanitized,
        requester=requester,
    )
