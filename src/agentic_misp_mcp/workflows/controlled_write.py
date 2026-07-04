from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.misp.queries import (
    attribute_create_payload,
    event_create_payload,
    sighting_create_payload,
)
from agentic_misp_mcp.policy.approvals import build_approval_request
from agentic_misp_mcp.policy.models import PolicyDecision, Role

# Static, internal-only metadata used to describe proposals/blocks. Not policy inputs.
RISK_BY_TOOL: dict[str, str] = {
    "propose_event": "medium",
    "propose_attribute": "medium",
    "submit_ioc_with_approval": "medium",
    "add_sighting_with_approval": "low",
    "tag_event_with_approval": "medium",
    "publish_event_with_approval": "high",
}

REQUIRED_ROLE_BY_TOOL: dict[str, str] = {
    "propose_event": Role.ANALYST_WRITE.value,
    "propose_attribute": Role.ANALYST_WRITE.value,
    "submit_ioc_with_approval": Role.ANALYST_WRITE.value,
    "add_sighting_with_approval": Role.ANALYST_WRITE.value,
    "tag_event_with_approval": Role.ANALYST_WRITE.value,
    "publish_event_with_approval": Role.CURATOR.value,
}


def _policy_fields(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "role": decision.role,
        "action": decision.action,
        "allowed": decision.allowed,
        "approval_required": decision.approval_required,
        "reason": decision.reason,
    }


def _blocked_result(tool_name: str, decision: PolicyDecision) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "status": "blocked",
        "risk": RISK_BY_TOOL[tool_name],
        "required_role": REQUIRED_ROLE_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
    }


def _approval_token_blocked_result(tool_name: str, decision: PolicyDecision) -> dict[str, Any]:
    safe_decision = decision.model_copy(update={"reason": "approval token is required or invalid"})
    return _blocked_result(tool_name, safe_decision)


def _approval_token_allows_execution(
    *, expected_approval_token: str | None, approval_token: str | None
) -> bool:
    if expected_approval_token is None:
        return True
    return approval_token == expected_approval_token


def _proposal_result(
    tool_name: str, decision: PolicyDecision, proposed_payload: dict[str, Any]
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "status": "proposal",
        "risk": RISK_BY_TOOL[tool_name],
        "required_role": REQUIRED_ROLE_BY_TOOL[tool_name],
        "proposed_payload": proposed_payload,
        "policy": _policy_fields(decision),
    }


def _pending_approval_result(
    tool_name: str, decision: PolicyDecision, *, proposed_arguments: dict[str, Any]
) -> dict[str, Any]:
    approval = build_approval_request(
        tool_name=tool_name,
        action=decision.action,
        role=decision.role,
        reason=decision.reason,
        proposed_arguments=proposed_arguments,
    )
    return {
        "tool_name": tool_name,
        "status": "pending_approval",
        "risk": RISK_BY_TOOL[tool_name],
        "required_role": REQUIRED_ROLE_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
        "approval": approval.model_dump(mode="json"),
    }


def _executed_result(tool_name: str, decision: PolicyDecision, result: Any) -> dict[str, Any]:
    dumped = result.model_dump() if hasattr(result, "model_dump") else result
    return {
        "tool_name": tool_name,
        "status": "executed",
        "risk": RISK_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
        "result": dumped,
    }


async def propose_event_workflow(
    decision: PolicyDecision,
    *,
    info: str,
    distribution: int,
    threat_level_id: int,
    analysis: int,
    tags: list[str] | None,
) -> dict[str, Any]:
    """Build a MISP event creation proposal. Never writes to MISP."""
    tool_name = "propose_event"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    payload = event_create_payload(
        info=info,
        distribution=distribution,
        threat_level_id=threat_level_id,
        analysis=analysis,
        tags=tags,
    )
    return _proposal_result(tool_name, decision, payload)


async def propose_attribute_workflow(
    decision: PolicyDecision,
    *,
    event_id: int,
    type: str,
    value: str,
    category: str | None,
    comment: str | None,
    to_ids: bool | None,
) -> dict[str, Any]:
    """Build an attribute creation proposal for an existing event. Never writes to MISP."""
    tool_name = "propose_attribute"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    payload = attribute_create_payload(
        type=type, value=value, category=category, comment=comment, to_ids=to_ids
    )
    payload["event_id"] = event_id
    return _proposal_result(tool_name, decision, payload)


async def submit_ioc_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    event_id: int,
    type: str,
    value: str,
    category: str | None,
    comment: str | None,
    to_ids: bool | None,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
) -> dict[str, Any]:
    """Submit an IOC (attribute) only when write is enabled, role allows it, and approval
    (when required) has been explicitly given. Otherwise returns a blocked/proposal result."""
    tool_name = "submit_ioc_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    payload = attribute_create_payload(
        type=type, value=value, category=category, comment=comment, to_ids=to_ids
    )
    proposed_arguments = {**payload, "event_id": event_id}
    if decision.approval_required and not approved:
        return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
    if decision.approval_required and not _approval_token_allows_execution(
        expected_approval_token=expected_approval_token, approval_token=approval_token
    ):
        return _approval_token_blocked_result(tool_name, decision)
    result = await client.add_attribute(event_id, payload)
    return _executed_result(tool_name, decision, result)


async def add_sighting_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    value: str | None,
    event_id: int | None,
    attribute_id: str | None,
    sighting_type: str,
    source: str | None,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
) -> dict[str, Any]:
    """Add a sighting only when policy and approval allow. Otherwise returns a
    blocked/proposal result."""
    tool_name = "add_sighting_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    payload = sighting_create_payload(
        value=value,
        event_id=event_id,
        attribute_id=attribute_id,
        sighting_type=sighting_type,
        source=source,
    )
    if decision.approval_required and not approved:
        return _pending_approval_result(tool_name, decision, proposed_arguments=payload)
    if decision.approval_required and not _approval_token_allows_execution(
        expected_approval_token=expected_approval_token, approval_token=approval_token
    ):
        return _approval_token_blocked_result(tool_name, decision)
    result = await client.add_sighting(payload)
    return _executed_result(tool_name, decision, result)


async def tag_event_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    event_id: int,
    tag: str,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
) -> dict[str, Any]:
    """Tag an event only when policy and approval allow. Otherwise returns a
    blocked/proposal result."""
    tool_name = "tag_event_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    proposed_arguments = {"event_id": event_id, "tag": tag}
    if decision.approval_required and not approved:
        return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
    if decision.approval_required and not _approval_token_allows_execution(
        expected_approval_token=expected_approval_token, approval_token=approval_token
    ):
        return _approval_token_blocked_result(tool_name, decision)
    result = await client.tag_event(event_id, tag)
    return _executed_result(tool_name, decision, result)


async def publish_event_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    event_id: int,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
) -> dict[str, Any]:
    """Publish an event only when policy and approval allow. Requires curator/admin-like
    permission and is always high-risk and approval-gated. Otherwise returns a blocked/
    proposal result."""
    tool_name = "publish_event_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    proposed_arguments = {"event_id": event_id}
    if decision.approval_required and not approved:
        return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
    if decision.approval_required and not _approval_token_allows_execution(
        expected_approval_token=expected_approval_token, approval_token=approval_token
    ):
        return _approval_token_blocked_result(tool_name, decision)
    result = await client.publish_event(event_id)
    return _executed_result(tool_name, decision, result)
