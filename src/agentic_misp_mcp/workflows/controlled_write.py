from __future__ import annotations

from typing import Any

from agentic_misp_mcp.misp.client import MISPClient
from agentic_misp_mcp.misp.queries import (
    attribute_create_payload,
    event_create_payload,
    sighting_create_payload,
)
from agentic_misp_mcp.policy.approval_store import ApprovalStore
from agentic_misp_mcp.policy.approvals import build_approval_request
from agentic_misp_mcp.policy.guardrails import GuardrailResult
from agentic_misp_mcp.policy.models import ApprovalRedemptionError, PolicyDecision, Role
from agentic_misp_mcp.policy.operation_hash import operation_hash

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


def _blocked_result(
    tool_name: str,
    decision: PolicyDecision,
    *,
    reason: str | None = None,
    approval_request_id: str | None = None,
    operation_hash_value: str | None = None,
    approval_status: str | None = None,
) -> dict[str, Any]:
    if reason is not None:
        decision = decision.model_copy(update={"reason": reason})
    result: dict[str, Any] = {
        "tool_name": tool_name,
        "status": "blocked",
        "risk": RISK_BY_TOOL[tool_name],
        "required_role": REQUIRED_ROLE_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
    }
    _add_approval_fields(
        result,
        approval_request_id=approval_request_id,
        operation_hash_value=operation_hash_value,
        approval_status=approval_status,
    )
    return result


def _approval_token_blocked_result(tool_name: str, decision: PolicyDecision) -> dict[str, Any]:
    return _blocked_result(tool_name, decision, reason="approval token is required or invalid")


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
    tool_name: str,
    decision: PolicyDecision,
    *,
    proposed_arguments: dict[str, Any],
    approval_store: ApprovalStore | None = None,
    ttl_seconds: int = 900,
) -> dict[str, Any]:
    op_hash = operation_hash(tool_name, proposed_arguments)
    approval = build_approval_request(
        tool_name=tool_name,
        action=decision.action,
        role=decision.role,
        reason=decision.reason,
        proposed_arguments=proposed_arguments,
    )
    if approval_store is not None:
        record = approval_store.create(
            tool_name=tool_name,
            operation_hash=op_hash,
            proposed_arguments=proposed_arguments,
            role=decision.role,
            ttl_seconds=ttl_seconds,
        )
        approval = approval.model_copy(
            update={"request_id": record.request_id, "created_at": record.created_at}
        )
    return {
        "tool_name": tool_name,
        "status": "pending_approval",
        "risk": RISK_BY_TOOL[tool_name],
        "required_role": REQUIRED_ROLE_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
        "approval": approval.model_dump(mode="json"),
        "approval_request_id": approval.request_id,
        "operation_hash": op_hash,
        "approval_status": "pending",
    }


def _executed_result(
    tool_name: str,
    decision: PolicyDecision,
    result: Any,
    *,
    approval_request_id: str | None = None,
    operation_hash_value: str | None = None,
) -> dict[str, Any]:
    dumped = result.model_dump() if hasattr(result, "model_dump") else result
    response: dict[str, Any] = {
        "tool_name": tool_name,
        "status": "executed",
        "risk": RISK_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
        "result": dumped,
    }
    _add_approval_fields(
        response,
        approval_request_id=approval_request_id,
        operation_hash_value=operation_hash_value,
        approval_status="used" if approval_request_id else None,
    )
    return response


def _failed_result(
    tool_name: str,
    decision: PolicyDecision,
    result: Any,
    *,
    approval_request_id: str | None = None,
    operation_hash_value: str | None = None,
) -> dict[str, Any]:
    """MISP answered the write call (no exception), but rejected the operation itself."""
    dumped = result.model_dump() if hasattr(result, "model_dump") else result
    response: dict[str, Any] = {
        "tool_name": tool_name,
        "status": "failed",
        "risk": RISK_BY_TOOL[tool_name],
        "policy": _policy_fields(decision),
        "result": dumped,
    }
    _add_approval_fields(
        response,
        approval_request_id=approval_request_id,
        operation_hash_value=operation_hash_value,
        approval_status="used" if approval_request_id else None,
    )
    return response


def _add_approval_fields(
    result: dict[str, Any], *, approval_request_id: str | None, operation_hash_value: str | None, approval_status: str | None
) -> None:
    if approval_request_id is not None:
        result["approval_request_id"] = approval_request_id
    if operation_hash_value is not None:
        result["operation_hash"] = operation_hash_value
    if approval_status is not None:
        result["approval_status"] = approval_status


def _guardrail_blocked_result(
    tool_name: str, decision: PolicyDecision, guardrail: GuardrailResult
) -> dict[str, Any]:
    return _blocked_result(tool_name, decision, reason=guardrail.reason or "write guardrail blocked")


def _production_approval_check(
    *,
    tool_name: str,
    decision: PolicyDecision,
    proposed_arguments: dict[str, Any],
    approved: bool,
    approval_request_id: str | None,
    approval_store: ApprovalStore | None,
    approval_ttl_seconds: int,
) -> dict[str, Any] | tuple[str, str]:
    if approval_store is None:
        return _blocked_result(
            tool_name,
            decision,
            reason="production approval mode requires an approval store",
            approval_status="not_found",
        )
    op_hash = operation_hash(tool_name, proposed_arguments)
    if approval_request_id is None:
        if approved:
            return _blocked_result(
                tool_name,
                decision,
                reason=(
                    "Production approval mode requires a valid approval_request_id. "
                    "approved=true alone is not accepted."
                ),
                operation_hash_value=op_hash,
                approval_status="not_found",
            )
        return _pending_approval_result(
            tool_name,
            decision,
            proposed_arguments=proposed_arguments,
            approval_store=approval_store,
            ttl_seconds=approval_ttl_seconds,
        )
    try:
        record = approval_store.redeem(
            approval_request_id, tool_name=tool_name, operation_hash=op_hash
        )
    except ApprovalRedemptionError as exc:
        return _blocked_result(
            tool_name,
            decision,
            reason=f"approval redemption blocked: {exc.status.value}",
            approval_request_id=approval_request_id,
            operation_hash_value=op_hash,
            approval_status=exc.status.value,
        )
    return record.request_id, op_hash


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
    approval_mode: str = "lab",
    approval_request_id: str | None = None,
    approval_store: ApprovalStore | None = None,
    approval_ttl_seconds: int = 900,
    guardrail: GuardrailResult | None = None,
) -> dict[str, Any]:
    """Submit an IOC (attribute) only when write policy and approval allow."""
    tool_name = "submit_ioc_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    if guardrail is not None and not guardrail.allowed:
        return _guardrail_blocked_result(tool_name, decision, guardrail)
    payload = attribute_create_payload(
        type=type, value=value, category=category, comment=comment, to_ids=to_ids
    )
    proposed_arguments = {**payload, "event_id": event_id}
    production = approval_mode == "production"
    if production:
        approval_check = _production_approval_check(
            tool_name=tool_name,
            decision=decision,
            proposed_arguments=proposed_arguments,
            approved=approved,
            approval_request_id=approval_request_id,
            approval_store=approval_store,
            approval_ttl_seconds=approval_ttl_seconds,
        )
        if isinstance(approval_check, dict):
            return approval_check
        redeemed_request_id, op_hash = approval_check
    else:
        redeemed_request_id = op_hash = None
        if decision.approval_required and not approved:
            return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
        if decision.approval_required and not _approval_token_allows_execution(
            expected_approval_token=expected_approval_token, approval_token=approval_token
        ):
            return _approval_token_blocked_result(tool_name, decision)
    result = await client.add_attribute(event_id, payload)
    return _executed_result(
        tool_name,
        decision,
        result,
        approval_request_id=redeemed_request_id,
        operation_hash_value=op_hash,
    )


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
    approval_mode: str = "lab",
    approval_request_id: str | None = None,
    approval_store: ApprovalStore | None = None,
    approval_ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Add a sighting only when policy and approval allow."""
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
    production = approval_mode == "production"
    if production:
        approval_check = _production_approval_check(
            tool_name=tool_name,
            decision=decision,
            proposed_arguments=payload,
            approved=approved,
            approval_request_id=approval_request_id,
            approval_store=approval_store,
            approval_ttl_seconds=approval_ttl_seconds,
        )
        if isinstance(approval_check, dict):
            return approval_check
        redeemed_request_id, op_hash = approval_check
    else:
        redeemed_request_id = op_hash = None
        if decision.approval_required and not approved:
            return _pending_approval_result(tool_name, decision, proposed_arguments=payload)
        if decision.approval_required and not _approval_token_allows_execution(
            expected_approval_token=expected_approval_token, approval_token=approval_token
        ):
            return _approval_token_blocked_result(tool_name, decision)
    result = await client.add_sighting(payload)
    return _executed_result(
        tool_name,
        decision,
        result,
        approval_request_id=redeemed_request_id,
        operation_hash_value=op_hash,
    )


async def tag_event_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    event_id: int,
    tag: str,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
    approval_mode: str = "lab",
    approval_request_id: str | None = None,
    approval_store: ApprovalStore | None = None,
    approval_ttl_seconds: int = 900,
    guardrail: GuardrailResult | None = None,
) -> dict[str, Any]:
    """Tag an event only when policy and approval allow."""
    tool_name = "tag_event_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    if guardrail is not None and not guardrail.allowed:
        return _guardrail_blocked_result(tool_name, decision, guardrail)
    proposed_arguments = {"event_id": event_id, "tag": tag}
    production = approval_mode == "production"
    if production:
        approval_check = _production_approval_check(
            tool_name=tool_name,
            decision=decision,
            proposed_arguments=proposed_arguments,
            approved=approved,
            approval_request_id=approval_request_id,
            approval_store=approval_store,
            approval_ttl_seconds=approval_ttl_seconds,
        )
        if isinstance(approval_check, dict):
            return approval_check
        redeemed_request_id, op_hash = approval_check
    else:
        redeemed_request_id = op_hash = None
        if decision.approval_required and not approved:
            return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
        if decision.approval_required and not _approval_token_allows_execution(
            expected_approval_token=expected_approval_token, approval_token=approval_token
        ):
            return _approval_token_blocked_result(tool_name, decision)
    result = await client.tag_event(event_id, tag)
    if not result.saved:
        return _failed_result(
            tool_name,
            decision,
            result,
            approval_request_id=redeemed_request_id,
            operation_hash_value=op_hash,
        )
    return _executed_result(
        tool_name,
        decision,
        result,
        approval_request_id=redeemed_request_id,
        operation_hash_value=op_hash,
    )


async def publish_event_with_approval_workflow(
    client: MISPClient,
    decision: PolicyDecision,
    *,
    event_id: int,
    approved: bool,
    approval_token: str | None = None,
    expected_approval_token: str | None = None,
    approval_mode: str = "lab",
    approval_request_id: str | None = None,
    approval_store: ApprovalStore | None = None,
    approval_ttl_seconds: int = 900,
) -> dict[str, Any]:
    """Publish an event only when policy and approval allow."""
    tool_name = "publish_event_with_approval"
    if not decision.allowed:
        return _blocked_result(tool_name, decision)
    proposed_arguments = {"event_id": event_id}
    production = approval_mode == "production"
    if production:
        approval_check = _production_approval_check(
            tool_name=tool_name,
            decision=decision,
            proposed_arguments=proposed_arguments,
            approved=approved,
            approval_request_id=approval_request_id,
            approval_store=approval_store,
            approval_ttl_seconds=approval_ttl_seconds,
        )
        if isinstance(approval_check, dict):
            return approval_check
        redeemed_request_id, op_hash = approval_check
    else:
        redeemed_request_id = op_hash = None
        if decision.approval_required and not approved:
            return _pending_approval_result(tool_name, decision, proposed_arguments=proposed_arguments)
        if decision.approval_required and not _approval_token_allows_execution(
            expected_approval_token=expected_approval_token, approval_token=approval_token
        ):
            return _approval_token_blocked_result(tool_name, decision)
    result = await client.publish_event(event_id)
    if not result.published:
        return _failed_result(
            tool_name,
            decision,
            result,
            approval_request_id=redeemed_request_id,
            operation_hash_value=op_hash,
        )
    return _executed_result(
        tool_name,
        decision,
        result,
        approval_request_id=redeemed_request_id,
        operation_hash_value=op_hash,
    )
