from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentic_misp_mcp.policy import Action, ApprovalRequest, PolicyEngine, Role, enforce_policy
from agentic_misp_mcp.policy.approvals import build_approval_request
from agentic_misp_mcp.tools.registry import ALLOWED_TOOL_NAMES


def test_read_only_allows_current_read_only_tools():
    engine = PolicyEngine(role=Role.READ_ONLY, enable_write=False, require_approval=True)

    for tool_name in ALLOWED_TOOL_NAMES:
        decision = engine.decide(tool_name=tool_name, action=Action.READ)

        assert decision.allowed is True
        assert decision.approval_required is False
        assert decision.role == "read_only"
        assert decision.action == "read"
        assert decision.tool_name == tool_name


def test_read_only_blocks_non_read_actions():
    engine = PolicyEngine(role=Role.READ_ONLY, enable_write=True, require_approval=True)

    for action in (Action.WRITE, Action.PUBLISH, Action.ADMIN, Action.SYNC, Action.DANGEROUS):
        decision = engine.decide(tool_name=f"future_{action.value}_tool", action=action)

        assert decision.allowed is False
        assert decision.approval_required is False
        with pytest.raises(PermissionError):
            enforce_policy(decision)


def test_analyst_write_requires_approval_for_write_actions():
    engine = PolicyEngine(role=Role.ANALYST_WRITE, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="future_add_attribute", action=Action.WRITE)

    assert decision.allowed is True
    assert decision.approval_required is True


def test_curator_requires_approval_for_publish_feed_like_actions():
    engine = PolicyEngine(role=Role.CURATOR, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="future_sync_feed", action=Action.SYNC)

    assert decision.allowed is True
    assert decision.approval_required is True


def test_admin_requires_approval_for_admin_actions():
    engine = PolicyEngine(role=Role.ADMIN, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="future_admin_tool", action=Action.ADMIN)

    assert decision.allowed is True
    assert decision.approval_required is True


@pytest.mark.parametrize("role", [Role.CURATOR, Role.ADMIN])
def test_curator_and_admin_require_approval_for_publish_actions(role: Role):
    engine = PolicyEngine(role=role, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="publish_event_with_approval", action=Action.PUBLISH)

    assert decision.allowed is True
    assert decision.approval_required is True


def test_analyst_write_cannot_publish():
    engine = PolicyEngine(role=Role.ANALYST_WRITE, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="publish_event_with_approval", action=Action.PUBLISH)

    assert decision.allowed is False
    assert decision.approval_required is False


def test_dangerous_actions_never_allowed_even_for_admin():
    engine = PolicyEngine(role=Role.ADMIN, enable_write=True, require_approval=True)

    decision = engine.decide(tool_name="future_dangerous_tool", action=Action.DANGEROUS)

    assert decision.allowed is False
    assert decision.approval_required is False


@pytest.mark.parametrize("role", [Role.ANALYST_WRITE, Role.ADMIN])
def test_write_disabled_blocks_write_even_for_write_capable_roles(role: Role):
    engine = PolicyEngine(role=role, enable_write=False, require_approval=True)

    decision = engine.decide(tool_name="future_add_attribute", action=Action.WRITE)

    assert decision.allowed is False
    assert decision.approval_required is False
    assert "AGENTIC_MISP_MCP_ENABLE_WRITE" in decision.reason


def test_approval_request_rejects_secret_material():
    with pytest.raises(ValidationError) as exc_info:
        ApprovalRequest(
            tool_name="future_add_attribute",
            action=Action.WRITE,
            role=Role.ANALYST_WRITE,
            reason="test",
            proposed_arguments={"misp_api_key": "super-secret"},
        )

    assert "super-secret" not in str(exc_info.value)


def test_build_approval_request_sanitizes_secret_material():
    request = build_approval_request(
        tool_name="future_add_attribute",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        reason="test",
        proposed_arguments={"headers": {"Authorization": "super-secret"}, "value": "1.2.3.4"},
    )

    assert request.proposed_arguments["headers"] == "[REDACTED]"
    assert request.proposed_arguments["value"] == "1.2.3.4"


@pytest.mark.parametrize(
    "proposed_arguments",
    [
        {"payload": {"headers": {"Authorization": "Bearer nested-secret-value"}}},
        {"nested": {"api_key": "nested-secret-value"}},
        {"items": [{"token": "nested-secret-value"}]},
    ],
)
def test_approval_request_rejects_nested_secret_material(proposed_arguments):
    with pytest.raises(ValidationError) as exc_info:
        ApprovalRequest(
            tool_name="submit_ioc_with_approval",
            action=Action.WRITE,
            role=Role.ANALYST_WRITE,
            reason="test",
            proposed_arguments=proposed_arguments,
        )

    assert "nested-secret-value" not in str(exc_info.value)


def test_approval_request_allows_safe_nested_payload():
    request = ApprovalRequest(
        tool_name="submit_ioc_with_approval",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        reason="test",
        proposed_arguments={"payload": {"value": "1.2.3.4", "tags": ["tlp:amber"]}},
    )

    assert request.proposed_arguments["payload"]["value"] == "1.2.3.4"
