from __future__ import annotations

import pytest

from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPPublishResult,
    MISPSightingSummary,
    MISPTagResult,
)
from agentic_misp_mcp.policy.models import Action, PolicyDecision, Role
from agentic_misp_mcp.workflows.controlled_write import (
    add_sighting_with_approval_workflow,
    propose_attribute_workflow,
    propose_event_workflow,
    publish_event_with_approval_workflow,
    submit_ioc_with_approval_workflow,
    tag_event_with_approval_workflow,
)


def _decision(
    *, tool_name: str, action: Action, role: Role, allowed: bool, approval_required: bool
) -> PolicyDecision:
    return PolicyDecision(
        allowed=allowed,
        approval_required=approval_required,
        reason="test decision",
        role=role.value,
        action=action.value,
        tool_name=tool_name,
    )


class FakeWriteClient:
    def __init__(self):
        self.calls = []

    async def add_attribute(self, event_id, payload):
        self.calls.append(("add_attribute", event_id, payload))
        return MISPAttributeSummary(event_id=event_id, type=payload["type"], value=payload["value"])

    async def add_sighting(self, payload):
        self.calls.append(("add_sighting", payload))
        return MISPSightingSummary(value=payload.get("value"))

    async def tag_event(self, event_id, tag):
        self.calls.append(("tag_event", event_id, tag))
        return MISPTagResult(event_id=event_id, tag=tag, saved=True)

    async def publish_event(self, event_id):
        self.calls.append(("publish_event", event_id))
        return MISPPublishResult(event_id=event_id, published=True)


@pytest.mark.asyncio
async def test_propose_event_blocked_when_not_allowed():
    decision = _decision(
        tool_name="propose_event",
        action=Action.WRITE,
        role=Role.READ_ONLY,
        allowed=False,
        approval_required=False,
    )
    result = await propose_event_workflow(
        decision, info="test", distribution=0, threat_level_id=4, analysis=0, tags=None
    )
    assert result["status"] == "blocked"
    assert "proposed_payload" not in result


@pytest.mark.asyncio
async def test_propose_event_returns_proposal_when_allowed():
    decision = _decision(
        tool_name="propose_event",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=True,
    )
    result = await propose_event_workflow(
        decision,
        info="phishing campaign",
        distribution=0,
        threat_level_id=2,
        analysis=1,
        tags=["tlp:amber"],
    )
    assert result["status"] == "proposal"
    assert result["proposed_payload"]["info"] == "phishing campaign"
    assert result["proposed_payload"]["Tag"] == [{"name": "tlp:amber"}]
    assert result["risk"] == "medium"
    assert result["required_role"] == "analyst_write"


@pytest.mark.asyncio
async def test_propose_attribute_returns_proposal_with_event_id():
    decision = _decision(
        tool_name="propose_attribute",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=True,
    )
    result = await propose_attribute_workflow(
        decision,
        event_id=7,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
    )
    assert result["status"] == "proposal"
    assert result["proposed_payload"] == {"type": "ip-dst", "value": "1.2.3.4", "event_id": 7}


@pytest.mark.asyncio
async def test_submit_ioc_pending_when_approval_required_and_not_given():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="submit_ioc_with_approval",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=True,
    )
    result = await submit_ioc_with_approval_workflow(
        client,
        decision,
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
        approved=False,
    )
    assert result["status"] == "pending_approval"
    assert result["approval"]["tool_name"] == "submit_ioc_with_approval"
    assert client.calls == []


@pytest.mark.asyncio
async def test_submit_ioc_executes_when_approved():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="submit_ioc_with_approval",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=True,
    )
    result = await submit_ioc_with_approval_workflow(
        client,
        decision,
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
        approved=True,
    )
    assert result["status"] == "executed"
    assert client.calls == [("add_attribute", 1, {"type": "ip-dst", "value": "1.2.3.4"})]


@pytest.mark.asyncio
async def test_submit_ioc_executes_without_approved_flag_when_approval_not_required():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="submit_ioc_with_approval",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=False,
    )
    result = await submit_ioc_with_approval_workflow(
        client,
        decision,
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
        approved=False,
    )
    assert result["status"] == "executed"
    assert client.calls


@pytest.mark.asyncio
async def test_add_sighting_blocked_when_not_allowed():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="add_sighting_with_approval",
        action=Action.WRITE,
        role=Role.READ_ONLY,
        allowed=False,
        approval_required=False,
    )
    result = await add_sighting_with_approval_workflow(
        client,
        decision,
        value="1.2.3.4",
        event_id=None,
        attribute_id=None,
        sighting_type="0",
        source=None,
        approved=True,
    )
    assert result["status"] == "blocked"
    assert client.calls == []


@pytest.mark.asyncio
async def test_tag_event_pending_then_executed():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="tag_event_with_approval",
        action=Action.WRITE,
        role=Role.ANALYST_WRITE,
        allowed=True,
        approval_required=True,
    )
    pending = await tag_event_with_approval_workflow(
        client, decision, event_id=1, tag="tlp:amber", approved=False
    )
    assert pending["status"] == "pending_approval"
    assert client.calls == []

    executed = await tag_event_with_approval_workflow(
        client, decision, event_id=1, tag="tlp:amber", approved=True
    )
    assert executed["status"] == "executed"
    assert client.calls == [("tag_event", 1, "tlp:amber")]


@pytest.mark.asyncio
async def test_publish_event_requires_curator_or_admin_and_approval():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="publish_event_with_approval",
        action=Action.PUBLISH,
        role=Role.CURATOR,
        allowed=True,
        approval_required=True,
    )
    pending = await publish_event_with_approval_workflow(
        client, decision, event_id=1, approved=False
    )
    assert pending["status"] == "pending_approval"
    assert pending["risk"] == "high"
    assert client.calls == []

    executed = await publish_event_with_approval_workflow(
        client, decision, event_id=1, approved=True
    )
    assert executed["status"] == "executed"
    assert client.calls == [("publish_event", 1)]


@pytest.mark.asyncio
async def test_publish_event_blocked_for_analyst_write():
    client = FakeWriteClient()
    decision = _decision(
        tool_name="publish_event_with_approval",
        action=Action.PUBLISH,
        role=Role.ANALYST_WRITE,
        allowed=False,
        approval_required=False,
    )
    result = await publish_event_with_approval_workflow(client, decision, event_id=1, approved=True)
    assert result["status"] == "blocked"
    assert client.calls == []
