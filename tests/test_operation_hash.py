from __future__ import annotations

from agentic_misp_mcp.policy.operation_hash import operation_hash


def test_operation_hash_stable_for_reordered_keys():
    left = operation_hash(
        "submit_ioc_with_approval",
        {"event_id": 1, "type": "ip-dst", "value": "1.2.3.4"},
    )
    right = operation_hash(
        "submit_ioc_with_approval",
        {"value": "1.2.3.4", "type": "ip-dst", "event_id": 1},
    )

    assert left == right


def test_operation_hash_changes_when_business_argument_changes():
    base = {"event_id": 1, "type": "ip-dst", "value": "1.2.3.4", "to_ids": True}

    assert operation_hash("submit_ioc_with_approval", base) != operation_hash(
        "submit_ioc_with_approval", {**base, "to_ids": False}
    )
    assert operation_hash("submit_ioc_with_approval", base) != operation_hash(
        "submit_ioc_with_approval", {**base, "value": "5.6.7.8"}
    )


def test_operation_hash_changes_when_tool_name_changes():
    args = {"event_id": 1, "tag": "tlp:amber"}

    assert operation_hash("tag_event_with_approval", args) != operation_hash(
        "publish_event_with_approval", args
    )
