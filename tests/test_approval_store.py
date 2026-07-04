from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from agentic_misp_mcp.policy.approval_store import InMemoryApprovalStore, SqliteApprovalStore
from agentic_misp_mcp.policy.models import (
    ApprovalRedemptionError,
    ApprovalStatus,
    ApprovalStoreError,
)


def test_create_approve_reject_and_redeem_lifecycle():
    store = InMemoryApprovalStore()
    pending = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
        proposed_arguments={"value": "1.2.3.4"},
        role="analyst_write",
        ttl_seconds=900,
    )
    assert pending.status is ApprovalStatus.PENDING

    approved = store.approve(pending.request_id, approved_by="operator")
    assert approved.status is ApprovalStatus.APPROVED
    assert approved.approved_by == "operator"

    used = store.redeem(
        pending.request_id,
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
    )
    assert used.status is ApprovalStatus.USED

    rejected = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-2",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=900,
    )
    rejected = store.reject(rejected.request_id, reason="bad tag")
    assert rejected.status is ApprovalStatus.REJECTED


def test_redeem_before_approval_rejected_expired_wrong_tool_hash_and_replay():
    store = InMemoryApprovalStore()
    record = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-1",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=900,
    )

    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            record.request_id, tool_name="tag_event_with_approval", operation_hash="hash-1"
        )
    assert exc_info.value.status is ApprovalStatus.NOT_YET_APPROVED

    store.approve(record.request_id)
    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            record.request_id, tool_name="publish_event_with_approval", operation_hash="hash-1"
        )
    assert exc_info.value.status is ApprovalStatus.WRONG_TOOL

    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            record.request_id, tool_name="tag_event_with_approval", operation_hash="changed"
        )
    assert exc_info.value.status is ApprovalStatus.HASH_MISMATCH

    store.redeem(record.request_id, tool_name="tag_event_with_approval", operation_hash="hash-1")
    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            record.request_id, tool_name="tag_event_with_approval", operation_hash="hash-1"
        )
    assert exc_info.value.status is ApprovalStatus.ALREADY_USED

    rejected = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-2",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(rejected.request_id, reason="no")
    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            rejected.request_id, tool_name="tag_event_with_approval", operation_hash="hash-2"
        )
    assert exc_info.value.status is ApprovalStatus.REJECTED

    expired = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-3",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=1,
    )
    store.expire_stale(now=datetime.now(timezone.utc) + timedelta(seconds=2))  # noqa: UP017
    with pytest.raises(ApprovalRedemptionError) as exc_info:
        store.redeem(
            expired.request_id, tool_name="tag_event_with_approval", operation_hash="hash-3"
        )
    assert exc_info.value.status is ApprovalStatus.EXPIRED


def test_sqlite_store_redeem_is_one_time_and_persists(tmp_path):
    path = tmp_path / "approvals.sqlite3"
    store = SqliteApprovalStore(path)
    record = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
        proposed_arguments={"value": "1.2.3.4"},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.approve(record.request_id, approved_by="operator")

    second = SqliteApprovalStore(path)
    used = second.redeem(
        record.request_id,
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
    )
    assert used.status is ApprovalStatus.USED
    assert second.get(record.request_id).status is ApprovalStatus.USED

    with pytest.raises(ApprovalRedemptionError) as exc_info:
        second.redeem(
            record.request_id,
            tool_name="submit_ioc_with_approval",
            operation_hash="hash-1",
        )
    assert exc_info.value.status is ApprovalStatus.ALREADY_USED


def test_sqlite_store_refuses_group_world_writable_parent_or_db(tmp_path):
    bad_parent = tmp_path / "bad"
    bad_parent.mkdir()
    os.chmod(bad_parent, 0o777)
    with pytest.raises(ApprovalStoreError):
        SqliteApprovalStore(bad_parent / "approvals.sqlite3")

    path = tmp_path / "approvals.sqlite3"
    store = SqliteApprovalStore(path)
    store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=900,
    )
    os.chmod(path, 0o666)
    with pytest.raises(ApprovalStoreError):
        SqliteApprovalStore(path)
