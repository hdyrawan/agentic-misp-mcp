from __future__ import annotations

import time

import pytest

from agentic_misp_mcp.cli import main
from agentic_misp_mcp.cli_approvals import parse_duration
from agentic_misp_mcp.policy.approval_store import SqliteApprovalStore


@pytest.mark.parametrize(
    ("value", "expected_seconds"),
    [
        ("7d", 7 * 86400),
        ("30d", 30 * 86400),
        ("24h", 24 * 3600),
        ("3600s", 3600),
        ("1s", 1),
        ("30D", 30 * 86400),
    ],
)
def test_parse_duration_supported_suffixes(value, expected_seconds):
    assert parse_duration(value) == expected_seconds


@pytest.mark.parametrize(
    "value",
    ["30", "30x", "", "d", "-5d", "1.5d"],
)
def test_parse_duration_rejects_invalid_input(value):
    with pytest.raises(ValueError):
        parse_duration(value)


def _valid_env(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MISP_URL", "https://misp.example.local")
    monkeypatch.setenv("MISP_API_KEY", "super-secret-test-key")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))


def test_sqlite_store_prune_removes_old_terminal_records_only(tmp_path):
    store = SqliteApprovalStore(tmp_path / "approvals.sqlite3")

    used = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-used",
        proposed_arguments={"value": "1.2.3.4"},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.approve(used.request_id)
    store.redeem(used.request_id, tool_name="submit_ioc_with_approval", operation_hash="hash-used")

    rejected = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-rejected",
        proposed_arguments={"tag": "tlp:amber"},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(rejected.request_id, reason="not needed")

    expired = store.create(
        tool_name="add_sighting_with_approval",
        operation_hash="hash-expired",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=1,
    )
    time.sleep(1.2)
    store.expire_stale()
    assert store.get(expired.request_id).status.value == "expired"

    pending = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-pending",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    approved = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-approved",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.approve(approved.request_id)

    deleted = store.prune(older_than_seconds=0)

    assert deleted == 3
    assert store.get(used.request_id) is None
    assert store.get(rejected.request_id) is None
    assert store.get(expired.request_id) is None
    assert store.get(pending.request_id) is not None
    assert store.get(pending.request_id).status.value == "pending"
    assert store.get(approved.request_id) is not None
    assert store.get(approved.request_id).status.value == "approved"


def test_sqlite_store_prune_respects_age_threshold(tmp_path):
    store = SqliteApprovalStore(tmp_path / "approvals.sqlite3")
    record = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(record.request_id, reason="too soon")

    deleted = store.prune(older_than_seconds=86400)

    assert deleted == 0
    assert store.get(record.request_id) is not None


def test_sqlite_store_prune_with_vacuum_does_not_raise(tmp_path):
    store = SqliteApprovalStore(tmp_path / "approvals.sqlite3")
    record = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-1",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(record.request_id, reason="too soon")

    deleted = store.prune(older_than_seconds=0, vacuum=True)

    assert deleted == 1
    assert store.get(record.request_id) is None


def test_approvals_prune_cli_removes_old_and_preserves_pending(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    store_path = tmp_path / "approvals.sqlite3"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))

    store = SqliteApprovalStore(store_path)
    rejected = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-rejected",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(rejected.request_id, reason="not needed")
    pending = store.create(
        tool_name="submit_ioc_with_approval",
        operation_hash="hash-pending",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )

    code = main(["approvals", "prune", "--older-than", "0s"])

    output = capsys.readouterr().out
    assert code == 0
    assert "Pruned 1 approval record(s)" in output
    assert store.get(rejected.request_id) is None
    assert store.get(pending.request_id) is not None


def test_approvals_prune_cli_with_vacuum_flag(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    store_path = tmp_path / "approvals.sqlite3"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))
    store = SqliteApprovalStore(store_path)
    rejected = store.create(
        tool_name="tag_event_with_approval",
        operation_hash="hash-rejected",
        proposed_arguments={},
        role="analyst_write",
        ttl_seconds=900,
    )
    store.reject(rejected.request_id, reason="not needed")

    code = main(["approvals", "prune", "--older-than", "0s", "--vacuum"])

    output = capsys.readouterr().out
    assert code == 0
    assert "vacuumed" in output


def test_approvals_prune_cli_rejects_invalid_duration(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    store_path = tmp_path / "approvals.sqlite3"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))
    SqliteApprovalStore(store_path)

    code = main(["approvals", "prune", "--older-than", "not-a-duration"])

    captured = capsys.readouterr()
    assert code == 2
    assert "Invalid --older-than value" in captured.err


def test_approvals_prune_requires_older_than_argument(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    store_path = tmp_path / "approvals.sqlite3"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))

    with pytest.raises(SystemExit) as exc:
        main(["approvals", "prune"])

    assert exc.value.code == 2


def test_prune_command_not_exposed_through_mcp_tools(settings, tmp_path):
    from agentic_misp_mcp.audit import AuditLogger
    from agentic_misp_mcp.tools.registry import ALLOWED_TOOL_NAMES, register_tools

    class FakeMCP:
        def __init__(self):
            self.tools = {}

        def tool(self, name):
            def decorator(func):
                self.tools[name] = func
                return func

            return decorator

    class FakeClient:
        pass

    mcp = FakeMCP()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    register_tools(mcp, client=FakeClient(), settings=settings, audit_logger=audit)

    for name in mcp.tools:
        assert "prune" not in name.lower()
    assert "prune" not in ALLOWED_TOOL_NAMES
