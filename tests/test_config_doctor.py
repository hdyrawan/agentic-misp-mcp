from __future__ import annotations

import os
from pathlib import Path

from agentic_misp_mcp.cli import main
from agentic_misp_mcp.config_doctor import run_config_doctor
from agentic_misp_mcp.settings import Settings


def _valid_env(monkeypatch, tmp_path, api_key: str = "super-secret-test-key") -> None:
    monkeypatch.setenv("MISP_URL", "https://misp.example.local")
    monkeypatch.setenv("MISP_API_KEY", api_key)
    monkeypatch.setenv("MISP_VERIFY_TLS", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "logs" / "audit.jsonl"))
    monkeypatch.delenv("AGENTIC_MISP_MCP_ENABLE_WRITE", raising=False)
    monkeypatch.delenv("AGENTIC_MISP_MCP_ENABLE_PUBLISH", raising=False)
    monkeypatch.delenv("AGENTIC_MISP_MCP_APPROVAL_MODE", raising=False)
    monkeypatch.delenv("AGENTIC_MISP_MCP_APPROVAL_TOKEN", raising=False)
    monkeypatch.delenv("AGENTIC_MISP_MCP_ROLE", raising=False)


def _levels(result) -> set[str]:
    return {check.level for check in result.checks}


def test_doctor_all_pass_for_default_read_only_lab_deployment(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert "FAIL" not in _levels(result)


def test_doctor_fail_write_enabled_with_lab_approval_mode(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_WRITE", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "APPROVAL_MODE" in check.message for check in result.checks
    )


def test_doctor_pass_write_enabled_with_production_approval_mode(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_WRITE", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    store_dir = tmp_path / "approvals"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_dir / "approvals.sqlite3"))

    result = run_config_doctor(Settings())

    assert not result.has_failures


def test_doctor_fail_publish_enabled_with_wrong_role(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_PUBLISH", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "ENABLE_PUBLISH" in check.message for check in result.checks
    )


def test_doctor_warns_publish_enabled_with_curator_role(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_PUBLISH", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "curator")

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert any(
        check.level == "WARN" and "ENABLE_PUBLISH" in check.message for check in result.checks
    )


def test_doctor_fail_unsafe_approval_store_permissions_in_production(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    unsafe_dir = tmp_path / "unsafe-approvals"
    # mkdir(mode=...) is masked by the process umask (e.g. CI runners default to 0022,
    # which would silently drop the group/world write bits from a plain mkdir(mode=0o777)).
    # chmod afterward to get the exact bits under test regardless of umask.
    unsafe_dir.mkdir()
    os.chmod(unsafe_dir, 0o777)
    monkeypatch.setenv(
        "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(unsafe_dir / "approvals.sqlite3")
    )

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "APPROVAL_STORE_PATH" in check.message for check in result.checks
    )


def test_doctor_skips_approval_store_check_in_lab_mode(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    unsafe_dir = tmp_path / "unsafe-approvals"
    unsafe_dir.mkdir()
    os.chmod(unsafe_dir, 0o777)
    monkeypatch.setenv(
        "AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(unsafe_dir / "approvals.sqlite3")
    )

    result = run_config_doctor(Settings())

    assert not result.has_failures


def test_doctor_approval_store_check_does_not_create_store_file(monkeypatch, tmp_path):
    """config doctor must be safe to run against a not-yet-provisioned path: it should never
    create the approval-store directory or database as a side effect of checking it."""
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    store_dir = tmp_path / "approvals"
    store_path = store_dir / "approvals.sqlite3"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert not store_dir.exists()
    assert not store_path.exists()


def test_doctor_fail_corrupted_approval_store_file_does_not_crash(monkeypatch, tmp_path):
    """Regression test: a non-SQLite file at the configured approval-store path must produce
    a clean FAIL, not an uncaught sqlite3.DatabaseError crash.

    Explicitly chmod 0600 so the permission check passes and the check under test actually
    reaches the read-only SQLite-validity check, rather than failing for the unrelated
    (also-valid) reason of unsafe permissions under a group-writable default umask.
    """
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    store_path = tmp_path / "approvals.sqlite3"
    store_path.write_text("not a sqlite database", encoding="utf-8")
    os.chmod(store_path, 0o600)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_path))

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "not a usable SQLite database" in check.message
        for check in result.checks
    )


def test_doctor_fail_missing_audit_log_parent_directory(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    not_a_directory = tmp_path / "not-a-directory"
    not_a_directory.write_text("file", encoding="utf-8")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(not_a_directory / "audit.jsonl"))

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "AUDIT_LOG_PATH" in check.message for check in result.checks
    )


def test_doctor_fail_unsafe_audit_log_permissions(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    unsafe_dir = tmp_path / "unsafe-logs"
    unsafe_dir.mkdir()
    os.chmod(unsafe_dir, 0o777)
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(unsafe_dir / "audit.jsonl"))

    result = run_config_doctor(Settings())

    assert result.has_failures
    assert any(
        check.level == "FAIL" and "AUDIT_LOG_PATH" in check.message and "unsafe" in check.message
        for check in result.checks
    )


def test_doctor_warns_tls_verification_disabled(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MISP_VERIFY_TLS", "false")

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert any(
        check.level == "WARN" and "MISP_VERIFY_TLS" in check.message for check in result.checks
    )


def test_doctor_warns_missing_allowlists_in_production_write_mode(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_WRITE", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    store_dir = tmp_path / "approvals"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_dir / "approvals.sqlite3"))

    result = run_config_doctor(Settings())

    assert not result.has_failures
    warn_messages = [check.message for check in result.checks if check.level == "WARN"]
    assert any("ALLOWED_ATTRIBUTE_TYPES" in message for message in warn_messages)
    assert any("ALLOWED_TAGS" in message for message in warn_messages)


def test_doctor_passes_when_allowlists_are_configured(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_WRITE", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    store_dir = tmp_path / "approvals"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_dir / "approvals.sqlite3"))
    monkeypatch.setenv("AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES", "ip-dst,domain")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ALLOWED_TAGS", "tlp:*")

    result = run_config_doctor(Settings())

    warn_messages = [check.message for check in result.checks if check.level == "WARN"]
    assert not any("ALLOWED_ATTRIBUTE_TYPES" in message for message in warn_messages)
    assert not any("ALLOWED_TAGS" in message for message in warn_messages)


def test_doctor_warns_long_approval_ttl(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS", "999999")

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert any(
        check.level == "WARN" and "APPROVAL_TTL_SECONDS" in check.message for check in result.checks
    )


def test_doctor_warns_temp_audit_log_path(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", "/tmp/some-audit/audit.jsonl")

    result = run_config_doctor(Settings())

    assert any(
        check.level == "WARN" and "AUDIT_LOG_PATH" in check.message and "temporary" in check.message
        for check in result.checks
    )


def test_doctor_warns_approval_token_set_in_production_mode(monkeypatch, tmp_path):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_TOKEN", "leftover-lab-token")
    store_dir = tmp_path / "approvals"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_dir / "approvals.sqlite3"))

    result = run_config_doctor(Settings())

    assert not result.has_failures
    assert any(
        check.level == "WARN" and "APPROVAL_TOKEN" in check.message for check in result.checks
    )


def test_doctor_never_prints_secret_values(monkeypatch, tmp_path):
    api_key_secret = "do-not-print-this-api-key"
    token_secret = "do-not-print-this-approval-token"
    _valid_env(monkeypatch, tmp_path, api_key=api_key_secret)
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_TOKEN", token_secret)
    store_dir = tmp_path / "approvals"
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(store_dir / "approvals.sqlite3"))

    result = run_config_doctor(Settings())
    rendered = result.render()

    assert api_key_secret not in rendered
    assert token_secret not in rendered
    assert "[REDACTED]" in rendered


def test_doctor_cli_exit_zero_when_no_failures(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)

    code = main(["config", "doctor"])

    output = capsys.readouterr().out
    assert code == 0
    assert "Config doctor: PASS" in output


def test_doctor_cli_exit_nonzero_when_failures_present(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_WRITE", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ROLE", "analyst_write")

    code = main(["config", "doctor"])

    captured = capsys.readouterr()
    # Matches config-check's exit-code convention (2 = configuration is bad) so a pipeline
    # gate written for one command behaves the same for the other.
    assert code == 2
    assert "Config doctor: FAIL" in captured.err


def test_doctor_cli_reports_configuration_error(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.delenv("MISP_URL")

    code = main(["config", "doctor"])

    captured = capsys.readouterr()
    assert code == 2
    assert "MISP_URL" in captured.err


def test_unsafe_permissions_helper_ignores_missing_paths(tmp_path):
    from agentic_misp_mcp.security.permissions import unsafe_permissions_reason

    missing = tmp_path / "does-not-exist" / "audit.jsonl"
    assert unsafe_permissions_reason(missing, check_group=False) is None


def test_temp_path_detection_matches_system_tempdir(tmp_path):
    from agentic_misp_mcp.config_doctor import _looks_like_temp_path

    assert _looks_like_temp_path(tmp_path / "audit.jsonl") is True
    assert _looks_like_temp_path(Path("/var/lib/agentic-misp-mcp/audit.jsonl")) is False


def test_temp_path_detection_does_not_false_positive_on_shared_string_prefix(tmp_path):
    """Regression test: a sibling directory that merely starts with "/tmp" as a string
    (e.g. /tmporary-data) must not be misclassified as living under /tmp."""
    from agentic_misp_mcp.config_doctor import _looks_like_temp_path

    assert _looks_like_temp_path(Path("/tmporary-data/audit.jsonl")) is False
    assert _looks_like_temp_path(Path("/var/tmpfiles/audit.jsonl")) is False
