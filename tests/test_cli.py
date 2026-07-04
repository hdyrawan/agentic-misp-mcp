from __future__ import annotations

import json

import pytest

from agentic_misp_mcp.cli import main

MINIMAL_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "MISP", "version": "1.0.0"},
    "paths": {
        "/attributes/restSearch": {
            "post": {
                "operationId": "restSearchAttributes",
                "summary": "Search MISP attributes",
                "tags": ["Attributes"],
            }
        },
        "/attributes/delete/{id}": {
            "delete": {
                "operationId": "deleteAttribute",
                "summary": "Delete an attribute",
                "tags": ["Attributes"],
            }
        },
    },
}


def _valid_env(monkeypatch, tmp_path, api_key: str = "super-secret-test-key") -> None:
    monkeypatch.setenv("MISP_URL", "https://misp.example.local")
    monkeypatch.setenv("MISP_API_KEY", api_key)
    monkeypatch.setenv("MISP_VERIFY_TLS", "true")
    monkeypatch.setenv("MISP_TIMEOUT_SECONDS", "30")
    monkeypatch.setenv("MISP_DEFAULT_LIMIT", "20")
    monkeypatch.setenv("MISP_MAX_LIMIT", "100")
    monkeypatch.setenv("MISP_EVENT_ATTRIBUTE_LIMIT", "50")
    monkeypatch.setenv("MISP_RELATED_EVENT_LIMIT", "5")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENTIC_MISP_MCP_LOG_LEVEL", "INFO")


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    output = capsys.readouterr().out
    assert exc.value.code == 0
    assert "--transport" in output
    assert "config-check" in output
    assert "openapi-inventory" in output


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert "agentic-misp-mcp" in capsys.readouterr().out


def test_cli_requires_known_transport():
    with pytest.raises(SystemExit) as exc:
        main(["--transport", "bad"])

    assert exc.value.code == 2


def test_config_check_success(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)

    code = main(["config-check"])

    output = capsys.readouterr().out
    assert code == 0
    assert "Configuration check: OK" in output
    assert "MISP_API_KEY is set ([REDACTED])" in output


def test_config_check_missing_misp_url(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.delenv("MISP_URL")

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "Configuration check: FAILED" in captured.err
    assert "MISP_URL" in captured.err


def test_config_check_missing_misp_api_key(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.delenv("MISP_API_KEY")

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "MISP_API_KEY" in captured.err


def test_config_check_invalid_limits(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MISP_DEFAULT_LIMIT", "101")
    monkeypatch.setenv("MISP_MAX_LIMIT", "100")

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "MISP_DEFAULT_LIMIT must be <= MISP_MAX_LIMIT" in captured.err


def test_config_check_invalid_timeout(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MISP_TIMEOUT_SECONDS", "0")

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "MISP_TIMEOUT_SECONDS" in captured.err


def test_config_check_invalid_audit_log_path(monkeypatch, tmp_path, capsys):
    _valid_env(monkeypatch, tmp_path)
    not_a_directory = tmp_path / "not-a-directory"
    not_a_directory.write_text("file", encoding="utf-8")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(not_a_directory / "audit.jsonl"))

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 2
    assert "AGENTIC_MISP_MCP_AUDIT_LOG_PATH" in captured.err
    assert "not a directory" in captured.err


def test_config_check_does_not_print_secret(monkeypatch, tmp_path, capsys):
    secret = "do-not-print-this-secret"
    _valid_env(monkeypatch, tmp_path, api_key=secret)

    code = main(["config-check"])

    captured = capsys.readouterr()
    assert code == 0
    assert secret not in captured.out
    assert secret not in captured.err


def test_openapi_inventory_writes_markdown_file(tmp_path, capsys):
    spec_file = tmp_path / "misp-openapi.json"
    spec_file.write_text(json.dumps(MINIMAL_OPENAPI_SPEC), encoding="utf-8")
    output_file = tmp_path / "openapi-inventory.md"

    code = main(["openapi-inventory", "--input", str(spec_file), "--output", str(output_file)])

    output = capsys.readouterr().out
    assert code == 0
    assert "Wrote OpenAPI inventory for 2 endpoint(s)" in output
    assert output_file.exists()
    written = output_file.read_text(encoding="utf-8")
    assert "MISP OpenAPI Inventory" in written
    assert "Planning only" in written


def test_openapi_inventory_reports_missing_input_file(tmp_path):
    missing_file = tmp_path / "does-not-exist.json"

    with pytest.raises(SystemExit) as exc:
        main(["openapi-inventory", "--input", str(missing_file)])

    assert exc.value.code == 2


def test_openapi_inventory_reports_invalid_json(tmp_path):
    bad_file = tmp_path / "bad-spec.json"
    bad_file.write_text("not json", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main(["openapi-inventory", "--input", str(bad_file)])

    assert exc.value.code == 2
