from __future__ import annotations

import pytest
from pydantic import ValidationError

from agentic_misp_mcp.settings import Settings


def test_settings_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    monkeypatch.delenv("MISP_VERIFY_TLS", raising=False)
    monkeypatch.delenv("MISP_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", raising=False)

    settings = Settings()

    assert settings.misp_verify_tls is True
    assert settings.misp_timeout_seconds == 30
    assert settings.misp_default_limit == 20
    assert settings.misp_max_limit == 100
    assert settings.misp_event_attribute_limit == 50
    assert settings.misp_related_event_limit == 5
    assert str(settings.audit_log_path) == "logs/audit.jsonl"
    assert settings.policy_role == "read_only"
    assert settings.enable_write is False
    assert settings.require_approval is True


def test_missing_api_key_fails(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.delenv("MISP_API_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings()


def test_clamp_limit(settings):
    assert settings.clamp_limit(None) == 20
    assert settings.clamp_limit(0) == 20
    assert settings.clamp_limit(999) == 100
    assert settings.clamp_limit(7) == 7


def test_settings_new_security_defaults(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")

    settings = Settings()

    assert settings.approval_token is None
    assert settings.max_response_bytes == 5_242_880
    assert settings.allow_insecure_http_bind is False


def test_validation_error_hides_misp_api_key_input(monkeypatch):
    secret = "do-not-leak-this-key"
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", secret)
    monkeypatch.setenv("MISP_TIMEOUT_SECONDS", "0")

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value.errors(include_url=False))
