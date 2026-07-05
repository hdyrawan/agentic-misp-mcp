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
    assert settings.approval_mode == "lab"
    assert str(settings.approval_store_path) == "approvals.sqlite3"
    assert settings.approval_ttl_seconds == 900
    assert settings.enable_publish is False
    assert settings.allowed_attribute_types == ()
    assert settings.allowed_tags == ()


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


def test_blank_approval_token_env_var_becomes_none(monkeypatch):
    """A present-but-empty AGENTIC_MISP_MCP_APPROVAL_TOKEN (e.g. `KEY=` in a .env file) must
    behave identically to the variable being unset, not as a configured empty-string token that
    silently blocks every controlled-write execution."""
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_TOKEN", "")

    settings = Settings()

    assert settings.approval_token is None


def test_validation_error_hides_misp_api_key_input(monkeypatch):
    secret = "do-not-leak-this-key"
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", secret)
    monkeypatch.setenv("MISP_TIMEOUT_SECONDS", "0")

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value.errors(include_url=False))


def test_production_approval_and_allowlist_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_MODE", "production")
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_STORE_PATH", str(tmp_path / "approvals.sqlite3"))
    monkeypatch.setenv("AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS", "60")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ENABLE_PUBLISH", "true")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES", "ip-dst, url")
    monkeypatch.setenv("AGENTIC_MISP_MCP_ALLOWED_TAGS", "tlp:*, misp-galaxy:foo")

    settings = Settings()

    assert settings.approval_mode == "production"
    assert settings.approval_store_path == tmp_path / "approvals.sqlite3"
    assert settings.approval_ttl_seconds == 60
    assert settings.enable_publish is True
    assert settings.allowed_attribute_types == ("ip-dst", "url")
    assert settings.allowed_tags == ("tlp:*", "misp-galaxy:foo")


def _freshness_env(monkeypatch, **env):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "secret")
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_freshness_defaults(monkeypatch):
    _freshness_env(monkeypatch)

    settings = Settings()

    assert settings.freshness_fresh_days == 30
    assert settings.freshness_aging_days == 90
    assert settings.freshness_stale_days == 365
    assert settings.age_weighting is True
    assert settings.age_weights == (1.0, 0.75, 0.4, 0.15)


def test_freshness_thresholds_configurable(monkeypatch):
    _freshness_env(
        monkeypatch,
        AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS="7",
        AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS="14",
        AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS="60",
        AGENTIC_MISP_MCP_AGE_WEIGHTING="false",
    )

    settings = Settings()

    assert (settings.freshness_fresh_days, settings.freshness_aging_days) == (7, 14)
    assert settings.freshness_stale_days == 60
    assert settings.age_weighting is False


def test_freshness_threshold_misordering_fails(monkeypatch):
    _freshness_env(
        monkeypatch,
        AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS="90",
        AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS="90",
    )

    with pytest.raises(ValidationError, match="ordered"):
        Settings()


def test_freshness_threshold_must_be_positive(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS="0")

    with pytest.raises(ValidationError):
        Settings()


def test_age_weights_csv_parsing(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_AGE_WEIGHTS="1.0, 0.9, 0.5, 0.1")

    assert Settings().age_weights == (1.0, 0.9, 0.5, 0.1)


def test_age_weights_out_of_range_fails(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_AGE_WEIGHTS="1.5,0.75,0.4,0.15")

    with pytest.raises(ValidationError, match="between 0 and 1"):
        Settings()


def test_age_weights_negative_fails(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_AGE_WEIGHTS="1.0,0.75,0.4,-0.1")

    with pytest.raises(ValidationError, match="between 0 and 1"):
        Settings()


def test_age_weights_wrong_count_fails(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_AGE_WEIGHTS="1.0,0.75")

    with pytest.raises(ValidationError):
        Settings()


def test_age_weights_non_numeric_fails(monkeypatch):
    _freshness_env(monkeypatch, AGENTIC_MISP_MCP_AGE_WEIGHTS="high,low,mid,none")

    with pytest.raises(ValidationError, match="comma-separated numbers"):
        Settings()
