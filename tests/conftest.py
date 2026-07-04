from __future__ import annotations

import pytest

from agentic_misp_mcp.settings import Settings


@pytest.fixture
def settings(monkeypatch, tmp_path):
    monkeypatch.setenv("MISP_URL", "https://misp.example.test")
    monkeypatch.setenv("MISP_API_KEY", "test-secret-key")
    monkeypatch.setenv("AGENTIC_MISP_MCP_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    return Settings()
