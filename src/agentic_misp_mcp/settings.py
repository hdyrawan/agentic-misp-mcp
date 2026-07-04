from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(extra="ignore")

    misp_url: AnyHttpUrl = Field(validation_alias="MISP_URL")
    misp_api_key: str = Field(validation_alias="MISP_API_KEY", min_length=1)
    misp_verify_tls: bool = Field(default=True, validation_alias="MISP_VERIFY_TLS")
    misp_timeout_seconds: float = Field(default=30, validation_alias="MISP_TIMEOUT_SECONDS", gt=0)
    misp_default_limit: int = Field(default=20, validation_alias="MISP_DEFAULT_LIMIT", ge=1)
    misp_max_limit: int = Field(default=100, validation_alias="MISP_MAX_LIMIT", ge=1)
    misp_event_attribute_limit: int = Field(
        default=50, validation_alias="MISP_EVENT_ATTRIBUTE_LIMIT", ge=1
    )
    misp_related_event_limit: int = Field(
        default=5, validation_alias="MISP_RELATED_EVENT_LIMIT", ge=0
    )
    audit_log_path: Path = Field(
        default=Path("./logs/audit.jsonl"),
        validation_alias="AGENTIC_MISP_MCP_AUDIT_LOG_PATH",
    )
    log_level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"] = Field(
        default="INFO", validation_alias="AGENTIC_MISP_MCP_LOG_LEVEL"
    )

    @field_validator("misp_api_key")
    @classmethod
    def api_key_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("MISP_API_KEY must not be blank")
        return value

    @field_validator("misp_max_limit")
    @classmethod
    def max_limit_must_be_positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("MISP_MAX_LIMIT must be >= 1")
        return value

    def clamp_limit(self, requested: int | None) -> int:
        if requested is None:
            requested = self.misp_default_limit
        if requested < 1:
            requested = self.misp_default_limit
        return min(requested, self.misp_max_limit)

    @property
    def misp_base_url(self) -> str:
        return str(self.misp_url).rstrip("/")
