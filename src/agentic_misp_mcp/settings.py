from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(extra="ignore", hide_input_in_errors=True)

    misp_url: AnyHttpUrl = Field(validation_alias="MISP_URL")
    misp_api_key: str = Field(validation_alias="MISP_API_KEY", min_length=1)
    misp_verify_tls: bool = Field(default=True, validation_alias="MISP_VERIFY_TLS")
    misp_timeout_seconds: float = Field(
        default=30, validation_alias="MISP_TIMEOUT_SECONDS", gt=0, le=300
    )
    misp_default_limit: int = Field(
        default=20, validation_alias="MISP_DEFAULT_LIMIT", ge=1, le=1000
    )
    misp_max_limit: int = Field(default=100, validation_alias="MISP_MAX_LIMIT", ge=1, le=1000)
    misp_event_attribute_limit: int = Field(
        default=50, validation_alias="MISP_EVENT_ATTRIBUTE_LIMIT", ge=1, le=1000
    )
    misp_related_event_limit: int = Field(
        default=5, validation_alias="MISP_RELATED_EVENT_LIMIT", ge=0, le=100
    )
    audit_log_path: Path = Field(
        default=Path("./logs/audit.jsonl"),
        validation_alias="AGENTIC_MISP_MCP_AUDIT_LOG_PATH",
    )
    log_level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"] = Field(
        default="INFO", validation_alias="AGENTIC_MISP_MCP_LOG_LEVEL"
    )
    policy_role: Literal["read_only", "analyst_write", "curator", "admin"] = Field(
        default="read_only", validation_alias="AGENTIC_MISP_MCP_ROLE"
    )
    enable_write: bool = Field(default=False, validation_alias="AGENTIC_MISP_MCP_ENABLE_WRITE")
    require_approval: bool = Field(
        default=True, validation_alias="AGENTIC_MISP_MCP_REQUIRE_APPROVAL"
    )
    approval_token: str | None = Field(
        default=None, validation_alias="AGENTIC_MISP_MCP_APPROVAL_TOKEN"
    )
    approval_mode: Literal["lab", "production"] = Field(
        default="lab", validation_alias="AGENTIC_MISP_MCP_APPROVAL_MODE"
    )
    approval_store_path: Path = Field(
        default=Path("./approvals.sqlite3"),
        validation_alias="AGENTIC_MISP_MCP_APPROVAL_STORE_PATH",
    )
    approval_ttl_seconds: int = Field(
        default=900, validation_alias="AGENTIC_MISP_MCP_APPROVAL_TTL_SECONDS", ge=1
    )
    enable_publish: bool = Field(default=False, validation_alias="AGENTIC_MISP_MCP_ENABLE_PUBLISH")
    allowed_attribute_types: Annotated[tuple[str, ...], NoDecode] = Field(
        default=(), validation_alias="AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES"
    )
    allowed_attribute_categories: Annotated[tuple[str, ...], NoDecode] = Field(
        default=(), validation_alias="AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES"
    )
    allowed_tags: Annotated[tuple[str, ...], NoDecode] = Field(
        default=(), validation_alias="AGENTIC_MISP_MCP_ALLOWED_TAGS"
    )
    max_response_bytes: int = Field(
        default=5_242_880, validation_alias="AGENTIC_MISP_MCP_MAX_RESPONSE_BYTES", ge=1024
    )
    allow_insecure_http_bind: bool = Field(
        default=False, validation_alias="AGENTIC_MISP_MCP_ALLOW_INSECURE_HTTP_BIND"
    )
    freshness_fresh_days: int = Field(
        default=30, validation_alias="AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS", ge=1
    )
    freshness_aging_days: int = Field(
        default=90, validation_alias="AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS", ge=1
    )
    freshness_stale_days: int = Field(
        default=365, validation_alias="AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS", ge=1
    )
    age_weighting: bool = Field(default=True, validation_alias="AGENTIC_MISP_MCP_AGE_WEIGHTING")
    age_weights: Annotated[tuple[float, float, float, float], NoDecode] = Field(
        default=(1.0, 0.75, 0.4, 0.15), validation_alias="AGENTIC_MISP_MCP_AGE_WEIGHTS"
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

    @field_validator("approval_token")
    @classmethod
    def blank_approval_token_becomes_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator(
        "allowed_attribute_types",
        "allowed_attribute_categories",
        "allowed_tags",
        mode="before",
    )
    @classmethod
    def parse_csv_allowlist(cls, value: object) -> tuple[str, ...]:
        if value is None or value == "":
            return ()
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        if isinstance(value, (list, tuple, set)):
            return tuple(str(item).strip() for item in value if str(item).strip())
        raise TypeError("allowlist must be a comma-separated string")

    @field_validator("age_weights", mode="before")
    @classmethod
    def parse_age_weights(cls, value: object) -> tuple[float, ...]:
        if value is None or value == "":
            return (1.0, 0.75, 0.4, 0.15)
        if isinstance(value, str):
            parts = [item.strip() for item in value.split(",") if item.strip()]
            try:
                return tuple(float(item) for item in parts)
            except ValueError as exc:
                raise ValueError(
                    "AGENTIC_MISP_MCP_AGE_WEIGHTS must be four comma-separated numbers"
                ) from exc
        if isinstance(value, (list, tuple)):
            return tuple(float(item) for item in value)
        raise TypeError("AGENTIC_MISP_MCP_AGE_WEIGHTS must be a comma-separated string")

    @field_validator("age_weights")
    @classmethod
    def age_weights_must_be_in_range(
        cls, value: tuple[float, float, float, float]
    ) -> tuple[float, float, float, float]:
        if any(weight < 0.0 or weight > 1.0 for weight in value):
            raise ValueError("AGENTIC_MISP_MCP_AGE_WEIGHTS values must each be between 0 and 1")
        return value

    @model_validator(mode="after")
    def limits_must_be_consistent(self) -> Settings:
        if self.misp_default_limit > self.misp_max_limit:
            raise ValueError("MISP_DEFAULT_LIMIT must be <= MISP_MAX_LIMIT")
        if not (self.freshness_fresh_days < self.freshness_aging_days < self.freshness_stale_days):
            raise ValueError(
                "freshness thresholds must be ordered: AGENTIC_MISP_MCP_FRESHNESS_FRESH_DAYS < "
                "AGENTIC_MISP_MCP_FRESHNESS_AGING_DAYS < AGENTIC_MISP_MCP_FRESHNESS_STALE_DAYS"
            )
        return self

    def clamp_limit(self, requested: int | None) -> int:
        if requested is None:
            requested = self.misp_default_limit
        if requested < 1:
            requested = self.misp_default_limit
        return min(requested, self.misp_max_limit)

    @property
    def misp_base_url(self) -> str:
        return str(self.misp_url).rstrip("/")
