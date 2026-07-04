from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Role(StrEnum):
    """Policy roles for current and future MISP workflows."""

    READ_ONLY = "read_only"
    ANALYST_WRITE = "analyst_write"
    CURATOR = "curator"
    ADMIN = "admin"


class Action(StrEnum):
    """Coarse action categories enforced before workflow execution."""

    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    SYNC = "sync"
    DANGEROUS = "dangerous"


class PolicyDecision(BaseModel):
    """Result of policy evaluation for a tool/action pair."""

    allowed: bool
    approval_required: bool
    reason: str
    role: str
    action: str
    tool_name: str


class ToolPolicy(BaseModel):
    """Static action classification for an MCP tool."""

    tool_name: str
    action: Action = Action.READ


class ApprovalRequest(BaseModel):
    """Future approval proposal envelope for controlled write workflows.

    Phase 7 only models approval metadata. It does not persist approvals and does not execute
    approved writes.
    """

    model_config = ConfigDict(hide_input_in_errors=True)

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    action: Action
    role: Role
    reason: str
    proposed_arguments: dict[str, Any] = Field(default_factory=dict)
    requester: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))  # noqa: UP017

    @field_validator("proposed_arguments")
    @classmethod
    def proposed_arguments_must_not_include_obvious_secrets(
        cls, value: dict[str, Any]
    ) -> dict[str, Any]:
        sensitive_keys = {"api_key", "authorization", "authkey", "headers", "misp_api_key", "token"}
        contains_unredacted_secret_key = any(
            str(key).lower() in sensitive_keys and nested != "[REDACTED]"
            for key, nested in value.items()
        )
        if contains_unredacted_secret_key:
            raise ValueError(
                "approval proposals must not include secrets or authorization material"
            )
        return value
