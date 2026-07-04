from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentic_misp_mcp.security.sanitization import contains_secret_key_recursive


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
    PUBLISH = "publish"
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

    Approval metadata only. It does not persist approvals and does not execute approved writes.
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
        if contains_secret_key_recursive(value):
            raise ValueError(
                "approval proposals must not include secrets or authorization material"
            )
        return value


class ApprovalStatus(StrEnum):
    """Persisted approval lifecycle states and redemption failure details."""

    PENDING = "pending"
    APPROVED = "approved"
    USED = "used"
    REJECTED = "rejected"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"
    WRONG_TOOL = "wrong_tool"
    HASH_MISMATCH = "hash_mismatch"
    ALREADY_USED = "already_used"
    NOT_YET_APPROVED = "not_yet_approved"


class StoredApprovalRecord(BaseModel):
    """Persisted production approval record.

    Stores sanitized proposed arguments for operator review and the exact canonical operation
    hash for redemption. It intentionally does not store approval tokens, MISP API keys, or
    caller-provided metadata that is not part of the business operation.
    """

    model_config = ConfigDict(hide_input_in_errors=True)

    request_id: str
    tool_name: str
    operation_hash: str
    proposed_arguments: dict[str, Any] = Field(default_factory=dict)
    role: Role
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    approved_at: datetime | None = None
    approved_by: str | None = None
    used_at: datetime | None = None
    rejected_at: datetime | None = None
    rejected_reason: str | None = None

    @field_validator("proposed_arguments")
    @classmethod
    def stored_arguments_must_not_include_obvious_secrets(
        cls, value: dict[str, Any]
    ) -> dict[str, Any]:
        if contains_secret_key_recursive(value):
            raise ValueError("stored approval records must not include secrets")
        return value


class ApprovalStoreError(RuntimeError):
    """Base error for production approval persistence failures."""


class ApprovalRedemptionError(ApprovalStoreError):
    """Raised when approval redemption is blocked."""

    def __init__(self, status: ApprovalStatus, message: str | None = None) -> None:
        self.status = status
        super().__init__(message or status.value)
