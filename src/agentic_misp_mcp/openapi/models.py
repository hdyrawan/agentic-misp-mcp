from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Classification = Literal["read", "write", "admin", "sync", "dangerous", "unknown"]
RiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
RecommendedRole = Literal["read_only", "analyst_write", "curator", "admin", "unknown"]

CLASSIFICATION_ORDER: tuple[Classification, ...] = (
    "read",
    "write",
    "admin",
    "sync",
    "dangerous",
    "unknown",
)
RISK_LEVEL_ORDER: tuple[RiskLevel, ...] = ("low", "medium", "high", "critical", "unknown")


class EndpointInventoryEntry(BaseModel):
    """A single classified MISP OpenAPI endpoint.

    This is a planning artifact only. It never becomes an MCP tool.
    """

    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    tags: list[str] = Field(default_factory=list)
    category: str
    classification: Classification
    risk_level: RiskLevel
    approval_required: bool
    recommended_role: RecommendedRole
