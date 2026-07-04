from __future__ import annotations

from pydantic import BaseModel, Field


class ReportFinding(BaseModel):
    title: str
    detail: str
    severity: str = "informational"


class IOCInvestigationReport(BaseModel):
    title: str
    executive_summary: str
    ioc: dict[str, str]
    misp_findings: list[ReportFinding] = Field(default_factory=list)
    warninglist_findings: list[ReportFinding] = Field(default_factory=list)
    related_events: list[dict[str, object]] = Field(default_factory=list)
    confidence: str
    recommended_actions: list[str] = Field(default_factory=list)
