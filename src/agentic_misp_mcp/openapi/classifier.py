from __future__ import annotations

from dataclasses import dataclass

from agentic_misp_mcp.openapi.models import Classification, RecommendedRole, RiskLevel

# Order matters: more specific/severe categories are checked before broader ones so that,
# for example, "/servers/pull" is classified as sync rather than admin, and "/attributes/
# restSearch" is classified as read even though it is a POST endpoint.
DANGEROUS_KEYWORDS = (
    "purge",
    "restartworkers",
    "restart_workers",
    "resetauthkey",
    "reset_auth_key",
    "deleteall",
    "delete_all",
    "shutdown",
)
SYNC_KEYWORDS = ("sync", "pull", "push", "feed")
ADMIN_KEYWORDS = (
    "user",
    "organisation",
    "organization",
    "org",
    "auth_key",
    "authkey",
    "server",
    "setting",
    "admin",
    "role",
)
CRITICAL_ADMIN_KEYWORDS = ("delete", "auth_key", "authkey", "setting")
READ_KEYWORDS = ("search", "view", "list", "index", "restsearch", "export", "fetch")
WRITE_KEYWORDS = (
    "add",
    "create",
    "edit",
    "update",
    "delete",
    "publish",
    "tag",
    "sighting",
    "untag",
    "populate",
    "modify",
    "remove",
)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class ClassificationResult:
    classification: Classification
    risk_level: RiskLevel
    approval_required: bool
    recommended_role: RecommendedRole


def classify_endpoint(
    *,
    path: str,
    method: str,
    operation_id: str | None = None,
    summary: str | None = None,
    tags: list[str] | None = None,
) -> ClassificationResult:
    """Deterministically classify a MISP OpenAPI endpoint from its path/method/metadata.

    This is a conservative, keyword-based heuristic. When no rule confidently matches,
    the endpoint is classified as `unknown` rather than guessed.
    """
    haystack = _build_haystack(
        path=path, operation_id=operation_id, summary=summary, tags=tags or []
    )
    method_upper = (method or "").upper()

    if _contains_any(haystack, DANGEROUS_KEYWORDS):
        return ClassificationResult("dangerous", "critical", True, "admin")

    if _contains_any(haystack, SYNC_KEYWORDS):
        return ClassificationResult("sync", "medium", True, "curator")

    if _contains_any(haystack, ADMIN_KEYWORDS):
        risk: RiskLevel = "critical" if _contains_any(haystack, CRITICAL_ADMIN_KEYWORDS) else "high"
        return ClassificationResult("admin", risk, True, "admin")

    if _contains_any(haystack, READ_KEYWORDS):
        return ClassificationResult("read", "low", False, "read_only")

    if _contains_any(haystack, WRITE_KEYWORDS) or method_upper in WRITE_METHODS:
        if "delete" in haystack:
            write_risk: RiskLevel = "critical"
        elif "publish" in haystack:
            write_risk = "high"
        else:
            write_risk = "medium"
        return ClassificationResult("write", write_risk, True, "analyst_write")

    if method_upper == "GET":
        return ClassificationResult("read", "low", False, "read_only")

    return ClassificationResult("unknown", "unknown", False, "unknown")


def _build_haystack(
    *, path: str, operation_id: str | None, summary: str | None, tags: list[str]
) -> str:
    parts = [path or "", operation_id or "", summary or "", " ".join(tags)]
    return " ".join(parts).lower()


def _contains_any(haystack: str, keywords: tuple[str, ...]) -> bool:
    return any(keyword in haystack for keyword in keywords)
