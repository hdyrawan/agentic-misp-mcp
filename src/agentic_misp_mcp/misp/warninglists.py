from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class WarninglistCheckResult(BaseModel):
    status: str = Field(description="available, not_available, or error")
    hit: bool = False
    matches: list[dict[str, Any]] = Field(default_factory=list)
    message: str | None = None


def parse_warninglist_response(raw: Any) -> WarninglistCheckResult:
    """Normalize known MISP warninglist response shapes.

    MISP warninglist behavior varies by version/deployment. Unknown shapes return
    `not_available` instead of a false success.
    """
    if raw is None:
        return WarninglistCheckResult(status="not_available", message="Empty warninglist response")
    if isinstance(raw, dict):
        if raw.get("not_available") is True:
            return WarninglistCheckResult(
                status="not_available", message=str(raw.get("message") or "")
            )
        if raw.get("error"):
            return WarninglistCheckResult(status="error", message=str(raw.get("error")))
        if "matches" in raw and isinstance(raw["matches"], list):
            return WarninglistCheckResult(
                status="available", hit=bool(raw["matches"]), matches=raw["matches"]
            )
        if "result" in raw:
            result = raw["result"]
            if isinstance(result, list):
                return WarninglistCheckResult(status="available", hit=bool(result), matches=result)
            if isinstance(result, dict):
                matches = result.get("matches") or result.get("values") or []
                if isinstance(matches, list):
                    return WarninglistCheckResult(
                        status="available", hit=bool(matches), matches=matches
                    )
        if "Warninglist" in raw:
            return WarninglistCheckResult(status="available", hit=True, matches=[raw])
        if raw.get("success") is False:
            return WarninglistCheckResult(
                status="not_available", message=str(raw.get("message") or "")
            )
    if isinstance(raw, list):
        return WarninglistCheckResult(status="available", hit=bool(raw), matches=raw)
    return WarninglistCheckResult(
        status="not_available", message="Unrecognized MISP warninglist response shape"
    )
