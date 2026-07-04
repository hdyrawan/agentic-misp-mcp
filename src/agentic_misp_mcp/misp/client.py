from __future__ import annotations

from typing import Any

import httpx

from agentic_misp_mcp.exceptions import (
    MISPAuthenticationError,
    MISPClientError,
    MISPNotFoundError,
    MISPRateLimitError,
)
from agentic_misp_mcp.misp.queries import attribute_search_payload, warninglist_check_payload
from agentic_misp_mcp.misp.warninglists import (
    WarninglistCheckResult,
    parse_warninglist_response,
)
from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPEventSummary,
    parse_attribute,
    parse_event,
)
from agentic_misp_mcp.settings import Settings


class MISPClient:
    """Small read-only async client for v0.1 workflow needs."""

    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.misp_base_url,
            headers={
                "Authorization": settings.misp_api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=settings.misp_timeout_seconds,
            verify=settings.misp_verify_tls,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise MISPClientError(f"MISP request failed: {type(exc).__name__}") from exc
        if response.status_code in {401, 403}:
            raise MISPAuthenticationError("MISP authentication/authorization failed")
        if response.status_code == 404:
            raise MISPNotFoundError("MISP resource not found")
        if response.status_code == 429:
            raise MISPRateLimitError("MISP rate limit reached")
        if response.status_code >= 400:
            raise MISPClientError(f"MISP request failed with HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise MISPClientError("MISP returned non-JSON response") from exc

    async def search_attributes(self, value: str, limit: int) -> list[MISPAttributeSummary]:
        raw = await self._request(
            "POST", "/attributes/restSearch", json=attribute_search_payload(value, limit)
        )
        records: list[Any]
        if isinstance(raw, dict):
            response = raw.get("response", raw)
            if isinstance(response, dict):
                records = response.get("Attribute") or response.get("attributes") or []
            elif isinstance(response, list):
                records = response
            else:
                records = []
        elif isinstance(raw, list):
            records = raw
        else:
            records = []
        return [parse_attribute(item) for item in records[:limit] if isinstance(item, dict)]

    async def get_event(self, event_id: int, attribute_limit: int) -> MISPEventSummary:
        raw = await self._request("GET", f"/events/view/{event_id}")
        if not isinstance(raw, dict):
            raise MISPClientError("MISP event response was not an object")
        return parse_event(raw, attribute_limit=attribute_limit)

    async def check_warninglists(self, value: str) -> WarninglistCheckResult:
        # The exact endpoint/shape varies by MISP version. Keep isolated and return
        # structured not_available/error states for unsupported responses.
        try:
            raw = await self._request(
                "POST", "/warninglists/checkValue", json=warninglist_check_payload(value)
            )
        except MISPNotFoundError:
            return WarninglistCheckResult(
                status="not_available", message="MISP warninglist check endpoint not available"
            )
        return parse_warninglist_response(raw)
