from __future__ import annotations

import json
from typing import Any

import httpx

from agentic_misp_mcp.exceptions import (
    MISPAuthenticationError,
    MISPClientError,
    MISPNotFoundError,
    MISPRateLimitError,
    MISPResponseTooLargeError,
)
from agentic_misp_mcp.misp.queries import (
    attribute_search_payload,
    event_tag_search_payload,
    tag_payload,
    warninglist_check_payload,
)
from agentic_misp_mcp.misp.warninglists import (
    WarninglistCheckResult,
    parse_warninglist_response,
)
from agentic_misp_mcp.models.misp import (
    MISPAttributeSummary,
    MISPEventSummary,
    MISPPublishResult,
    MISPSightingSummary,
    MISPTagResult,
    parse_attribute,
    parse_event,
    parse_publish_result,
    parse_sighting,
    parse_tag_result,
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
        response: httpx.Response | None = None
        try:
            request = self._client.build_request(method, path, **kwargs)
            response = await self._client.send(request, stream=True)
            content = await self._read_bounded_response(response)
        except httpx.HTTPError as exc:
            raise MISPClientError(f"MISP request failed: {type(exc).__name__}") from exc
        finally:
            if response is not None:
                await response.aclose()
        assert response is not None
        if response.status_code in {401, 403}:
            raise MISPAuthenticationError("MISP authentication/authorization failed")
        if response.status_code == 404:
            raise MISPNotFoundError("MISP resource not found")
        if response.status_code == 429:
            raise MISPRateLimitError("MISP rate limit reached")
        if response.status_code >= 400:
            raise MISPClientError(f"MISP request failed with HTTP {response.status_code}")
        try:
            return json.loads(content)
        except ValueError as exc:
            raise MISPClientError("MISP returned non-JSON response") from exc

    async def _read_bounded_response(self, response: httpx.Response) -> bytes:
        max_bytes = self.settings.max_response_bytes
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = None
            if declared_length is not None and declared_length > max_bytes:
                raise MISPResponseTooLargeError(
                    f"MISP response exceeded configured limit of {max_bytes} bytes"
                )

        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise MISPResponseTooLargeError(
                    f"MISP response exceeded configured limit of {max_bytes} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)

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

    async def search_events_by_tag(self, tag: str, limit: int) -> list[MISPEventSummary]:
        raw = await self._request(
            "POST", "/events/restSearch", json=event_tag_search_payload(tag, limit)
        )
        records: list[Any]
        if isinstance(raw, dict):
            response = raw.get("response", raw)
            if isinstance(response, dict):
                records = response.get("Event") or response.get("events") or []
            elif isinstance(response, list):
                records = response
            else:
                records = []
        elif isinstance(raw, list):
            records = raw
        else:
            records = []

        events: list[MISPEventSummary] = []
        for item in records[:limit]:
            if not isinstance(item, dict):
                continue
            try:
                events.append(parse_event(item, attribute_limit=0))
            except ValueError:
                continue
        return events

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

    # Controlled write methods (Phase 8). Each maps to exactly one narrow MISP write
    # endpoint and is only ever invoked after policy allow + approval checks upstream.
    # There is no generic request proxy exposed here or through any MCP tool.

    async def add_attribute(
        self, event_id: int, payload: dict[str, object]
    ) -> MISPAttributeSummary:
        raw = await self._request("POST", f"/attributes/add/{event_id}", json=payload)
        if not isinstance(raw, dict):
            raise MISPClientError("MISP attribute creation response was not an object")
        return parse_attribute(raw)

    async def add_sighting(self, payload: dict[str, object]) -> MISPSightingSummary:
        raw = await self._request("POST", "/sightings/add", json=payload)
        if not isinstance(raw, dict):
            raise MISPClientError("MISP sighting response was not an object")
        return parse_sighting(raw)

    async def tag_event(self, event_id: int, tag: str) -> MISPTagResult:
        raw = await self._request("POST", f"/events/addTag/{event_id}", json=tag_payload(tag))
        if not isinstance(raw, dict):
            raise MISPClientError("MISP tag response was not an object")
        return parse_tag_result(raw, event_id=event_id, tag=tag)

    async def publish_event(self, event_id: int) -> MISPPublishResult:
        raw = await self._request("POST", f"/events/publish/{event_id}")
        if not isinstance(raw, dict):
            raise MISPClientError("MISP publish response was not an object")
        return parse_publish_result(raw, event_id=event_id)
