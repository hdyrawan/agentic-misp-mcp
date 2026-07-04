from __future__ import annotations

import httpx
import pytest

from agentic_misp_mcp.exceptions import MISPAuthenticationError, MISPNotFoundError
from agentic_misp_mcp.misp.client import MISPClient


@pytest.mark.asyncio
async def test_search_attributes_sends_auth_and_parses(settings):
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["path"] = request.url.path
        return httpx.Response(
            200,
            json={
                "response": [
                    {
                        "Attribute": {
                            "id": "1",
                            "event_id": "42",
                            "type": "ip-dst",
                            "category": "Network activity",
                            "value": "1.2.3.4",
                            "Tag": [{"name": "tlp:amber"}],
                        }
                    }
                ]
            },
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        matches = await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()

    assert seen == {"auth": "test-secret-key", "path": "/attributes/restSearch"}
    assert matches[0].event_id == 42
    assert matches[0].tags == ["tlp:amber"]


@pytest.mark.asyncio
async def test_get_event_limits_attributes(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "Event": {
                    "id": "42",
                    "info": "test event",
                    "Attribute": [
                        {"type": "ip-dst", "value": "1.2.3.4"},
                        {"type": "domain", "value": "example.org"},
                    ],
                }
            },
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        event = await client.get_event(42, attribute_limit=1)
    finally:
        await client.aclose()

    assert event.id == 42
    assert event.attribute_count == 2
    assert len(event.attributes) == 1
    assert event.attributes_by_type == {"ip-dst": 1, "domain": 1}


@pytest.mark.asyncio
async def test_auth_error_normalized(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": "forbidden"})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MISPAuthenticationError):
            await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_warninglist_not_available_on_404(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = await client.check_warninglists("1.2.3.4")
    finally:
        await client.aclose()

    assert result.status == "not_available"


@pytest.mark.asyncio
async def test_search_events_by_tag_parses_event_list(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/events/restSearch"
        return httpx.Response(
            200,
            json={
                "response": [
                    {
                        "Event": {
                            "id": "1",
                            "info": "tagged event",
                            "Tag": [{"name": "malware:family=test"}],
                            "Attribute": [{"type": "ip-dst", "value": "1.2.3.4"}],
                        }
                    }
                ]
            },
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        events = await client.search_events_by_tag("malware:family=test", 20)
    finally:
        await client.aclose()

    assert len(events) == 1
    assert events[0].id == 1
    assert events[0].tags == ["malware:family=test"]
    assert events[0].attribute_count == 1
    assert events[0].attributes == []


@pytest.mark.asyncio
async def test_not_found_normalized(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MISPNotFoundError):
            await client.get_event(999, attribute_limit=5)
    finally:
        await client.aclose()
