from __future__ import annotations

import json

import httpx
import pytest

from agentic_misp_mcp.exceptions import (
    MISPAuthenticationError,
    MISPNotFoundError,
    MISPResponseTooLargeError,
)
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


@pytest.mark.asyncio
async def test_add_attribute_sends_payload_and_parses(settings):
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"Attribute": {"id": "5", "event_id": "42", "type": "ip-dst", "value": "1.2.3.4"}},
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        attribute = await client.add_attribute(42, {"type": "ip-dst", "value": "1.2.3.4"})
    finally:
        await client.aclose()

    assert seen == {
        "path": "/attributes/add/42",
        "body": {"type": "ip-dst", "value": "1.2.3.4"},
    }
    assert attribute.event_id == 42
    assert attribute.value == "1.2.3.4"


@pytest.mark.asyncio
async def test_add_sighting_sends_payload_and_parses(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/sightings/add"
        return httpx.Response(
            200, json={"Sighting": {"id": "7", "value": "1.2.3.4", "type": "0", "event_id": "42"}}
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        sighting = await client.add_sighting({"type": "0", "value": "1.2.3.4"})
    finally:
        await client.aclose()

    assert sighting.value == "1.2.3.4"
    assert sighting.event_id == 42


@pytest.mark.asyncio
async def test_tag_event_sends_payload_and_parses(settings):
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"saved": True, "message": "Tag added"})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = await client.tag_event(42, "tlp:amber")
    finally:
        await client.aclose()

    assert seen == {"path": "/events/addTag/42", "body": {"tag": "tlp:amber"}}
    assert result.event_id == 42
    assert result.tag == "tlp:amber"
    assert result.saved is True


@pytest.mark.asyncio
async def test_publish_event_sends_request_and_parses(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/events/publish/42"
        assert request.method == "POST"
        return httpx.Response(200, json={"name": "Job queued", "message": "Job queued"})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        result = await client.publish_event(42)
    finally:
        await client.aclose()

    assert result.event_id == 42
    assert result.published is True


@pytest.mark.asyncio
async def test_response_size_cap_rejects_large_content_length(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "2048"}, content=b"{}")

    settings.max_response_bytes = 1024
    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MISPResponseTooLargeError):
            await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_response_size_cap_rejects_large_actual_body_without_content_length(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b" " * 1025)

    settings.max_response_bytes = 1024
    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MISPResponseTooLargeError):
            await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_response_size_cap_rejects_dishonest_small_content_length(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "2"},
            content=b" " * 1025,
        )

    settings.max_response_bytes = 1024
    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(MISPResponseTooLargeError):
            await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_response_size_cap_allows_normal_response_under_limit(settings):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": []})

    settings.max_response_bytes = 1024
    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        matches = await client.search_attributes("1.2.3.4", 20)
    finally:
        await client.aclose()

    assert matches == []


@pytest.mark.asyncio
async def test_search_sightings_uses_rest_search_and_parses(settings):
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "response": [
                    {
                        "Sighting": {
                            "event_id": "42",
                            "attribute_id": "7",
                            "type": "0",
                            "source": "sensor",
                            "date_sighting": "1783209600",
                        }
                    }
                ]
            },
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        sightings = await client.search_sightings("1.2.3.4", 10)
    finally:
        await client.aclose()

    assert seen == {
        "path": "/sightings/restSearch",
        "body": {"returnFormat": "json", "value": "1.2.3.4", "limit": 10},
    }
    assert sightings[0].event_id == 42
    assert sightings[0].attribute_id == "7"
    assert sightings[0].source == "sensor"
    assert sightings[0].date_sighting is not None


@pytest.mark.asyncio
async def test_search_events_uses_bounded_filters_and_skips_malformed(settings):
    seen = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "response": [
                    {"Event": {"id": "9", "info": "event", "date": "2026-07-05"}},
                    {"Event": {"info": "missing id"}},
                ]
            },
        )

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        events = await client.search_events(
            date_from="2026-07-01",
            date_to="2026-07-05",
            published=True,
            org="CIRCL",
            limit=20,
        )
    finally:
        await client.aclose()

    assert seen == {
        "path": "/events/restSearch",
        "body": {
            "returnFormat": "json",
            "limit": 20,
            "datefrom": "2026-07-01",
            "dateto": "2026-07-05",
            "published": True,
            "org": "CIRCL",
        },
    }
    assert len(events) == 1
    assert events[0].id == 9


@pytest.mark.asyncio
async def test_get_version_and_warninglist_probe(settings):
    paths = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/servers/getVersion":
            return httpx.Response(200, json={"version": "2.5.42"})
        return httpx.Response(200, json={"result": []})

    client = MISPClient(settings, transport=httpx.MockTransport(handler))
    try:
        version = await client.get_version()
        available = await client.probe_warninglists_available()
    finally:
        await client.aclose()

    assert version == "2.5.42"
    assert available is True
    assert paths == ["/servers/getVersion", "/warninglists/checkValue"]
