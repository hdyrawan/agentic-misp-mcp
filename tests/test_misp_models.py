from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentic_misp_mcp.models.misp import parse_attribute, parse_event, parse_misp_datetime


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1783154993", datetime.fromtimestamp(1783154993, tz=UTC)),
        (1783154993, datetime.fromtimestamp(1783154993, tz=UTC)),
        ("2026-07-01T09:14:00+00:00", datetime(2026, 7, 1, 9, 14, tzinfo=UTC)),
        ("2026-07-01 09:14:00", datetime(2026, 7, 1, 9, 14, tzinfo=UTC)),
        ("", None),
        ("   ", None),
        (None, None),
        ("0", None),
        (0, None),
        (True, None),
        ("not-a-date", None),
        ([], None),
    ],
)
def test_parse_misp_datetime_shapes(raw, expected):
    assert parse_misp_datetime(raw) == expected


def test_parse_attribute_extracts_timestamps_and_empty_seen_fields():
    raw = {
        "Attribute": {
            "id": "511388",
            "event_id": "1641",
            "type": "ip-dst",
            "value": "203.0.113.183",
            "timestamp": "1783154993",
            "first_seen": "",
            "last_seen": "",
        }
    }
    attr = parse_attribute(raw)
    assert attr.timestamp == datetime.fromtimestamp(1783154993, tz=UTC)
    assert attr.first_seen is None
    assert attr.last_seen is None


def test_parse_attribute_iso_first_seen():
    attr = parse_attribute(
        {"type": "domain", "value": "evil.test", "first_seen": "2026-06-01T00:00:00+00:00"}
    )
    assert attr.first_seen == datetime(2026, 6, 1, tzinfo=UTC)


def test_parse_event_extracts_publish_metadata():
    raw = {
        "Event": {
            "id": "1641",
            "info": "sandbox",
            "date": "2026-07-04",
            "timestamp": "1783154000",
            "publish_timestamp": "1783155000",
            "published": True,
        }
    }
    event = parse_event(raw, attribute_limit=0)
    assert event.timestamp == datetime.fromtimestamp(1783154000, tz=UTC)
    assert event.publish_timestamp == datetime.fromtimestamp(1783155000, tz=UTC)
    assert event.published is True


def test_parse_event_missing_publish_metadata_is_none():
    event = parse_event({"Event": {"id": "5", "publish_timestamp": "0"}}, attribute_limit=0)
    assert event.timestamp is None
    assert event.publish_timestamp is None
    assert event.published is None
