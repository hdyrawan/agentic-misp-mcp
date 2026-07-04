from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MISPTagSummary(BaseModel):
    name: str


class MISPAttributeSummary(BaseModel):
    id: str | None = None
    event_id: int | None = None
    type: str | None = None
    category: str | None = None
    value: str | None = None
    comment: str | None = None
    to_ids: bool | None = None
    tags: list[str] = Field(default_factory=list)


class MISPEventSummary(BaseModel):
    id: int
    info: str | None = None
    date: str | None = None
    threat_level_id: str | None = None
    analysis: str | None = None
    distribution: str | None = None
    tags: list[str] = Field(default_factory=list)
    attribute_count: int = 0
    attributes_by_type: dict[str, int] = Field(default_factory=dict)
    attributes: list[MISPAttributeSummary] = Field(default_factory=list)


class MISPSearchResult(BaseModel):
    matches: list[MISPAttributeSummary] = Field(default_factory=list)
    match_count: int = 0


class MISPSightingSummary(BaseModel):
    id: str | None = None
    value: str | None = None
    event_id: int | None = None
    attribute_id: str | None = None
    type: str | None = None
    saved: bool = False
    message: str | None = None


class MISPTagResult(BaseModel):
    event_id: int
    tag: str
    saved: bool = False
    message: str | None = None


class MISPPublishResult(BaseModel):
    event_id: int
    published: bool = False
    message: str | None = None


def _coerce_event_id(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_tags(raw: Any) -> list[str]:
    tags = []
    if not isinstance(raw, list):
        return tags
    for tag in raw:
        if isinstance(tag, dict):
            name = tag.get("name") or tag.get("Tag", {}).get("name")
            if name:
                tags.append(str(name))
    return tags


def parse_attribute(raw: dict[str, Any]) -> MISPAttributeSummary:
    attr = raw.get("Attribute", raw)
    event_id = _coerce_event_id(attr.get("event_id"))
    return MISPAttributeSummary(
        id=str(attr.get("id")) if attr.get("id") is not None else None,
        event_id=event_id,
        type=attr.get("type"),
        category=attr.get("category"),
        value=attr.get("value"),
        comment=attr.get("comment"),
        to_ids=attr.get("to_ids"),
        tags=parse_tags(attr.get("Tag") or attr.get("tags")),
    )


def parse_event(raw: dict[str, Any], attribute_limit: int) -> MISPEventSummary:
    event = raw.get("Event", raw)
    event_id = _coerce_event_id(event.get("id"))
    if event_id is None:
        raise ValueError("MISP event response did not include an integer id")

    raw_attributes = event.get("Attribute") or event.get("attributes") or []
    attributes = [parse_attribute(item) for item in raw_attributes[:attribute_limit]]
    counts: dict[str, int] = {}
    for item in raw_attributes:
        attr = item.get("Attribute", item) if isinstance(item, dict) else {}
        attr_type = str(attr.get("type") or "unknown")
        counts[attr_type] = counts.get(attr_type, 0) + 1

    return MISPEventSummary(
        id=event_id,
        info=event.get("info"),
        date=event.get("date"),
        threat_level_id=event.get("threat_level_id"),
        analysis=event.get("analysis"),
        distribution=event.get("distribution"),
        tags=parse_tags(event.get("Tag") or event.get("tags")),
        attribute_count=len(raw_attributes),
        attributes_by_type=counts,
        attributes=attributes,
    )


def parse_sighting(raw: dict[str, Any]) -> MISPSightingSummary:
    # MISP answers HTTP 200 with no `Sighting` key (just a `message`, e.g. "No valid
    # attributes found") when it rejects a sighting it cannot attach to a real attribute.
    # That is not distinguishable from a real success by status code alone.
    saved = "Sighting" in raw
    sighting = raw.get("Sighting", raw)
    return MISPSightingSummary(
        id=str(sighting.get("id")) if sighting.get("id") is not None else None,
        value=sighting.get("value"),
        event_id=_coerce_event_id(sighting.get("event_id")),
        attribute_id=(
            str(sighting.get("attribute_id")) if sighting.get("attribute_id") is not None else None
        ),
        type=sighting.get("type"),
        saved=saved,
        message=None if saved else str(raw.get("message") or raw.get("name") or ""),
    )


def parse_tag_result(raw: dict[str, Any], *, event_id: int, tag: str) -> MISPTagResult:
    saved = bool(raw.get("saved", raw.get("success", False)))
    message = raw.get("message") or raw.get("name")
    return MISPTagResult(event_id=event_id, tag=tag, saved=saved, message=message)


def parse_publish_result(raw: dict[str, Any], *, event_id: int) -> MISPPublishResult:
    message = raw.get("message") or raw.get("name")
    published = raw.get("errors") is None
    return MISPPublishResult(event_id=event_id, published=published, message=message)
