from __future__ import annotations


def attribute_search_payload(value: str, limit: int) -> dict[str, object]:
    return {
        "returnFormat": "json",
        "value": value,
        "limit": limit,
        "includeEventTags": True,
        "includeAttributeUuid": True,
        "includeContext": True,
    }


def warninglist_check_payload(value: str) -> dict[str, object]:
    return {"value": value}


def event_tag_search_payload(tag: str, limit: int) -> dict[str, object]:
    return {
        "returnFormat": "json",
        "tags": [tag],
        "limit": limit,
    }


def sighting_search_payload(value: str, limit: int) -> dict[str, object]:
    return {
        "returnFormat": "json",
        "value": value,
        "limit": limit,
    }


def event_search_payload(
    *,
    date_from: str | None = None,
    date_to: str | None = None,
    published: bool | None = None,
    org: str | None = None,
    limit: int,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "returnFormat": "json",
        "limit": limit,
    }
    # MISP restSearch date-range params are `from`/`to`. It silently ignores unknown
    # params (`datefrom`/`dateto` returned unfiltered results on live 2.5.42), so the
    # names here are load-bearing: a wrong name means unfiltered data, not an error.
    if date_from is not None:
        payload["from"] = date_from
    if date_to is not None:
        payload["to"] = date_to
    if published is not None:
        payload["published"] = published
    if org is not None:
        payload["org"] = org
    return payload


def event_create_payload(
    *,
    info: str,
    distribution: int = 0,
    threat_level_id: int = 4,
    analysis: int = 0,
    tags: list[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "info": info,
        "distribution": distribution,
        "threat_level_id": threat_level_id,
        "analysis": analysis,
        "published": False,
    }
    if tags:
        payload["Tag"] = [{"name": tag} for tag in tags]
    return payload


def attribute_create_payload(
    *,
    type: str,
    value: str,
    category: str | None = None,
    comment: str | None = None,
    to_ids: bool | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"type": type, "value": value}
    if category is not None:
        payload["category"] = category
    if comment is not None:
        payload["comment"] = comment
    if to_ids is not None:
        payload["to_ids"] = to_ids
    return payload


def sighting_create_payload(
    *,
    value: str | None = None,
    event_id: int | None = None,
    attribute_id: str | None = None,
    sighting_type: str = "0",
    source: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"type": sighting_type}
    if value is not None:
        payload["value"] = value
    if event_id is not None:
        payload["event_id"] = event_id
    if attribute_id is not None:
        payload["id"] = attribute_id
    if source is not None:
        payload["source"] = source
    return payload


def tag_payload(tag: str) -> dict[str, object]:
    return {"tag": tag}
