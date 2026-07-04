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
