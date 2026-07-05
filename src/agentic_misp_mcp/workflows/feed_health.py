from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agentic_misp_mcp.models.misp import parse_misp_datetime
from agentic_misp_mcp.security.sanitization import sanitize_for_audit
from agentic_misp_mcp.settings import Settings

FEED_HEALTH_LABELS = (
    "healthy",
    "stale",
    "never_fetched",
    "disabled",
    "cache_stale",
    "error",
    "unknown",
)

_SENSITIVE_QUERY_KEYS = {
    "api_key",
    "apikey",
    "authkey",
    "auth_key",
    "authorization",
    "bearer",
    "cookie",
    "key",
    "password",
    "secret",
    "token",
}
_SENSITIVE_FEED_FIELDS = {
    "headers",
    "header",
    "authkey",
    "auth_key",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
}
_FETCH_TIMESTAMP_FIELDS = (
    "last_fetched",
    "last_fetch",
    "last_fetch_time",
    "fetched_at",
    "fetch_timestamp",
    "timestamp",
)
_CACHE_TIMESTAMP_FIELDS = (
    "cache_timestamp",
    "cached_at",
    "last_cached",
    "last_cache",
    "cache_time",
)
_ERROR_FIELDS = ("error", "last_error", "message")


def normalize_feed_record(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    feed = raw.get("Feed", raw)
    return dict(feed) if isinstance(feed, dict) else {}


def summarize_feed(raw: Any) -> dict[str, object]:
    feed = normalize_feed_record(raw)
    enabled = _coerce_bool(feed.get("enabled"))
    return {
        "feed_id": _string_or_none(feed.get("id")),
        "name": _string_or_none(feed.get("name")),
        "provider": _string_or_none(feed.get("provider")),
        "url": redact_feed_url(feed.get("url")),
        "enabled": enabled,
        "caching_enabled": _coerce_bool(feed.get("caching_enabled")),
        "lookup_visible": _coerce_bool(feed.get("lookup_visible")),
        "source_format": _string_or_none(feed.get("source_format")),
    }


def feed_status(raw: Any, settings: Settings) -> dict[str, object]:
    feed = sanitize_feed_record(normalize_feed_record(raw))
    summary = summarize_feed({"Feed": feed})
    fetched_at = _first_datetime(feed, _FETCH_TIMESTAMP_FIELDS)
    cached_at = _first_datetime(feed, _CACHE_TIMESTAMP_FIELDS)
    age_days_since_fetch = age_days(fetched_at)
    age_days_since_cache = age_days(cached_at)
    health_label, warnings = classify_feed_health(
        enabled=summary["enabled"],
        age_days_since_fetch=age_days_since_fetch,
        age_days_since_cache=age_days_since_cache,
        feed=feed,
        settings=settings,
    )

    return {
        **summary,
        "age_days_since_fetch": age_days_since_fetch,
        "age_days_since_cache": age_days_since_cache,
        "health_label": health_label,
        "warnings": warnings,
        "metadata": feed,
    }


def classify_feed_health(
    *,
    enabled: object,
    age_days_since_fetch: int | None,
    age_days_since_cache: int | None,
    feed: dict[str, Any],
    settings: Settings,
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    if enabled is False:
        return "disabled", ["feed is disabled"]
    if _has_error(feed):
        return "error", ["feed reports an error field"]
    if age_days_since_fetch is None:
        warnings.append("feed has no usable fetch timestamp")
        return "never_fetched", warnings
    if age_days_since_fetch > settings.feed_stale_days:
        warnings.append(f"feed last fetch is older than {settings.feed_stale_days} days")
        return "stale", warnings
    if age_days_since_fetch > settings.feed_fresh_days:
        warnings.append(f"feed last fetch is older than {settings.feed_fresh_days} days")
    if age_days_since_cache is not None and age_days_since_cache > settings.feed_stale_days:
        warnings.append(f"feed cache is older than {settings.feed_stale_days} days")
        return "cache_stale", warnings
    return "healthy", warnings


def age_days(value: datetime | None) -> int | None:
    if value is None:
        return None
    now = datetime.now(UTC)
    normalized = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    return max(0, (now - normalized).days)


def sanitize_feed_record(feed: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in feed.items():
        key_text = str(key)
        if key_text.lower() in _SENSITIVE_FEED_FIELDS:
            sanitized[key_text] = "[REDACTED]"
        elif key_text.lower() == "url":
            sanitized[key_text] = redact_feed_url(value)
        else:
            sanitized[key_text] = sanitize_for_audit(value)
    return sanitized


def redact_feed_url(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    try:
        parts = urlsplit(text)
    except ValueError:
        return str(sanitize_for_audit(text))
    if not parts.query and not parts.username and not parts.password:
        return str(sanitize_for_audit(text))

    netloc = parts.hostname or ""
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    if parts.username or parts.password:
        user = "[REDACTED]"
        netloc = f"{user}@{netloc}"
    redacted_query = urlencode(
        [
            (key, "[REDACTED]" if key.lower() in _SENSITIVE_QUERY_KEYS else val)
            for key, val in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, redacted_query, parts.fragment))


def _first_datetime(feed: dict[str, Any], keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        value = parse_misp_datetime(feed.get(key))
        if value is not None:
            return value
    return None


def _has_error(feed: dict[str, Any]) -> bool:
    for key in _ERROR_FIELDS:
        value = feed.get(key)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _string_or_none(value: Any) -> str | None:
    return str(value) if value is not None and str(value) != "" else None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes"}:
            return True
        if lowered in {"0", "false", "no"}:
            return False
    return None
