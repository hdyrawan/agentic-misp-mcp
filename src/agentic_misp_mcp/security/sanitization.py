from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SENSITIVE_KEY_NAMES = {
    "api_key",
    "apikey",
    "authkey",
    "authorization",
    "bearer",
    "token",
    "password",
    "secret",
    "misp_api_key",
    "approval_token",
    "headers",
    "cookie",
    "set-cookie",
}

_REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PATTERN = "|".join(
    re.escape(key) for key in sorted(SENSITIVE_KEY_NAMES, key=len, reverse=True)
)
_KEY_VALUE_PATTERNS = [
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(['\"]?(?:authorization|cookie|set-cookie)['\"]?\s*[:=]\s*)['\"]?[^,'\"}\s]+"),
    re.compile(
        rf"(?i)\b({_SENSITIVE_KEY_PATTERN})\b\s*[:=]\s*([^\s,;}}\]]+|['\"][^'\"]*['\"])",
    ),
]


def is_sensitive_key(key: object) -> bool:
    """Return True when a key name is likely to carry secrets/auth material."""
    return str(key).strip().lower() in SENSITIVE_KEY_NAMES


def sanitize_for_audit(value: Any) -> Any:
    """Return a JSON-serializable copy with sensitive fields redacted."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, nested in value.items():
            key_text = str(key)
            if is_sensitive_key(key_text):
                sanitized[key_text] = _REDACTED
            else:
                sanitized[key_text] = sanitize_for_audit(nested)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_audit(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_audit(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def contains_secret_key_recursive(value: Any) -> bool:
    """Return True if nested dict/list/tuple data contains an unredacted secret key."""
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if is_sensitive_key(key) and nested != _REDACTED:
                return True
            if contains_secret_key_recursive(nested):
                return True
        return False
    if isinstance(value, list | tuple):
        return any(contains_secret_key_recursive(item) for item in value)
    return False


def redact_sensitive_text(text: str, *, max_length: int | None = None) -> str:
    """Redact obvious secret-bearing text and optionally truncate it."""
    redacted = text
    for pattern in _KEY_VALUE_PATTERNS:
        redacted = pattern.sub(_redact_regex_match, redacted)
    if max_length is not None and len(redacted) > max_length:
        suffix = "... [truncated]"
        redacted = redacted[: max(0, max_length - len(suffix))] + suffix
    return redacted


def _redact_regex_match(match: re.Match[str]) -> str:
    prefix = match.group(1) if match.lastindex else "Bearer "
    if prefix.lower().strip() == "bearer":
        prefix = "Bearer "
    separator = "" if prefix.endswith((" ", "=", ":")) else "="
    return f"{prefix}{separator}{_REDACTED}"


def safe_error_message(exc: BaseException, max_length: int = 512) -> str:
    """Return a short sanitized exception summary safe for agents and audit logs."""
    exc_type = type(exc).__name__
    raw_message = str(exc)
    if not raw_message:
        return exc_type
    safe_message = redact_sensitive_text(raw_message, max_length=max_length)
    return f"{exc_type}: {safe_message}"
