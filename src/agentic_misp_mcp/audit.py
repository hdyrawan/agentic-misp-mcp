from __future__ import annotations

import asyncio
import functools
import json
import time
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from agentic_misp_mcp.policy.models import PolicyDecision

T = TypeVar("T")

SENSITIVE_KEYS = {"api_key", "authorization", "authkey", "headers", "misp_api_key", "token"}


def sanitize_for_audit(value: Any) -> Any:
    """Return a JSON-serializable copy with sensitive fields redacted."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, nested in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS:
                sanitized[key_text] = "[REDACTED]"
            else:
                sanitized[key_text] = sanitize_for_audit(nested)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_audit(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_audit(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


class AuditLogger:
    """Append-only JSONL audit logger."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()

    async def write(self, record: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(sanitize_for_audit(dict(record)), sort_keys=True, default=str)
        async with self._lock:
            await asyncio.to_thread(self._append_line, line)

    def _append_line(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


async def audit_call(
    audit_logger: AuditLogger,
    tool_name: str,
    arguments: Mapping[str, Any],
    call: Callable[[], Awaitable[T]],
    policy_decision: PolicyDecision | Mapping[str, Any] | None = None,
) -> T:
    started = time.perf_counter()
    base_record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        "tool": tool_name,
        "arguments": sanitize_for_audit(arguments),
    }
    if policy_decision is not None:
        policy_fields = _policy_audit_fields(policy_decision)
        base_record["policy"] = policy_fields
        base_record.update(policy_fields)
    try:
        result = await call()
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        await audit_logger.write(
            {
                **base_record,
                "success": False,
                "duration_ms": duration_ms,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
        )
        raise
    duration_ms = int((time.perf_counter() - started) * 1000)
    await audit_logger.write(
        {
            **base_record,
            "success": True,
            "duration_ms": duration_ms,
            "error_type": None,
            "error_message": None,
        }
    )
    return result


def audited_tool(
    audit_logger: AuditLogger,
    tool_name: str,
    func: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    @functools.wraps(func)
    async def wrapper(**kwargs: Any) -> T:
        return await audit_call(audit_logger, tool_name, kwargs, lambda: func(**kwargs))

    return wrapper


def _policy_audit_fields(policy_decision: PolicyDecision | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(policy_decision, PolicyDecision):
        return {
            "role": policy_decision.role,
            "action": policy_decision.action,
            "allowed": policy_decision.allowed,
            "approval_required": policy_decision.approval_required,
        }
    return {
        "role": str(policy_decision.get("role", "")),
        "action": str(policy_decision.get("action", "")),
        "allowed": bool(policy_decision.get("allowed", False)),
        "approval_required": bool(policy_decision.get("approval_required", False)),
    }
