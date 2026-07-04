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
from agentic_misp_mcp.security.sanitization import safe_error_message, sanitize_for_audit

T = TypeVar("T")


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
                "outcome": "error",
                "duration_ms": duration_ms,
                "error_type": type(exc).__name__,
                "error_message": safe_error_message(exc),
            }
        )
        raise
    duration_ms = int((time.perf_counter() - started) * 1000)
    # A policy decision that disallows the action is a blocked attempt, not a
    # successful call, even though `call()` returned normally instead of raising.
    policy_allowed = bool(base_record["policy"]["allowed"]) if policy_decision is not None else True
    # A controlled-write tool can call MISP without raising and still have MISP reject the
    # operation itself (e.g. `saved`/`published` false on an HTTP 200 response) — see
    # `workflows/controlled_write.py`'s `status: "failed"` result. That is neither a policy
    # block nor a real success, so it gets its own outcome rather than being recorded as
    # `success: true`.
    tool_reported_failure = isinstance(result, Mapping) and result.get("status") == "failed"
    if not policy_allowed:
        outcome = "blocked"
    elif tool_reported_failure:
        outcome = "failed"
    else:
        outcome = "success"
    await audit_logger.write(
        {
            **base_record,
            "success": outcome == "success",
            "outcome": outcome,
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
