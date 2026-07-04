from __future__ import annotations

import hashlib
import json
from typing import Any


def operation_hash(tool_name: str, proposed_arguments: dict[str, Any]) -> str:
    """Return a stable hash for a tool name plus canonical business arguments.

    The input must be the normalized operation object used by the workflow, not an
    audit-sanitized record and not request metadata such as timestamps or request IDs.
    """

    canonical = json.dumps(
        {"tool": tool_name, "args": proposed_arguments},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
