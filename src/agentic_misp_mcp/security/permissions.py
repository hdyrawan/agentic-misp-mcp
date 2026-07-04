from __future__ import annotations

import stat
from pathlib import Path


def unsafe_permissions_reason(path: Path, *, check_group: bool) -> str | None:
    """Return a description if `path` (or its parent directory) is unsafely writable.

    Always flags world-writable. Also flags group-writable when `check_group` is set —
    callers protecting a stricter security boundary (e.g. the approval store) should pass
    `check_group=True`; callers where group-writable is common/acceptable (e.g. an audit log
    directory under a typical non-zero umask) should pass `check_group=False`.
    """
    bits = (stat.S_IWGRP | stat.S_IWOTH) if check_group else stat.S_IWOTH
    descriptor = "group/world" if check_group else "world"
    parent = path.parent
    if parent.exists():
        parent_mode = stat.S_IMODE(parent.stat().st_mode)
        if parent_mode & bits:
            return f"parent directory is {descriptor} writable: {parent}"
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & bits:
            return f"file is {descriptor} writable: {path}"
    return None
