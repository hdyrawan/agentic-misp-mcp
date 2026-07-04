from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from agentic_misp_mcp.openapi.classifier import classify_endpoint
from agentic_misp_mcp.openapi.models import (
    CLASSIFICATION_ORDER,
    RISK_LEVEL_ORDER,
    EndpointInventoryEntry,
)

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

INVENTORY_DISCLAIMER = (
    "> **Planning only.** This inventory classifies MISP OpenAPI endpoints for internal risk "
    "planning. It does not expose any MISP API endpoint as an MCP tool, and no endpoint listed "
    "here is callable through this project's MCP server."
)


def load_openapi_spec(path: str | Path) -> dict[str, Any]:
    """Load an OpenAPI document from a JSON file.

    Only JSON input is supported, to avoid adding a YAML dependency. Convert a YAML MISP
    OpenAPI spec to JSON before running the inventory.
    """
    resolved = Path(path)
    text = resolved.read_text(encoding="utf-8")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Could not parse OpenAPI spec at {resolved} as JSON: {exc}. Convert YAML specs to "
            "JSON before running the inventory."
        ) from exc
    if not isinstance(spec, dict):
        raise ValueError(f"OpenAPI spec at {resolved} must be a JSON object.")
    return spec


def build_inventory(spec: dict[str, Any]) -> list[EndpointInventoryEntry]:
    """Build a classified, deterministic endpoint inventory from a parsed OpenAPI document."""
    entries: list[EndpointInventoryEntry] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return entries

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            operation_id = operation.get("operationId")
            summary = operation.get("summary") or operation.get("description")
            tags = [str(tag) for tag in (operation.get("tags") or []) if tag]

            result = classify_endpoint(
                path=path,
                method=method,
                operation_id=operation_id,
                summary=summary,
                tags=tags,
            )
            entries.append(
                EndpointInventoryEntry(
                    path=path,
                    method=method.upper(),
                    operation_id=operation_id,
                    summary=summary,
                    tags=tags,
                    category=tags[0] if tags else _category_from_path(path),
                    classification=result.classification,
                    risk_level=result.risk_level,
                    approval_required=result.approval_required,
                    recommended_role=result.recommended_role,
                )
            )

    entries.sort(key=lambda entry: (entry.path, entry.method))
    return entries


def _category_from_path(path: str) -> str:
    segments = [
        segment for segment in path.strip("/").split("/") if segment and not segment.startswith("{")
    ]
    return segments[0] if segments else "unknown"


def render_markdown_inventory(entries: list[EndpointInventoryEntry]) -> str:
    """Render a deterministic Markdown inventory grouped by classification."""
    lines: list[str] = [
        "# MISP OpenAPI Inventory",
        "",
        INVENTORY_DISCLAIMER,
        "",
        "## Summary",
        "",
        f"- Total endpoints: {len(entries)}",
    ]

    classification_counts = Counter(entry.classification for entry in entries)
    classification_summary = ", ".join(
        f"{name}: {classification_counts.get(name, 0)}" for name in CLASSIFICATION_ORDER
    )
    lines.append(f"- By classification: {classification_summary}")

    risk_counts = Counter(entry.risk_level for entry in entries)
    risk_summary = ", ".join(f"{name}: {risk_counts.get(name, 0)}" for name in RISK_LEVEL_ORDER)
    lines.append(f"- By risk level: {risk_summary}")
    lines.append("")

    for classification in CLASSIFICATION_ORDER:
        group = [entry for entry in entries if entry.classification == classification]
        lines.append(f"## {classification}")
        lines.append("")
        if not group:
            lines.append("No endpoints in this category.")
            lines.append("")
            continue
        lines.append(
            "| Method | Path | Operation ID | Summary | Category | Risk | Approval Required "
            "| Recommended Role |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for entry in group:
            summary_cell = (entry.summary or "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                "| "
                + " | ".join(
                    [
                        entry.method,
                        f"`{entry.path}`",
                        entry.operation_id or "",
                        summary_cell,
                        entry.category,
                        entry.risk_level,
                        "yes" if entry.approval_required else "no",
                        entry.recommended_role,
                    ]
                )
                + " |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def generate_markdown_inventory_file(
    *, input_path: str | Path, output_path: str | Path
) -> tuple[int, str]:
    """Load an OpenAPI spec, classify it, and write a Markdown inventory file.

    Returns (endpoint_count, resolved_output_path).
    """
    spec = load_openapi_spec(input_path)
    entries = build_inventory(spec)
    markdown = render_markdown_inventory(entries)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    return len(entries), str(output)
