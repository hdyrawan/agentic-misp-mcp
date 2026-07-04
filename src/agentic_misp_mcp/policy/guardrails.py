from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuardrailResult:
    allowed: bool
    reason: str | None = None


def enforce_attribute_guardrails(
    *,
    attribute_type: str,
    category: str | None,
    allowed_types: tuple[str, ...],
    allowed_categories: tuple[str, ...],
) -> GuardrailResult:
    if allowed_types and attribute_type not in allowed_types:
        return GuardrailResult(
            allowed=False,
            reason=("attribute type is not allowed by AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES"),
        )
    if allowed_categories and category is not None and category not in allowed_categories:
        return GuardrailResult(
            allowed=False,
            reason=(
                "attribute category is not allowed by AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES"
            ),
        )
    return GuardrailResult(allowed=True)


def enforce_tag_guardrails(*, tag: str, allowed_tags: tuple[str, ...]) -> GuardrailResult:
    if not allowed_tags:
        return GuardrailResult(allowed=True)
    for allowed in allowed_tags:
        if allowed.endswith("*") and tag.startswith(allowed[:-1]):
            return GuardrailResult(allowed=True)
        if tag == allowed:
            return GuardrailResult(allowed=True)
    return GuardrailResult(
        allowed=False,
        reason="tag is not allowed by AGENTIC_MISP_MCP_ALLOWED_TAGS",
    )
