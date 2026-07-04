from __future__ import annotations

from agentic_misp_mcp.policy.guardrails import enforce_attribute_guardrails, enforce_tag_guardrails


def test_attribute_type_allowlist_blocks_disallowed_type():
    result = enforce_attribute_guardrails(
        attribute_type="url",
        category="Network activity",
        allowed_types=("ip-dst",),
        allowed_categories=(),
    )

    assert result.allowed is False
    assert "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_TYPES" in result.reason


def test_attribute_category_allowlist_blocks_disallowed_category():
    result = enforce_attribute_guardrails(
        attribute_type="ip-dst",
        category="Payload delivery",
        allowed_types=("ip-dst",),
        allowed_categories=("Network activity",),
    )

    assert result.allowed is False
    assert "AGENTIC_MISP_MCP_ALLOWED_ATTRIBUTE_CATEGORIES" in result.reason


def test_attribute_guardrails_allow_matching_type_and_category():
    result = enforce_attribute_guardrails(
        attribute_type="ip-dst",
        category="Network activity",
        allowed_types=("ip-dst",),
        allowed_categories=("Network activity",),
    )

    assert result.allowed is True


def test_tag_allowlist_supports_exact_and_prefix_matches():
    assert enforce_tag_guardrails(tag="tlp:amber", allowed_tags=("tlp:amber",)).allowed is True
    assert (
        enforce_tag_guardrails(tag="misp-galaxy:foo", allowed_tags=("misp-galaxy:*",)).allowed
        is True
    )
    assert enforce_tag_guardrails(tag="private:tag", allowed_tags=("tlp:*",)).allowed is False
