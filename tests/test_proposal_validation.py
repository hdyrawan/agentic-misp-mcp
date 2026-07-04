from __future__ import annotations

from agentic_misp_mcp.policy.proposal_validation import (
    validate_attribute_proposal,
    validate_event_proposal,
)


def test_valid_event_proposal_has_no_errors():
    errors = validate_event_proposal(
        info="phishing campaign",
        distribution=0,
        threat_level_id=4,
        analysis=0,
        tags=["tlp:amber"],
    )
    assert errors == []


def test_event_proposal_rejects_blank_info():
    errors = validate_event_proposal(
        info="   ", distribution=0, threat_level_id=4, analysis=0, tags=None
    )
    assert any("info" in error for error in errors)


def test_event_proposal_rejects_missing_info_type():
    errors = validate_event_proposal(
        info=None, distribution=0, threat_level_id=4, analysis=0, tags=None
    )
    assert any("info" in error for error in errors)


def test_event_proposal_rejects_out_of_range_distribution():
    errors = validate_event_proposal(
        info="x", distribution=99, threat_level_id=4, analysis=0, tags=None
    )
    assert any("distribution" in error for error in errors)


def test_event_proposal_rejects_out_of_range_threat_level():
    errors = validate_event_proposal(
        info="x", distribution=0, threat_level_id=0, analysis=0, tags=None
    )
    assert any("threat_level_id" in error for error in errors)


def test_event_proposal_rejects_out_of_range_analysis():
    errors = validate_event_proposal(
        info="x", distribution=0, threat_level_id=4, analysis=5, tags=None
    )
    assert any("analysis" in error for error in errors)


def test_event_proposal_rejects_bool_as_int_field():
    errors = validate_event_proposal(
        info="x", distribution=True, threat_level_id=4, analysis=0, tags=None
    )
    assert any("distribution" in error for error in errors)


def test_event_proposal_rejects_non_list_tags():
    errors = validate_event_proposal(
        info="x", distribution=0, threat_level_id=4, analysis=0, tags="tlp:amber"
    )
    assert any("tags" in error for error in errors)


def test_event_proposal_rejects_blank_tag_entries():
    errors = validate_event_proposal(
        info="x", distribution=0, threat_level_id=4, analysis=0, tags=["tlp:amber", "  "]
    )
    assert any("tags" in error for error in errors)


def test_event_proposal_rejects_too_many_tags():
    errors = validate_event_proposal(
        info="x",
        distribution=0,
        threat_level_id=4,
        analysis=0,
        tags=[f"tag{i}" for i in range(51)],
    )
    assert any("at most" in error for error in errors)


def test_event_proposal_rejects_oversized_info():
    errors = validate_event_proposal(
        info="a" * 5001, distribution=0, threat_level_id=4, analysis=0, tags=None
    )
    assert any("info" in error for error in errors)


def test_valid_attribute_proposal_has_no_errors():
    errors = validate_attribute_proposal(
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
    )
    assert errors == []


def test_valid_attribute_proposal_with_category_and_comment():
    errors = validate_attribute_proposal(
        event_id=1,
        type="md5",
        value="d41d8cd98f00b204e9800998ecf8427e",
        category="Payload delivery",
        comment="seen in the wild",
        to_ids=True,
    )
    assert errors == []


def test_attribute_proposal_rejects_non_positive_event_id():
    errors = validate_attribute_proposal(
        event_id=0, type="ip-dst", value="1.2.3.4", category=None, comment=None, to_ids=None
    )
    assert any("event_id" in error for error in errors)


def test_attribute_proposal_rejects_negative_event_id():
    errors = validate_attribute_proposal(
        event_id=-1, type="ip-dst", value="1.2.3.4", category=None, comment=None, to_ids=None
    )
    assert any("event_id" in error for error in errors)


def test_attribute_proposal_rejects_non_int_event_id():
    errors = validate_attribute_proposal(
        event_id="1", type="ip-dst", value="1.2.3.4", category=None, comment=None, to_ids=None
    )
    assert any("event_id" in error for error in errors)


def test_attribute_proposal_rejects_blank_type():
    errors = validate_attribute_proposal(
        event_id=1, type="", value="1.2.3.4", category=None, comment=None, to_ids=None
    )
    assert any("type" in error for error in errors)


def test_attribute_proposal_rejects_unsupported_type():
    errors = validate_attribute_proposal(
        event_id=1,
        type="shell-command-that-does-not-exist",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids=None,
    )
    assert any("not a recognized/supported" in error for error in errors)


def test_attribute_proposal_rejects_blank_value():
    errors = validate_attribute_proposal(
        event_id=1, type="ip-dst", value="   ", category=None, comment=None, to_ids=None
    )
    assert any("value" in error for error in errors)


def test_attribute_proposal_rejects_oversized_value():
    errors = validate_attribute_proposal(
        event_id=1,
        type="text",
        value="a" * 2049,
        category=None,
        comment=None,
        to_ids=None,
    )
    assert any("value" in error for error in errors)


def test_attribute_proposal_rejects_unsupported_category():
    errors = validate_attribute_proposal(
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category="Not A Real Category",
        comment=None,
        to_ids=None,
    )
    assert any("not a recognized MISP attribute category" in error for error in errors)


def test_attribute_proposal_rejects_non_bool_to_ids():
    errors = validate_attribute_proposal(
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment=None,
        to_ids="true",
    )
    assert any("to_ids" in error for error in errors)


def test_attribute_proposal_rejects_oversized_comment():
    errors = validate_attribute_proposal(
        event_id=1,
        type="ip-dst",
        value="1.2.3.4",
        category=None,
        comment="a" * 5001,
        to_ids=None,
    )
    assert any("comment" in error for error in errors)


def test_attribute_proposal_accumulates_multiple_errors():
    errors = validate_attribute_proposal(
        event_id=-1,
        type="",
        value="",
        category="Not A Real Category",
        comment=None,
        to_ids="not-a-bool",
    )
    assert len(errors) >= 4
