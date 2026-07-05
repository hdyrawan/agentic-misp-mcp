from __future__ import annotations

from typing import Any

MAX_TEXT_LENGTH = 5000
MAX_VALUE_LENGTH = 2048
MAX_TAGS = 50
MAX_TAG_LENGTH = 255

VALID_DISTRIBUTIONS = {0, 1, 2, 3, 4, 5}
VALID_THREAT_LEVELS = {1, 2, 3, 4}
VALID_ANALYSIS_LEVELS = {0, 1, 2}
# MISP sighting types: 0 = sighting, 1 = false positive, 2 = expiration.
VALID_SIGHTING_TYPES = {"0", "1", "2"}

# Standard MISP event/attribute categories (misp-core-format taxonomy). Anything outside
# this set is rejected as unsupported rather than silently passed through to a proposal.
MISP_ATTRIBUTE_CATEGORIES = frozenset(
    {
        "Internal reference",
        "Targeting data",
        "Antivirus detection",
        "Payload delivery",
        "Artifacts dropped",
        "Payload installation",
        "Persistence mechanism",
        "Network activity",
        "Payload type",
        "Attribution",
        "External analysis",
        "Financial fraud",
        "Support Tool",
        "Social network",
        "Person",
        "Other",
    }
)

# A curated, non-exhaustive allowlist of standard MISP attribute types covering the common
# IOC/threat-intel types this project's tools are designed around. Unknown/unrecognized
# type strings are treated as unsupported rather than passed through to a MISP write proposal.
MISP_ATTRIBUTE_TYPES = frozenset(
    {
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512/224",
        "sha512/256",
        "sha3-224",
        "sha3-256",
        "sha3-384",
        "sha3-512",
        "ssdeep",
        "imphash",
        "authentihash",
        "tlsh",
        "pehash",
        "impfuzzy",
        "filename",
        "filename|md5",
        "filename|sha1",
        "filename|sha256",
        "filename|sha512",
        "filename|imphash",
        "filename|authentihash",
        "filename|ssdeep",
        "filename|tlsh",
        "ip-src",
        "ip-dst",
        "ip-src|port",
        "ip-dst|port",
        "port",
        "hostname",
        "hostname|port",
        "domain",
        "domain|ip",
        "url",
        "uri",
        "link",
        "email",
        "email-src",
        "email-dst",
        "email-subject",
        "email-attachment",
        "email-header",
        "email-reply-to",
        "email-x-mailer",
        "email-mime-boundary",
        "email-thread-index",
        "email-message-id",
        "user-agent",
        "http-method",
        "regkey",
        "regkey|value",
        "mutex",
        "named pipe",
        "as",
        "asn",
        "btc",
        "xmr",
        "iban",
        "bic",
        "bank-account-nr",
        "cve",
        "vulnerability",
        "weakness",
        "threat-actor",
        "campaign-name",
        "campaign-id",
        "text",
        "comment",
        "other",
        "attachment",
        "malware-sample",
        "malware-type",
        "yara",
        "snort",
        "sigma",
        "pattern-in-file",
        "pattern-in-traffic",
        "pattern-in-memory",
        "jarm-fingerprint",
        "ja3-fingerprint-md5",
        "jarm-hash",
        "hassh-md5",
        "hasshserver-md5",
        "mac-address",
        "hex",
        "target-user",
        "target-email",
        "target-machine",
        "target-org",
        "target-location",
        "target-external",
        "size-in-bytes",
        "counter",
        "datetime",
        "cpe",
        "whois-registrant-email",
        "whois-registrant-name",
        "whois-registrant-org",
        "whois-registrar",
        "whois-creation-date",
        "github-username",
        "github-repository",
        "github-organisation",
        "twitter-id",
        "first-name",
        "last-name",
        "full-name",
        "nationality",
        "passport-number",
        "date-of-birth",
    }
)


def validate_event_proposal(
    *,
    info: Any,
    distribution: Any,
    threat_level_id: Any,
    analysis: Any,
    tags: Any,
) -> list[str]:
    """Validate a proposed MISP event payload. Returns a list of human-readable errors,
    empty when the proposal is well-formed. Never touches MISP."""
    errors: list[str] = []

    if not isinstance(info, str) or not info.strip():
        errors.append("info is required and must not be blank")
    elif len(info) > MAX_TEXT_LENGTH:
        errors.append(f"info must be <= {MAX_TEXT_LENGTH} characters")

    if not _is_plain_int(distribution) or distribution not in VALID_DISTRIBUTIONS:
        errors.append(f"distribution must be one of {sorted(VALID_DISTRIBUTIONS)}")

    if not _is_plain_int(threat_level_id) or threat_level_id not in VALID_THREAT_LEVELS:
        errors.append(f"threat_level_id must be one of {sorted(VALID_THREAT_LEVELS)}")

    if not _is_plain_int(analysis) or analysis not in VALID_ANALYSIS_LEVELS:
        errors.append(f"analysis must be one of {sorted(VALID_ANALYSIS_LEVELS)}")

    errors.extend(_validate_tags(tags))
    return errors


def validate_attribute_proposal(
    *,
    event_id: Any,
    type: Any,  # noqa: A002
    value: Any,
    category: Any,
    comment: Any,
    to_ids: Any,
) -> list[str]:
    """Validate a proposed MISP attribute payload. Returns a list of human-readable errors,
    empty when the proposal is well-formed. Never touches MISP."""
    errors: list[str] = []

    if not _is_plain_int(event_id) or event_id <= 0:
        errors.append("event_id must be a positive integer")

    if not isinstance(type, str) or not type.strip():
        errors.append("type is required and must not be blank")
    elif type not in MISP_ATTRIBUTE_TYPES:
        errors.append(f"type '{type}' is not a recognized/supported MISP attribute type")

    if not isinstance(value, str) or not value.strip():
        errors.append("value is required and must not be blank")
    elif len(value) > MAX_VALUE_LENGTH:
        errors.append(f"value must be <= {MAX_VALUE_LENGTH} characters")

    if category is not None:
        if not isinstance(category, str) or not category.strip():
            errors.append("category must not be blank when provided")
        elif category not in MISP_ATTRIBUTE_CATEGORIES:
            errors.append(f"category '{category}' is not a recognized MISP attribute category")

    if comment is not None:
        if not isinstance(comment, str):
            errors.append("comment must be a string when provided")
        elif len(comment) > MAX_TEXT_LENGTH:
            errors.append(f"comment must be <= {MAX_TEXT_LENGTH} characters")

    if to_ids is not None and not isinstance(to_ids, bool):
        errors.append("to_ids must be a boolean when provided")

    return errors


def validate_sighting_proposal(
    *,
    value: Any,
    event_id: Any,
    attribute_id: Any,
    sighting_type: Any,
    source: Any,
) -> list[str]:
    """Validate a proposed MISP sighting payload. Returns a list of human-readable errors,
    empty when the proposal is well-formed. Never touches MISP."""
    errors: list[str] = []

    if value is None and event_id is None and attribute_id is None:
        errors.append("at least one of value, event_id, or attribute_id is required")

    if value is not None:
        if not isinstance(value, str) or not value.strip():
            errors.append("value must not be blank when provided")
        elif len(value) > MAX_VALUE_LENGTH:
            errors.append(f"value must be <= {MAX_VALUE_LENGTH} characters")

    if event_id is not None and (not _is_plain_int(event_id) or event_id <= 0):
        errors.append("event_id must be a positive integer when provided")

    if attribute_id is not None and (not isinstance(attribute_id, str) or not attribute_id.strip()):
        errors.append("attribute_id must not be blank when provided")

    if not isinstance(sighting_type, str) or sighting_type not in VALID_SIGHTING_TYPES:
        errors.append(f"sighting_type must be one of {sorted(VALID_SIGHTING_TYPES)}")

    if source is not None:
        if not isinstance(source, str):
            errors.append("source must be a string when provided")
        elif len(source) > MAX_TEXT_LENGTH:
            errors.append(f"source must be <= {MAX_TEXT_LENGTH} characters")

    return errors


def _validate_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if not isinstance(tags, list):
        return ["tags must be a list of strings"]
    errors: list[str] = []
    if len(tags) > MAX_TAGS:
        errors.append(f"tags must contain at most {MAX_TAGS} entries")
    for tag in tags:
        if not isinstance(tag, str) or not tag.strip():
            errors.append("tags must not contain blank entries")
            break
    for tag in tags:
        if isinstance(tag, str) and len(tag) > MAX_TAG_LENGTH:
            errors.append(f"tag values must be <= {MAX_TAG_LENGTH} characters")
            break
    return errors


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
