from __future__ import annotations

from agentic_misp_mcp.models.misp import MISPAttributeSummary

SUPPORTED_IOC_BUCKETS = ("ip", "domain", "url", "md5", "sha1", "sha256", "email")

_SIMPLE_TYPE_MAP = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
}
_COMPOSITE_HASH_TYPE_MAP = {
    "filename|md5": "md5",
    "filename|sha1": "sha1",
    "filename|sha256": "sha256",
}


def extract_iocs_by_type(attributes: list[MISPAttributeSummary]) -> dict[str, list[str]]:
    """Extract and group supported IOC types from bounded MISP attributes.

    Only a fixed, deterministic set of IOC types is extracted (ip, domain, url,
    md5, sha1, sha256, email); composite `filename|<hash>` attributes contribute
    just the hash portion. Output is deduplicated and sorted per type.
    """
    buckets: dict[str, set[str]] = {bucket: set() for bucket in SUPPORTED_IOC_BUCKETS}
    for attribute in attributes:
        attr_type = (attribute.type or "").lower()
        value = attribute.value
        if not value:
            continue
        if attr_type in _SIMPLE_TYPE_MAP:
            buckets[_SIMPLE_TYPE_MAP[attr_type]].add(value)
        elif attr_type in _COMPOSITE_HASH_TYPE_MAP:
            hash_part = value.rsplit("|", 1)[-1] if "|" in value else value
            buckets[_COMPOSITE_HASH_TYPE_MAP[attr_type]].add(hash_part)
    return {bucket: sorted(values) for bucket, values in buckets.items()}
