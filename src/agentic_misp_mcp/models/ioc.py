from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,128}@[^@\s]{1,253}$")
MAX_IOC_LENGTH = 2048


class IOCType(str, Enum):  # noqa: UP042
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class NormalizedIOC(BaseModel):
    value: str = Field(min_length=1, max_length=MAX_IOC_LENGTH)
    type: IOCType


class IOCQuery(BaseModel):
    value: str = Field(min_length=1, max_length=MAX_IOC_LENGTH)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("IOC value must not be blank")
        return stripped

    def normalize(self) -> NormalizedIOC:
        return normalize_ioc(self.value)


def normalize_ioc(value: str) -> NormalizedIOC:
    value = value.strip()
    if not value:
        raise ValueError("IOC value must not be blank")
    if len(value) > MAX_IOC_LENGTH:
        raise ValueError(f"IOC value must be <= {MAX_IOC_LENGTH} characters")

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return NormalizedIOC(value=value, type=IOCType.URL)

    lowered = value.lower()
    try:
        ip = ipaddress.ip_address(lowered)
        return NormalizedIOC(value=lowered, type=IOCType.IPV4 if ip.version == 4 else IOCType.IPV6)
    except ValueError:
        pass

    if MD5_RE.match(lowered):
        return NormalizedIOC(value=lowered, type=IOCType.MD5)
    if SHA1_RE.match(lowered):
        return NormalizedIOC(value=lowered, type=IOCType.SHA1)
    if SHA256_RE.match(lowered):
        return NormalizedIOC(value=lowered, type=IOCType.SHA256)
    if EMAIL_RE.match(lowered):
        return NormalizedIOC(value=lowered, type=IOCType.EMAIL)
    if DOMAIN_RE.match(lowered):
        return NormalizedIOC(value=lowered, type=IOCType.DOMAIN)
    if "." not in lowered and re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$", lowered):
        return NormalizedIOC(value=lowered, type=IOCType.HOSTNAME)
    return NormalizedIOC(value=value, type=IOCType.UNKNOWN)
