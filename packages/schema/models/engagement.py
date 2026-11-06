"""Engagement and authorization.

No scan runs without an Authorization that permits its target. Matching never
resolves DNS: a name could resolve differently between the authorization being
granted and the scan running, so a hostname target only matches a hostname
pattern.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.schema.models._time import require_aware

_HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_MAX_HOSTNAME_LEN = 253


def is_valid_hostname(value: str) -> bool:
    """Is `value` a syntactically valid DNS hostname (RFC 1123), and nothing more?

    Letters, digits and hyphens only, in dot-separated labels of 1-63 characters that
    neither start nor end with a hyphen, 253 characters in all. No trailing dot, no
    port, no userinfo, no path — anything a URL parser could read a different host out
    of is rejected.
    """
    if not value or len(value) > _MAX_HOSTNAME_LEN:
        return False
    return all(_HOSTNAME_LABEL_RE.fullmatch(label) for label in value.lower().split("."))


_NETWORK_TARGET_RE = re.compile(r"[0-9a-fA-F:.]+/(?:0|[1-9][0-9]{0,2})", re.ASCII)


def _network_target_within(
    target: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network
) -> bool:
    """Is CIDR `target` entirely inside allowlisted `network`?

    Only canonical "address/prefixlen" with no host bits set: netmask forms
    ("10.0.0.0/255.0.0.0") and "10.0.0.5/24" are refused, since the string goes
    to nmap verbatim and must mean exactly the block that was checked.
    """
    if not _NETWORK_TARGET_RE.fullmatch(target):
        return False
    try:
        target_net = ipaddress.ip_network(target, strict=True)
    except ValueError:
        return False
    if target_net.version != network.version:
        return False
    return target_net.subnet_of(network)  # type: ignore[arg-type]


def target_matches(target: str, pattern: str) -> bool:
    """Does `target` fall inside allowlist entry `pattern`?

    Patterns are either an IP address, a CIDR block, a hostname, or a
    `*.domain` wildcard matching subdomains but not the apex. A wildcard only ever
    matches a target that is itself a valid DNS hostname: it is a suffix check, not a
    glob, so `http://evil.com/.lab.local` does not "end in" `.lab.local`.

    A target is a single IP, a hostname, or a canonical CIDR block; a CIDR target
    matches only a network pattern that contains the whole block.

    The target is compared exactly as provided — no URL parsing, no DNS
    resolution. URLs and ranges are broken into these shapes before the gate, by
    `apps/api/core/targets.py` (DECISIONS.md D-045); callers must supply the
    exact string that will be scanned.
    """
    target = target.strip()
    pattern = pattern.strip()
    if not target or not pattern:
        return False
    if "%" in target:
        # An IPv6 scope id ("fe80::1%eth0") is free text that ipaddress accepts and then
        # ignores for network membership, so "fd00::1%x,10.9.9.9" would match fd00::/8.
        # No valid hostname contains '%' either, so refusing it outright loses nothing.
        return False

    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        network = None

    if network is not None:
        if "/" in target:
            return _network_target_within(target, network)
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            # A hostname is never resolved to compare against a network.
            return False

    # Pattern is a hostname. An IP target never matches one.
    try:
        ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return False

    if pattern.startswith("*."):
        suffix = pattern[2:].lower()
        if not is_valid_hostname(suffix) or not is_valid_hostname(target):
            return False
        # A valid hostname has no empty labels, so this also requires at least one
        # label in front of the suffix: the apex never matches.
        return target.lower().endswith("." + suffix)

    return target.lower() == pattern.lower()


class Authorization(BaseModel):
    """Proof that a scan is permitted. No scan runs without one."""

    model_config = ConfigDict(frozen=True)

    engagement_id: str
    authorized_by: str
    allowlist: tuple[str, ...]
    granted_at: datetime
    expires_at: datetime

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator("allowlist")
    @classmethod
    def _allowlist_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("allowlist must name at least one target")
        return value

    @field_validator("authorized_by")
    @classmethod
    def _authorizer_is_named(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("authorized_by must name a human, not be blank")
        return stripped

    @model_validator(mode="after")
    def _window_is_not_inverted(self) -> Authorization:
        if self.expires_at <= self.granted_at:
            raise ValueError(
                f"expires_at must be after granted_at ({self.expires_at!r} <= {self.granted_at!r})"
            )
        return self

    def permits(self, target: str) -> bool:
        now = datetime.now(UTC)
        if now < self.granted_at or now > self.expires_at:
            return False
        return any(target_matches(target, entry) for entry in self.allowlist)


class Engagement(BaseModel):
    """A scoped piece of authorized work. Scopes every row downstream."""

    engagement_id: str
    name: str
    authorization: Authorization
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _created_aware(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _authorization_is_for_this_engagement(self) -> Engagement:
        if self.authorization.engagement_id != self.engagement_id:
            raise ValueError(
                "engagement_id must match the authorization's engagement_id "
                f"({self.engagement_id!r} != {self.authorization.engagement_id!r})"
            )
        return self


class ScanRequest(BaseModel):
    """One scan of one target, under one authorization."""

    target: str
    authorization: Authorization
    options: dict[str, Any] = Field(default_factory=dict)
