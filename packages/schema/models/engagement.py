"""Engagement and authorization.

No scan runs without an Authorization that permits its target. Matching never
resolves DNS: a name could resolve differently between the authorization being
granted and the scan running, so a hostname target only matches a hostname
pattern.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from fnmatch import fnmatch

from pydantic import BaseModel, ConfigDict, field_validator

from packages.schema.models._time import require_aware


def target_matches(target: str, pattern: str) -> bool:
    """Does `target` fall inside allowlist entry `pattern`?

    Patterns are either an IP address, a CIDR block, a hostname, or a
    `*.domain` wildcard matching subdomains but not the apex.
    """
    target = target.strip()
    pattern = pattern.strip()
    if not target or not pattern:
        return False

    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        network = None

    if network is not None:
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
        return fnmatch(target.lower(), pattern.lower())

    return target.lower() == pattern.lower()


class Authorization(BaseModel):
    """Proof that a scan is permitted. No scan runs without one."""

    model_config = ConfigDict(frozen=True)

    engagement_id: str
    authorized_by: str
    allowlist: list[str]
    granted_at: datetime
    expires_at: datetime

    @field_validator("granted_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator("allowlist")
    @classmethod
    def _allowlist_not_empty(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowlist must name at least one target")
        return value

    @field_validator("authorized_by")
    @classmethod
    def _authorizer_is_named(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("authorized_by must name a human, not be blank")
        return value

    def permits(self, target: str) -> bool:
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return any(target_matches(target, entry) for entry in self.allowlist)
