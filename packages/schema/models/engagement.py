"""Engagement and authorization.

No scan runs without an Authorization that permits its target. Matching never
resolves DNS: a name could resolve differently between the authorization being
granted and the scan running, so a hostname target only matches a hostname
pattern.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packages.schema.models._time import require_aware


def target_matches(target: str, pattern: str) -> bool:
    """Does `target` fall inside allowlist entry `pattern`?

    Patterns are either an IP address, a CIDR block, a hostname, or a
    `*.domain` wildcard matching subdomains but not the apex.

    The target is compared exactly as provided — no URL parsing, no DNS
    resolution. Until proper URL target support is added (see DECISIONS.md),
    callers must supply the exact string that will be scanned.
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
        return fnmatchcase(target.lower(), pattern.lower())

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
