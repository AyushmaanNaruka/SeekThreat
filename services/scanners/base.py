"""
Scanner adapter interface.

Every scanner integration implements ScannerAdapter. The contract:

  1. Adapters NEVER scan without an authorization record. Enforced here, not by callers.
  2. Adapters invoke tools as subprocesses or containers and parse their output.
     We do not vendor or link scanner source code.
  3. Adapters emit Finding objects from packages.schema. Raw tool output is preserved
     in Finding.raw for provenance.
  4. Adapters do not enrich. Severity, EPSS and scoring belong to services.enrichment.

See docs/01-open-source-policy.md before adding an adapter for a new tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


class AuthorizationError(Exception):
    """Raised when a scan is attempted without valid authorization."""


@dataclass(frozen=True)
class Authorization:
    """Proof that this scan is permitted. No scan runs without one."""

    engagement_id: str
    authorized_by: str          # named human, not a service account
    allowlist: list[str]        # hostnames or CIDRs
    granted_at: datetime
    expires_at: datetime

    def permits(self, target: str) -> bool:
        """TODO: proper CIDR and wildcard-subdomain matching."""
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return target in self.allowlist


@dataclass
class ScanRequest:
    target: str
    authorization: Authorization
    options: dict = field(default_factory=dict)


class ScannerAdapter(ABC):
    """Base for all scanner integrations."""

    name: str
    version_command: list[str]

    def scan(self, request: ScanRequest) -> list:
        """Entry point. Do not override — override _execute and _parse."""
        if not request.authorization.permits(request.target):
            raise AuthorizationError(
                f"No valid authorization for {request.target!r}. "
                f"Scans require an authorization record covering the target."
            )
        raw = self._execute(request)
        return self._parse(raw, request)

    @abstractmethod
    def _execute(self, request: ScanRequest) -> str:
        """Invoke the tool. Return its raw output."""

    @abstractmethod
    def _parse(self, raw: str, request: ScanRequest) -> list:
        """Convert raw output into Finding objects. Preserve raw in each Finding."""

    @abstractmethod
    def is_available(self) -> bool:
        """Is the tool installed and runnable?"""
