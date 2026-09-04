"""
Scanner adapter interface.

Every scanner integration implements ScannerAdapter. The contract:

  1. Adapters NEVER scan without an authorization record. Enforced here, not by callers.
  2. Adapters invoke tools as subprocesses or containers and parse their output.
     We do not vendor or link scanner source code.
  3. Adapters emit Observation objects from packages.schema. Raw tool output is
     preserved as a RawArtifact for provenance.
  4. Adapters do not enrich. Severity, EPSS and scoring belong to services.enrichment.

Adapters must be constructible with no arguments — tests/architecture discovers
every subclass by reflection and instantiates it to prove the authorization gate
holds.

See docs/01-open-source-policy.md before adding an adapter for a new tool.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from packages.schema.models.engagement import Authorization, ScanRequest
from packages.schema.models.observation import Observation

__all__ = [
    "Authorization",
    "AuthorizationError",
    "Observation",
    "ScanRequest",
    "ScannerAdapter",
]


class AuthorizationError(Exception):
    """Raised when a scan is attempted without valid authorization."""


class ScannerAdapter(ABC):
    """Base for all scanner integrations."""

    name: str
    version_command: list[str]

    def scan(self, request: ScanRequest) -> list[Observation]:
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
    def _parse(self, raw: str, request: ScanRequest) -> list[Observation]:
        """Convert raw output into Observation objects. Preserve the raw artifact."""

    @abstractmethod
    def is_available(self) -> bool:
        """Is the tool installed and runnable?"""
