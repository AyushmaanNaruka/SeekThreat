"""No scan runs without authorization, and the gate precedes tool invocation.

Parametrized over every ScannerAdapter subclass, so a new adapter is covered
without anyone remembering to add a test. Adapters must therefore be
constructible with no arguments — see services/scanners/base.py.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from datetime import UTC, datetime, timedelta

import pytest

import services.scanners as scanners_pkg
from packages.schema import Authorization, ScanRequest
from services.scanners.base import AuthorizationError, ScannerAdapter

NOW = datetime.now(UTC)
UNAUTHORIZED_TARGET = "203.0.113.10"  # TEST-NET-3, never in an allowlist


def _all_subclasses(cls: type) -> set[type]:
    found = set(cls.__subclasses__())
    for sub in list(found):
        found |= _all_subclasses(sub)
    return found


def _concrete_adapters() -> list[type[ScannerAdapter]]:
    for module in pkgutil.walk_packages(scanners_pkg.__path__, scanners_pkg.__name__ + "."):
        importlib.import_module(module.name)
    return sorted(
        (c for c in _all_subclasses(ScannerAdapter) if not inspect.isabstract(c)),
        key=lambda c: c.__name__,
    )


ADAPTERS = _concrete_adapters()


def _authorization() -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_adapter_discovery_found_something() -> None:
    """Without this, an empty parametrize list would pass silently."""
    assert ADAPTERS, "no ScannerAdapter subclasses discovered — the gate tests are vacuous"


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_adapter_rejects_unauthorized_target(adapter_cls: type[ScannerAdapter]) -> None:
    adapter = adapter_cls()
    request = ScanRequest(target=UNAUTHORIZED_TARGET, authorization=_authorization())
    with pytest.raises(AuthorizationError):
        adapter.scan(request)


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_gate_precedes_tool_invocation(
    adapter_cls: type[ScannerAdapter], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool must never run for an unauthorized target."""
    invocations: list[ScanRequest] = []

    def spy(self: ScannerAdapter, request: ScanRequest) -> str:
        invocations.append(request)
        return ""

    monkeypatch.setattr(adapter_cls, "_execute", spy, raising=True)

    adapter = adapter_cls()
    request = ScanRequest(target=UNAUTHORIZED_TARGET, authorization=_authorization())
    with pytest.raises(AuthorizationError):
        adapter.scan(request)

    assert invocations == [], f"{adapter_cls.__name__} invoked its tool before authorizing"


@pytest.mark.parametrize("adapter_cls", ADAPTERS, ids=lambda c: c.__name__)
def test_expired_authorization_blocks_an_allowlisted_target(
    adapter_cls: type[ScannerAdapter], monkeypatch: pytest.MonkeyPatch
) -> None:
    invocations: list[ScanRequest] = []

    def spy(self: ScannerAdapter, request: ScanRequest) -> str:
        invocations.append(request)
        return ""

    monkeypatch.setattr(adapter_cls, "_execute", spy, raising=True)

    expired = Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    adapter = adapter_cls()
    with pytest.raises(AuthorizationError):
        adapter.scan(ScanRequest(target="172.20.1.10", authorization=expired))

    assert invocations == []
