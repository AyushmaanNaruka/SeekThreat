"""POST /engagements rejects allowlist entries the gate could never match."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from apps.api.routers.engagements import CreateEngagementRequest

_BASE = {
    "engagement_id": "eng-x",
    "name": "x",
    "authorized_by": "Tester",
    "granted_at": "2026-11-10T00:00:00Z",
    "expires_at": "2026-11-17T00:00:00Z",
}


@pytest.mark.parametrize(
    "entry", ["172.20.0.0/16", "172.20.1.10", "fd00::/8", "web.lab.local", "*.lab.local"]
)
def test_valid_entries_accepted(entry: str) -> None:
    req = CreateEngagementRequest(**_BASE, allowlist=[f"  {entry} "])
    assert req.allowlist == [entry]


@pytest.mark.parametrize(
    "entry", ["172.20.0.0/16172.20.0.0/16", "", "  ", "http://x.lab", "*.", "a b", "10.0.0.0/33"]
)
def test_malformed_entries_rejected(entry: str) -> None:
    with pytest.raises(ValidationError):
        CreateEngagementRequest(**_BASE, allowlist=[entry])
