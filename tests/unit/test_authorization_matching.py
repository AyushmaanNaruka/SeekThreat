from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from packages.schema.models.engagement import Authorization, target_matches

NOW = datetime.now(UTC)


def _auth(
    allowlist: list[str],
    expires_in: timedelta = timedelta(hours=1),
    granted_offset: timedelta = timedelta(0),
) -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=allowlist,
        granted_at=NOW + granted_offset,
        expires_at=NOW + expires_in,
    )


@pytest.mark.parametrize(
    ("target", "pattern", "expected"),
    [
        # The live defect: a host inside a CIDR must be permitted.
        ("172.20.1.10", "172.20.0.0/16", True),
        ("172.20.3.44", "172.20.0.0/16", True),
        ("10.0.0.5", "172.20.0.0/16", False),
        # A bare IP behaves as a single-host network.
        ("127.0.0.1", "127.0.0.1", True),
        ("127.0.0.2", "127.0.0.1", False),
        # Hostnames, case-insensitive.
        ("lab.local", "lab.local", True),
        ("LAB.LOCAL", "lab.local", True),
        ("other.local", "lab.local", False),
        # Wildcard subdomains match children, not the apex.
        ("web.lab.local", "*.lab.local", True),
        ("db.internal.lab.local", "*.lab.local", True),
        ("lab.local", "*.lab.local", False),
        ("evil.com", "*.lab.local", False),
        # No DNS resolution: a hostname never matches a CIDR.
        ("lab.local", "172.20.0.0/16", False),
        # An IP never matches a hostname pattern.
        ("172.20.1.10", "lab.local", False),
    ],
)
def test_target_matches(target: str, pattern: str, expected: bool) -> None:
    assert target_matches(target, pattern) is expected


def test_permits_accepts_target_in_any_allowlist_entry() -> None:
    auth = _auth(["10.0.0.0/8", "172.20.0.0/16"])
    assert auth.permits("172.20.1.10") is True


def test_permits_rejects_target_outside_allowlist() -> None:
    auth = _auth(["172.20.0.0/16"])
    assert auth.permits("8.8.8.8") is False


def test_expired_authorization_permits_nothing() -> None:
    # Granted two hours ago, expired one hour ago: a valid (non-inverted) window
    # that has since closed.
    auth = _auth(
        ["172.20.0.0/16"],
        expires_in=timedelta(hours=-1),
        granted_offset=timedelta(hours=-2),
    )
    assert auth.permits("172.20.1.10") is False


def test_authorization_rejects_empty_allowlist() -> None:
    with pytest.raises(ValidationError):
        _auth([])


def test_authorization_rejects_anonymous_authorizer() -> None:
    with pytest.raises(ValidationError):
        Authorization(
            engagement_id="eng-001",
            authorized_by="   ",
            allowlist=["172.20.0.0/16"],
            granted_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )


def test_authorization_rejects_naive_datetimes() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        Authorization(
            engagement_id="eng-001",
            authorized_by="A. Named Human",
            allowlist=["172.20.0.0/16"],
            granted_at=datetime(2026, 9, 5, 12, 0),
            expires_at=datetime(2026, 9, 5, 13, 0),
        )


def test_allowlist_cannot_be_mutated_in_place() -> None:
    auth = _auth(["172.20.0.0/16"])
    with pytest.raises(AttributeError):
        auth.allowlist.append("0.0.0.0/0")  # type: ignore[attr-defined]


def test_not_yet_granted_authorization_permits_nothing() -> None:
    # granted_at in the future: an otherwise-allowlisted, otherwise-unexpired
    # target must still be rejected because the window has not opened yet.
    future_auth = Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(hours=2),
    )
    assert future_auth.permits("172.20.1.10") is False


def test_authorization_rejects_inverted_or_zero_width_window() -> None:
    with pytest.raises(ValidationError, match="expires_at"):
        Authorization(
            engagement_id="eng-001",
            authorized_by="A. Named Human",
            allowlist=["172.20.0.0/16"],
            granted_at=NOW,
            expires_at=NOW,
        )
