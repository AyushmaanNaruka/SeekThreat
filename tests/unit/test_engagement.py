from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from packages.schema.models.engagement import Authorization, Engagement, ScanRequest

NOW = datetime.now(UTC)


def _auth() -> Authorization:
    return Authorization(
        engagement_id="eng-001",
        authorized_by="A. Named Human",
        allowlist=["172.20.0.0/16"],
        granted_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_engagement_carries_its_authorization() -> None:
    eng = Engagement(
        engagement_id="eng-001",
        name="Lab baseline",
        authorization=_auth(),
        created_at=NOW,
    )
    assert eng.authorization.permits("172.20.1.10") is True


def test_engagement_id_must_match_authorization() -> None:
    with pytest.raises(ValidationError, match="engagement_id"):
        Engagement(
            engagement_id="eng-002",
            name="Mismatched",
            authorization=_auth(),
            created_at=NOW,
        )


def test_scan_request_defaults_options_to_empty() -> None:
    req = ScanRequest(target="172.20.1.10", authorization=_auth())
    assert req.options == {}


def test_scanner_base_reuses_the_schema_authorization() -> None:
    from packages.schema.models.engagement import Authorization as SchemaAuthorization
    from services.scanners.base import Authorization as BaseAuthorization

    assert BaseAuthorization is SchemaAuthorization
