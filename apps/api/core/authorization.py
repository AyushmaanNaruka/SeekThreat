"""API-layer authorization choke point.

Strictly enforces that every scan target is explicitly permitted by an active,
non-expired authorization record before any scan job is created or dispatched.
"""

from __future__ import annotations

from datetime import UTC, datetime
from fastapi import HTTPException, status

from apps.api.core.audit import log_audit_event
from packages.schema.models.engagement import Authorization, Engagement


class AuthorizationDeniedError(HTTPException):
    """Raised when a scan target or time window fails authorization verification."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


def verify_scan_authorization(
    engagement: Engagement,
    target: str,
    scanner: str = "scanner",
    actor: str | None = None,
) -> Authorization:
    """Verify that a target is covered by an active authorization record.

    Fails closed if the engagement is expired, not yet active, or if the target
    is outside the allowlist. Emits structured audit events on every check.
    """
    now = datetime.now(UTC)
    auth = engagement.authorization
    effective_actor = actor or auth.authorized_by

    # 1. Time window validation
    if now < auth.granted_at:
        reason = f"Authorization not yet active (valid from {auth.granted_at.isoformat()})"
        log_audit_event(
            event="scan.rejected",
            actor=effective_actor,
            target=target,
            engagement_id=engagement.engagement_id,
            scanner=scanner,
            status="forbidden",
            details={"reason": reason},
        )
        raise AuthorizationDeniedError(
            f"Authorization for engagement {engagement.engagement_id!r} is not yet active. "
            f"Valid window begins at {auth.granted_at.isoformat()}."
        )

    if now > auth.expires_at:
        reason = f"Authorization expired at {auth.expires_at.isoformat()}"
        log_audit_event(
            event="scan.rejected",
            actor=effective_actor,
            target=target,
            engagement_id=engagement.engagement_id,
            scanner=scanner,
            status="forbidden",
            details={"reason": reason},
        )
        raise AuthorizationDeniedError(
            f"Authorization for engagement {engagement.engagement_id!r} expired at "
            f"{auth.expires_at.isoformat()}. Scans are forbidden."
        )

    # 2. Allowlist scope validation
    if not auth.permits(target):
        reason = f"Target {target!r} not in allowlist {list(auth.allowlist)}"
        log_audit_event(
            event="scan.rejected",
            actor=effective_actor,
            target=target,
            engagement_id=engagement.engagement_id,
            scanner=scanner,
            status="forbidden",
            details={"reason": reason},
        )
        raise AuthorizationDeniedError(
            f"Target {target!r} is not authorized under engagement {engagement.engagement_id!r}. "
            f"Allowed patterns: {list(auth.allowlist)}."
        )

    # 3. Passed authorization gate
    log_audit_event(
        event="scan.accepted",
        actor=effective_actor,
        target=target,
        engagement_id=engagement.engagement_id,
        scanner=scanner,
        status="authorized",
        details={"allowlist": list(auth.allowlist)},
    )
    return auth
