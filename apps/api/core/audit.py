"""Structured audit logging for security-sensitive operations.

Every scan dispatch, completion, or authorization failure is recorded with
actor, target, authorization reference, and timestamp.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

audit_logger = logging.getLogger("seekthreat.audit")

# Optional in-memory record of audit entries for test inspection
_audit_events: list[dict[str, Any]] = []


def log_audit_event(
    event: str,
    actor: str,
    target: str,
    engagement_id: str,
    scanner: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a structured security audit event."""
    record = {
        "event": event,
        "actor": actor,
        "target": target,
        "engagement_id": engagement_id,
        "scanner": scanner,
        "status": status,
        "timestamp": datetime.now(UTC).isoformat(),
        "details": details or {},
    }

    _audit_events.append(record)
    audit_logger.info("AUDIT: %s", json.dumps(record))
    return record


def get_audit_log() -> list[dict[str, Any]]:
    """Return all recorded audit events (primarily for testing and inspection)."""
    return list(_audit_events)


def clear_audit_log() -> None:
    """Clear in-memory audit events."""
    _audit_events.clear()
