"""Shared datetime validation. Internal to packages.schema.models."""

from __future__ import annotations

from datetime import datetime


def require_aware(value: datetime) -> datetime:
    """Reject naive datetimes. Every timestamp in this system is timezone-aware."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("datetime must be timezone-aware")
    return value
