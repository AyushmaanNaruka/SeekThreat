"""Router: feed health / status endpoint.

Provides GET /feeds/status — reads .meta.json sidecars and .notfound.json caches
from the enrichment_cache_dir for all 8 intelligence mirrors and returns
structured freshness, record-count, and sha256 information.

Every access is audited as ``feeds_status_read``.  No data is fabricated: if a
sidecar is absent the field is null and last_sync_result is "never".
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from apps.api.core.audit import log_audit_event
from apps.api.core.config import settings
from packages.schema.models.provenance import Source
from services.enrichment.sources.base import meta_path, read_mirror_meta
from services.enrichment.sources.sync import MIRROR_FILENAMES, not_found_path

router = APIRouter()

#: Audit constants — feed status reads are platform-wide, not engagement-scoped.
_AUDIT_ENGAGEMENT = "n/a"
_AUDIT_SCANNER = "feeds_status"
_AUDIT_ACTOR = "system:api"


class FeedStatus(BaseModel):
    """Serialised health record for a single feed mirror."""

    name: str
    """Short source name (e.g. ``cisa_kev``, ``epss_v4``)."""
    synced_at: str | None
    """ISO-8601 timestamp when the mirror was last written, or null if never synced."""
    record_count: int | None
    """Number of records in the mirror file, or null if no sidecar exists."""
    sha256: str | None
    """SHA-256 hex digest of the mirror file as of last sync, or null."""
    last_sync_result: str
    """``"ok"``, ``"never"``, or the error string from the last sync attempt."""
    is_stale: bool
    """True when the mirror is older than ``settings.mirror_staleness_threshold_days``."""
    not_found_cache_size: int
    """Number of CVEs recorded as not-found upstream in the .notfound.json sidecar."""


def _read_not_found_size(mirror_file: Path) -> int:
    """Return the number of entries in the .notfound.json sidecar (0 if absent)."""
    nf_path = not_found_path(mirror_file)
    try:
        with nf_path.open(encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return sum(1 for k in data if not k.startswith("_"))
        return 0
    except (OSError, ValueError):
        return 0


def _feed_status(name: str, mirror_file: Path) -> FeedStatus:
    """Build one FeedStatus from on-disk sidecars — never from network."""
    meta: dict[str, Any] | None = read_mirror_meta(mirror_file) if mirror_file.exists() else None

    synced_at: str | None = None
    record_count: int | None = None
    sha256: str | None = None
    last_sync_result: str = "never"
    is_stale: bool = False

    if meta is not None:
        synced_at = meta.get("synced_at") or None
        record_count_raw = meta.get("record_count")
        record_count = int(record_count_raw) if record_count_raw is not None else None
        sha256 = meta.get("sha256") or None
        last_sync_result = meta.get("last_sync_result") or "ok"

        # Staleness: compare synced_at age against configured threshold.
        if synced_at:
            try:
                synced_dt = datetime.fromisoformat(synced_at)
                if synced_dt.tzinfo is None:
                    synced_dt = synced_dt.replace(tzinfo=UTC)
                age_days = (datetime.now(UTC) - synced_dt).total_seconds() / 86400.0
                is_stale = age_days > settings.mirror_staleness_threshold_days
            except ValueError:
                pass

    not_found_cache_size = _read_not_found_size(mirror_file)

    return FeedStatus(
        name=name,
        synced_at=synced_at,
        record_count=record_count,
        sha256=sha256,
        last_sync_result=last_sync_result,
        is_stale=is_stale,
        not_found_cache_size=not_found_cache_size,
    )


@router.get("/feeds/status", response_model=list[FeedStatus], tags=["feeds"])
def get_feeds_status() -> list[FeedStatus]:
    """Return health and freshness information for all 8 intelligence feed mirrors.

    Reads only on-disk sidecars (.meta.json) and negative-cache files (.notfound.json).
    No network calls are made. Missing sidecars appear as ``synced_at: null`` and
    ``last_sync_result: "never"`` — data is never fabricated.

    Access is audit-logged as ``feeds_status_read``.
    """
    log_audit_event(
        event="feeds_status_read",
        actor=_AUDIT_ACTOR,
        target="feeds",
        engagement_id=_AUDIT_ENGAGEMENT,
        scanner=_AUDIT_SCANNER,
        status="success",
        details={"cache_dir": str(settings.enrichment_cache_dir)},
    )

    cache_dir = settings.enrichment_cache_dir
    statuses: list[FeedStatus] = []

    for source, filename in MIRROR_FILENAMES.items():
        # Use the SOURCE_NAMES short name for the "name" field where possible.
        from services.enrichment.sources.sync import SOURCE_NAMES
        name = SOURCE_NAMES.get(source, source.value)
        mirror_file = Path(cache_dir) / filename
        statuses.append(_feed_status(name, mirror_file))

    # Sort by name for a stable, alphabetical response.
    statuses.sort(key=lambda s: s.name)
    return statuses
