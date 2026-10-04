"""Scheduled mirroring and synchronization jobs for intelligence sources.

Rule 5 from services/enrichment/README.md:
"Mirror sources locally. Don't hit APIs on the request path."

This module persists already-fetched feed payloads to local mirror files
atomically. It does not download anything itself; fetching upstream feeds and
scheduling that fetch are not implemented yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.schema.models.provenance import Source

# Upstream canonical URLs for reference
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class SyncResult:
    """Summary of a background source mirroring execution."""

    source: Source
    success: bool
    records_synced: int
    target_path: Path
    synced_at: datetime
    error: str | None = None


#: Mirror file name for each source inside a cache directory. Shared by
#: ``SourceSynchronizer`` (writer) and ``FusionEngine(cache_dir=...)`` (reader)
#: so the two can never disagree.
MIRROR_FILENAMES: dict[Source, str] = {
    Source.CVE_ORG: "cve_org.json",
    Source.KEV: "cisa_kev.json",
    Source.EPSS: "epss_v4.json",
    Source.VULNRICHMENT: "vulnrichment.json",
    Source.NVD: "nvd.json",
    Source.EUVD: "euvd.json",
}


def mirror_path(cache_dir: Path | str, source: Source) -> Path:
    """Return the mirror file path for ``source`` inside ``cache_dir``."""
    return Path(cache_dir) / MIRROR_FILENAMES.get(source, f"{source.value}.json")


def get_default_cache_dir() -> Path:
    """Return default directory for local enrichment intelligence mirrors."""
    return Path("data") / "enrichment_cache"


class SourceSynchronizer:
    """Atomically writes already-fetched feed payloads into the local mirror directory.

    It does not download feeds and nothing schedules it yet.
    """

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else get_default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_source_path(self, source: Source) -> Path:
        """Return the local cache file path for a source."""
        return mirror_path(self.cache_dir, source)

    def sync_from_data(self, source: Source, data: Any, count: int) -> SyncResult:
        """Atomically persist fresh sync payload to the local mirror file."""
        import json

        target_path = self.get_source_path(source)
        temp_path = target_path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_path.replace(target_path)
            return SyncResult(
                source=source,
                success=True,
                records_synced=count,
                target_path=target_path,
                synced_at=datetime.now(UTC),
            )
        except Exception as exc:
            if temp_path.exists():
                temp_path.unlink()
            return SyncResult(
                source=source,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )
