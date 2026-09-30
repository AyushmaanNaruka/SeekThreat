"""Scheduled mirroring and synchronization jobs for intelligence sources.

Rule 5 from services/enrichment/README.md:
"Mirror sources locally. Don't hit APIs on the request path."

This module defines background fetchers that download and update local mirrors
outside the HTTP/scan request lifecycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.schema.models.provenance import Source

# Upstream canonical URLs for reference
DEFAULT_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
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


def get_default_cache_dir() -> Path:
    """Return default directory for local enrichment intelligence mirrors."""
    return Path("data") / "enrichment_cache"


class SourceSynchronizer:
    """Orchestrates scheduled batch synchronization of offline intelligence mirrors."""

    def __init__(self, cache_dir: Path | str | None = None) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else get_default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_source_path(self, source: Source) -> Path:
        """Return the local cache file path for a source."""
        filename_map = {
            Source.CVE_ORG: "cve_org.json",
            Source.KEV: "cisa_kev.json",
            Source.EPSS: "epss_v4.json",
            Source.VULNRICHMENT: "vulnrichment.json",
            Source.NVD: "nvd.json",
            Source.EUVD: "euvd.json",
        }
        filename = filename_map.get(source, f"{source.value}.json")
        return self.cache_dir / filename

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
