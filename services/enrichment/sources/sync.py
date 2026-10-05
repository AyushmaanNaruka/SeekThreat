"""Scheduled mirroring and synchronization jobs for intelligence sources.

Rule 5 from services/enrichment/README.md:
"Mirror sources locally. Don't hit APIs on the request path."

Two classes:
- SourceSynchronizer: atomically writes already-fetched payloads to mirror files.
- FeedSyncer: fetches upstream feeds over HTTP and calls SourceSynchronizer to persist
  them. Network is ONLY allowed here — never on the enrichment request path.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from packages.schema.models.provenance import Source

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Upstream canonical URLs (used by FeedSyncer)
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
# CVE Services bulk download — full CVE list in delta ZIP bundles:
# <https://github.com/CVEProject/cvelistV5>
# We fetch the JSON index and a representative slice for the mirror.
DEFAULT_CVE_ORG_URL = "https://cveawg.mitre.org/api/cve"
# Secondary threat intelligence sources
DEFAULT_VULNRICHMENT_URL = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/develop/vulnrichment.json"
)
DEFAULT_EUVD_URL = "https://euvd.enisa.europa.eu/api/vulnerabilities"
# ExploitDB files_exploits.csv (metadata mapping CVE -> EDB-ID, no exploit code)
DEFAULT_EXPLOITDB_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
# Rapid7 Metasploit module metadata (module names to CVE references, no Ruby code)
DEFAULT_METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"


@dataclass(frozen=True)
class SyncResult:
    """Summary of a background source mirroring execution."""

    source: Source
    success: bool
    records_synced: int
    target_path: Path
    synced_at: datetime = field(default_factory=lambda: datetime.now(UTC))
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
    Source.EXPLOITDB: "exploitdb.json",
    Source.METASPLOIT: "metasploit.json",
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


class FeedSyncer:
    """Downloads upstream intelligence feeds and persists them as local mirror files.

    This is the ONLY place in the codebase where outbound network requests are
    permitted. The enrichment request path (EnrichmentService / FusionEngine) reads
    only from local mirror files and must never make network calls.

    Typical use:
        syncer = FeedSyncer(cache_dir=settings.enrichment_cache_dir)
        results = syncer.sync_all()

    Each sync_*() method:
    1. Fetches the upstream feed via httpx.
    2. Extracts a record count.
    3. Delegates atomic write to SourceSynchronizer.sync_from_data().
    4. Returns a SyncResult with success flag, count, and any error.

    A failure in one source does not abort the others (sync_all is best-effort).
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        kev_url: str = DEFAULT_CISA_KEV_URL,
        epss_url: str = DEFAULT_FIRST_EPSS_URL,
        cve_org_url: str = DEFAULT_CVE_ORG_URL,
        vulnrichment_url: str = DEFAULT_VULNRICHMENT_URL,
        euvd_url: str = DEFAULT_EUVD_URL,
        exploitdb_url: str = DEFAULT_EXPLOITDB_URL,
        metasploit_url: str = DEFAULT_METASPLOIT_URL,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else get_default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._synchronizer = SourceSynchronizer(cache_dir=self.cache_dir)
        self._kev_url = kev_url
        self._epss_url = epss_url
        self._cve_org_url = cve_org_url
        self._vulnrichment_url = vulnrichment_url
        self._euvd_url = euvd_url
        self._exploitdb_url = exploitdb_url
        self._metasploit_url = metasploit_url
        self._timeout = timeout_seconds

    def sync_kev(self) -> SyncResult:
        """Fetch the CISA Known Exploited Vulnerabilities catalog and write to mirror."""
        target_path = mirror_path(self.cache_dir, Source.KEV)
        try:
            response = httpx.get(self._kev_url, timeout=self._timeout, follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            count = len(payload.get("vulnerabilities", []))
            return self._synchronizer.sync_from_data(Source.KEV, payload, count)
        except Exception as exc:
            return SyncResult(
                source=Source.KEV,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_epss(self) -> SyncResult:
        """Fetch the FIRST EPSS v4 scores and write to mirror.

        Fetches all current scores (scores-only endpoint, no full CVE list needed).
        The FIRST API supports ?all=true to get the complete dataset.
        """
        target_path = mirror_path(self.cache_dir, Source.EPSS)
        try:
            # ?all=true returns the full current score set as one page.
            url = self._epss_url if "?" in self._epss_url else f"{self._epss_url}?all=true"
            response = httpx.get(url, timeout=self._timeout, follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            count = len(payload.get("data", []))
            return self._synchronizer.sync_from_data(Source.EPSS, payload, count)
        except Exception as exc:
            return SyncResult(
                source=Source.EPSS,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_cve_org(self) -> SyncResult:
        """Fetch the CVE.org bulk record list and write to mirror.

        Uses the MITRE CVE Services API to download records. In production the
        full mirror would use the cvelistV5 GitHub ZIP; this implementation uses
        the REST API endpoint to download a representative slice (1000 records,
        most-recently-updated) sufficient for development and eval.
        """
        target_path = mirror_path(self.cache_dir, Source.CVE_ORG)
        try:
            # Fetch recent CVE records via the public CVE Services API.
            # Real production mirror would stream the cvelistV5 delta ZIPs.
            url = f"{self._cve_org_url}?state=PUBLISHED&resultsPerPage=1000"
            response = httpx.get(url, timeout=self._timeout, follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            # API returns {totalCount, resultsPerPage, startIndex, cveMetadata: [...]}
            # Reshape to our local mirror format: {cve_id: record, ...}
            if isinstance(payload, dict) and not payload.get("cveMetadata"):
                records: dict[str, object] = payload
            else:
                records = {}
            if "cveMetadata" in payload:
                # Normalise paginated API response into {CVE-XXXX: record} dict
                records = {
                    item["cveMetadata"]["cveId"]: item
                    for item in payload["cveMetadata"]
                    if isinstance(item, dict) and "cveMetadata" in item
                }
            count = len(records)
            return self._synchronizer.sync_from_data(Source.CVE_ORG, records, count)
        except Exception as exc:
            return SyncResult(
                source=Source.CVE_ORG,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_vulnrichment(self) -> SyncResult:
        """Fetch CISA Vulnrichment enrichment data and write to mirror."""
        target_path = mirror_path(self.cache_dir, Source.VULNRICHMENT)
        try:
            response = httpx.get(
                self._vulnrichment_url, timeout=self._timeout, follow_redirects=True
            )
            response.raise_for_status()
            payload = response.json()
            count = len(payload) if isinstance(payload, (dict, list)) else 0
            return self._synchronizer.sync_from_data(Source.VULNRICHMENT, payload, count)
        except Exception as exc:
            return SyncResult(
                source=Source.VULNRICHMENT,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_euvd(self) -> SyncResult:
        """Fetch ENISA European Vulnerability Database data and write to mirror."""
        target_path = mirror_path(self.cache_dir, Source.EUVD)
        try:
            response = httpx.get(self._euvd_url, timeout=self._timeout, follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            count = len(payload) if isinstance(payload, (dict, list)) else 0
            return self._synchronizer.sync_from_data(Source.EUVD, payload, count)
        except Exception as exc:
            return SyncResult(
                source=Source.EUVD,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_exploitdb(self) -> SyncResult:
        """Fetch ExploitDB files_exploits.csv and write normalized JSON mirror.

        Hard Rule 4: Extracts ONLY exploit IDs mapped to CVE identifiers.
        Never downloads or stores exploit payloads or executable code.
        """
        target_path = mirror_path(self.cache_dir, Source.EXPLOITDB)
        try:
            response = httpx.get(
                self._exploitdb_url, timeout=self._timeout, follow_redirects=True
            )
            response.raise_for_status()
            text = response.text
            records: dict[str, dict[str, Any]] = {}
            if text.strip().startswith("{") or text.strip().startswith("["):
                payload = response.json()
                if isinstance(payload, dict):
                    records = payload
                count = len(records)
                return self._synchronizer.sync_from_data(Source.EXPLOITDB, records, count)

            reader = csv.DictReader(io.StringIO(text))
            cve_map: dict[str, list[str]] = {}
            for row in reader:
                edb_id = row.get("id", "").strip()
                if not edb_id:
                    continue
                formatted_id = f"EDB-{edb_id}"
                codes = row.get("codes", "")
                for match in CVE_PATTERN.finditer(codes):
                    cve = match.group(0).upper()
                    if cve not in cve_map:
                        cve_map[cve] = []
                    if formatted_id not in cve_map[cve]:
                        cve_map[cve].append(formatted_id)

            records = {
                cve: {
                    "cve_id": cve,
                    "exploit_ids": ids,
                    "has_public_exploit": True,
                }
                for cve, ids in cve_map.items()
            }
            count = len(records)
            return self._synchronizer.sync_from_data(Source.EXPLOITDB, records, count)
        except Exception as exc:
            return SyncResult(
                source=Source.EXPLOITDB,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_metasploit(self) -> SyncResult:
        """Fetch Metasploit modules_metadata_base.json and write normalized JSON mirror.

        Hard Rule 4: Extracts ONLY module names mapped to CVE identifiers.
        Never downloads or stores Ruby exploit source code.
        """
        target_path = mirror_path(self.cache_dir, Source.METASPLOIT)
        try:
            response = httpx.get(
                self._metasploit_url, timeout=self._timeout, follow_redirects=True
            )
            response.raise_for_status()
            data = response.json()
            cve_map: dict[str, list[str]] = {}
            if isinstance(data, dict):
                for mod_name, mod_info in data.items():
                    if mod_name.startswith("_") or not isinstance(mod_info, dict):
                        continue
                    refs = mod_info.get("references", [])
                    if isinstance(refs, list):
                        for ref in refs:
                            if isinstance(ref, str):
                                for match in CVE_PATTERN.finditer(ref):
                                    cve = match.group(0).upper()
                                    if cve not in cve_map:
                                        cve_map[cve] = []
                                    if mod_name not in cve_map[cve]:
                                        cve_map[cve].append(mod_name)
            records = {
                cve: {
                    "cve_id": cve,
                    "module_names": mods,
                    "has_metasploit_module": True,
                }
                for cve, mods in cve_map.items()
            }
            count = len(records)
            return self._synchronizer.sync_from_data(Source.METASPLOIT, records, count)
        except Exception as exc:
            return SyncResult(
                source=Source.METASPLOIT,
                success=False,
                records_synced=0,
                target_path=target_path,
                synced_at=datetime.now(UTC),
                error=str(exc),
            )

    def sync_primary(self) -> list[SyncResult]:
        """Sync the three primary feeds (KEV, EPSS, CVE.org)."""
        results: list[SyncResult] = []
        for sync_fn in (self.sync_kev, self.sync_epss, self.sync_cve_org):
            results.append(sync_fn())
        return results

    def sync_secondary(self) -> list[SyncResult]:
        """Sync secondary threat feeds (Vulnrichment, EUVD, ExploitDB, Metasploit)."""
        results: list[SyncResult] = []
        for sync_fn in (
            self.sync_vulnrichment,
            self.sync_euvd,
            self.sync_exploitdb,
            self.sync_metasploit,
        ):
            results.append(sync_fn())
        return results

    def sync_all(self, include_secondary: bool = False) -> list[SyncResult]:
        """Sync feeds. Returns one SyncResult per source.

        Best-effort: a failure in one source does not abort the others.
        By default syncs primary feeds (KEV, EPSS, CVE.org). Set
        include_secondary=True to sync all 7 feeds.
        """
        results = self.sync_primary()
        if include_secondary:
            results.extend(self.sync_secondary())
        return results
