"""Scheduled mirroring and synchronization jobs for intelligence sources.

Rule 5 from services/enrichment/README.md:
"Mirror sources locally. Don't hit APIs on the request path."

Two classes:
- SourceSynchronizer: atomically writes already-fetched payloads to mirror files,
  refuses to shrink an existing mirror, and records a ``<name>.meta.json`` sidecar.
- FeedSyncer: fetches upstream feeds over HTTPS and calls SourceSynchronizer to
  persist them. Network is ONLY allowed here — never on the enrichment request path.

Two sync modes:
- Full mirrors for catalogs that are published as one bounded file: CISA KEV (JSON),
  FIRST EPSS (daily bulk CSV), ExploitDB (``files_exploits.csv`` IDs only) and
  Metasploit (``modules_metadata_base.json`` exploit module names only).
- Targeted per-CVE sync for record-oriented sources — CVE.org, CISA Vulnrichment,
  ENISA EUVD and NVD — fetching only the CVE IDs the platform has seen, merged into
  the existing mirror keyed by CVE ID. Mirroring those catalogs whole is hundreds of
  thousands of records the platform never looks up.

Upstream URLs and record shapes were checked against live responses; captured,
trimmed examples live in ``tests/fixtures/enrichment/upstream/``.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import tempfile
import time
import zlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from packages.schema.models.provenance import Source
from services.enrichment.sources.base import meta_path, read_mirror_meta
from services.enrichment.sources.secondary import exploitdb_cve_map, metasploit_cve_map

logger = logging.getLogger(__name__)

SYNC_VERSION = "0.2"
USER_AGENT = f"SeekThreat-feed-sync/{SYNC_VERSION} (+https://github.com/AyushmaanNaruka/SeekThreat)"

#: The one default mirror directory. ``Settings.enrichment_cache_dir`` defaults to
#: this too, so the sync job (writer) and the API/worker (readers) agree.
DEFAULT_CACHE_DIR = Path("data") / "enrichment_cache"

CVE_ID = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)

# Upstream URLs (all https; FeedSyncer refuses anything else).
DEFAULT_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
#: FIRST's daily bulk file: gzip CSV, ``#model_version:...,score_date:...`` comment
#: line, then ``cve,epss,percentile``. Redirects (same host) to the dated file.
DEFAULT_FIRST_EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
#: CVE Services per-record endpoint: ``{base}/{CVE-ID}`` returns one CVE_RECORD.
DEFAULT_CVE_ORG_URL = "https://cveawg.mitre.org/api/cve"
#: cisagov/vulnrichment repo root; files live at ``{year}/{n // 1000}xxx/{CVE-ID}.json``.
DEFAULT_VULNRICHMENT_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
#: EUVD API host (the euvd.enisa.europa.eu site is the SPA). ``?text={CVE-ID}``.
DEFAULT_EUVD_URL = "https://euvdservices.enisa.europa.eu/api/search"
#: NVD CVE API 2.0: ``?cveId={CVE-ID}``.
DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#: ExploitDB files_exploits.csv — only ``id`` and ``codes`` are read; no exploit files.
DEFAULT_EXPLOITDB_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
)
#: Rapid7 module metadata — exploit module names and CVE references only; no Ruby code.
DEFAULT_METASPLOIT_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/"
    "modules_metadata_base.json"
)

_MIB = 1024 * 1024
#: Per-download byte caps (applied to the body and, for gzip, to the decompressed
#: size). Generous multiples of observed sizes (2026-10): KEV ~1.5 MB, EPSS ~2.7 MB
#: gz / ~12 MB CSV, ExploitDB ~10 MB, Metasploit ~11 MB, one CVE record < 100 KB.
DEFAULT_MAX_BYTES: dict[Source, int] = {
    Source.KEV: 32 * _MIB,
    Source.EPSS: 256 * _MIB,
    Source.EXPLOITDB: 128 * _MIB,
    Source.METASPLOIT: 128 * _MIB,
    Source.CVE_ORG: 4 * _MIB,
    Source.VULNRICHMENT: 4 * _MIB,
    Source.EUVD: 4 * _MIB,
    Source.NVD: 4 * _MIB,
}
DEFAULT_MAX_SECONDS = 900.0
MAX_REDIRECTS = 5

#: NVD API rate limits: 5 requests / rolling 30 s without a key, 50 with one.
NVD_DELAY_NO_KEY_SECONDS = 6.0
NVD_DELAY_WITH_KEY_SECONDS = 0.6

#: A new full mirror must keep at least this fraction of the previous record count.
MIN_RETAINED_FRACTION = 0.5

#: Short names used by the CLI, the Celery task and summaries.
SOURCE_NAMES: dict[Source, str] = {
    Source.KEV: "kev",
    Source.EPSS: "epss",
    Source.EXPLOITDB: "exploitdb",
    Source.METASPLOIT: "metasploit",
    Source.CVE_ORG: "cve_org",
    Source.VULNRICHMENT: "vulnrichment",
    Source.EUVD: "euvd",
    Source.NVD: "nvd",
}
FULL_SOURCES = ("kev", "epss", "exploitdb", "metasploit")
TARGETED_SOURCES = ("cve_org", "vulnrichment", "euvd", "nvd")
ALL_SOURCES = FULL_SOURCES + TARGETED_SOURCES

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

__all__ = [
    "ALL_SOURCES",
    "DEFAULT_CACHE_DIR",
    "MIRROR_FILENAMES",
    "SOURCE_NAMES",
    "USER_AGENT",
    "FeedFetchError",
    "FeedSyncer",
    "SourceSynchronizer",
    "SyncReport",
    "SyncResult",
    "get_default_cache_dir",
    "meta_path",
    "mirror_path",
    "normalize_cve_ids",
    "read_mirror_meta",
    "vulnrichment_path",
]


class FeedFetchError(RuntimeError):
    """An upstream download was refused, failed, or exceeded its bounds."""


@dataclass(frozen=True)
class SyncResult:
    """Outcome of syncing one source. ``success`` is False whenever anything failed."""

    source: Source
    success: bool
    records_synced: int
    target_path: Path
    synced_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    error: str | None = None
    source_url: str | None = None
    sha256: str | None = None
    note: str | None = None

    @property
    def key(self) -> str:
        """Short source name (``kev``, ``epss``, ...)."""
        return SOURCE_NAMES.get(self.source, self.source.value)


@dataclass(frozen=True)
class SyncReport:
    """Per-source results of one sync run."""

    results: list[SyncResult]

    @property
    def ok(self) -> bool:
        return all(r.success for r in self.results)

    @property
    def succeeded(self) -> list[SyncResult]:
        return [r for r in self.results if r.success]

    @property
    def failed(self) -> list[SyncResult]:
        return [r for r in self.results if not r.success]

    def to_summary(self) -> dict[str, Any]:
        """JSON-safe summary (Celery result / audit details)."""
        return {
            "ok": self.ok,
            "succeeded": [r.key for r in self.succeeded],
            "failed": [r.key for r in self.failed],
            "sources": {
                r.key: {
                    "success": r.success,
                    "records": r.records_synced,
                    "error": r.error,
                    "note": r.note,
                    "target_path": str(r.target_path),
                    "synced_at": r.synced_at.isoformat(),
                    "sha256": r.sha256,
                }
                for r in self.results
            },
        }


def mirror_path(cache_dir: Path | str, source: Source) -> Path:
    """Return the mirror file path for ``source`` inside ``cache_dir``."""
    return Path(cache_dir) / MIRROR_FILENAMES.get(source, f"{source.value}.json")


def get_default_cache_dir() -> Path:
    """Return the default directory for local enrichment intelligence mirrors."""
    return DEFAULT_CACHE_DIR


def normalize_cve_ids(cve_ids: Iterable[str] | None) -> list[str]:
    """Sorted, de-duplicated, upper-cased CVE IDs; anything else is dropped.

    Only exact ``CVE-YYYY-NNNN`` strings survive, so nothing else is ever
    interpolated into an upstream URL path.
    """
    out: set[str] = set()
    for raw in cve_ids or ():
        if isinstance(raw, str) and CVE_ID.fullmatch(raw.strip()):
            out.add(raw.strip().upper())
    return sorted(out)


def vulnrichment_path(cve_id: str) -> str:
    """Repo-relative Vulnrichment path: ``CVE-2024-3400`` -> ``2024/3xxx/CVE-2024-3400.json``."""
    match = CVE_ID.fullmatch(cve_id.strip())
    if not match:
        raise ValueError(f"not a CVE ID: {cve_id!r}")
    year, number = match.group(1), match.group(2)
    return f"{year}/{int(number) // 1000}xxx/CVE-{year}-{number}.json"


def _count_records(data: Any) -> int:
    if isinstance(data, dict):
        for key in ("vulnerabilities", "data"):
            if isinstance(data.get(key), list):
                return len(data[key])
        return sum(1 for k in data if not str(k).startswith("_"))
    if isinstance(data, list):
        return len(data)
    return 0


def _gunzip_bounded(data: bytes, cap: int, label: str) -> bytes:
    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    pending = data
    while True:
        out += decomp.decompress(pending, cap + 1 - len(out))
        if len(out) > cap:
            raise FeedFetchError(f"{label} decompressed size exceeds {cap} bytes")
        pending = decomp.unconsumed_tail
        if not pending:
            break
    if not decomp.eof:
        raise FeedFetchError(f"{label} gzip stream is truncated")
    return bytes(out)


class SourceSynchronizer:
    """Atomically writes already-fetched feed payloads into the local mirror directory.

    Each write goes to a unique temp file in the mirror directory, is flushed and
    fsynced, then ``os.replace``-d over the mirror. A ``<name>.meta.json`` sidecar
    records ``synced_at``, ``source_url``, ``record_count`` and the ``sha256`` of the
    bytes written. The sha256 documents what was written; nothing upstream publishes
    a checksum to validate the download against.

    Shrink guard: an existing mirror is never replaced by an empty result or by one
    holding fewer than ``MIN_RETAINED_FRACTION`` of its previous records, unless
    ``allow_shrink`` is set. Upstream truncation must not silently empty a mirror.
    """

    def __init__(self, cache_dir: Path | str | None = None, allow_shrink: bool = False) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else get_default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.allow_shrink = allow_shrink

    def get_source_path(self, source: Source) -> Path:
        """Return the local cache file path for a source."""
        return mirror_path(self.cache_dir, source)

    def _previous_count(self, target: Path) -> int | None:
        if not target.exists():
            return None
        meta = read_mirror_meta(target)
        if meta is not None and isinstance(meta.get("record_count"), int):
            return int(meta["record_count"])
        try:
            with open(target, encoding="utf-8") as f:
                return _count_records(json.load(f))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None  # an unreadable mirror is not worth protecting

    def _write_atomic(self, target: Path, data: Any) -> str:
        """Write ``data`` as compact JSON to ``target`` atomically; return its sha256."""
        tmp_path: Path | None = None
        try:
            # Unique name in the mirror's own directory, so os.replace is atomic.
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp:
                tmp_path = Path(tmp.name)
                json.dump(data, tmp, separators=(",", ":"), ensure_ascii=False)
                tmp.flush()
                os.fsync(tmp.fileno())
            digest = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
            os.replace(tmp_path, target)
            return digest
        except BaseException:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
            raise

    def sync_from_data(
        self,
        source: Source,
        data: Any,
        count: int,
        source_url: str | None = None,
    ) -> SyncResult:
        """Atomically persist a fresh payload (``count`` records) to the mirror file."""
        target = self.get_source_path(source)
        now = datetime.now(UTC)

        def failure(message: str) -> SyncResult:
            logger.error("feed_sync: %s", message)
            return SyncResult(
                source=source,
                success=False,
                records_synced=0,
                target_path=target,
                synced_at=now,
                error=message,
                source_url=source_url,
            )

        previous = self._previous_count(target)
        if not self.allow_shrink and target.exists():
            if count == 0:
                return failure(
                    f"refusing to overwrite {target.name} ({previous} records) with an empty result"
                )
            if previous and count < previous * MIN_RETAINED_FRACTION:
                return failure(
                    f"refusing to overwrite {target.name}: new result has {count} records, "
                    f"less than {MIN_RETAINED_FRACTION:.0%} of the previous {previous}"
                )

        try:
            digest = self._write_atomic(target, data)
            meta = {
                "source": source.value,
                "synced_at": now.isoformat(),
                "source_url": source_url,
                "record_count": count,
                "sha256": digest,
                "sync_version": SYNC_VERSION,
            }
            self._write_atomic(meta_path(target), meta)
        except Exception as exc:  # report, never raise: one source must not stop others
            return failure(f"writing {target.name} failed: {type(exc).__name__}: {exc}")

        return SyncResult(
            source=source,
            success=True,
            records_synced=count,
            target_path=target,
            synced_at=now,
            source_url=source_url,
            sha256=digest,
        )


class FeedSyncer:
    """Downloads upstream intelligence feeds and persists them as local mirror files.

    This is the ONLY place in the codebase where outbound network requests are
    permitted. The enrichment request path (EnrichmentService / FusionEngine) reads
    only from local mirror files and must never make network calls.

    Typical use:
        syncer = FeedSyncer(cache_dir=settings.enrichment_cache_dir)
        report = syncer.sync_all(cve_ids=known_cve_ids)
        if not report.ok: ...

    Downloads are bounded: a SeekThreat User-Agent, connect/read timeouts, a
    per-download wall-clock limit, a per-source byte cap (streamed; aborted once
    passed), and https-only redirects (followed manually, at most ``MAX_REDIRECTS``).

    Every sync method returns a ``SyncResult`` and does not raise; ``sync_all``
    returns a ``SyncReport`` so callers can fail truthfully.
    """

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        kev_url: str = DEFAULT_CISA_KEV_URL,
        epss_url: str = DEFAULT_FIRST_EPSS_URL,
        cve_org_url: str = DEFAULT_CVE_ORG_URL,
        vulnrichment_url: str = DEFAULT_VULNRICHMENT_URL,
        euvd_url: str = DEFAULT_EUVD_URL,
        nvd_url: str = DEFAULT_NVD_URL,
        exploitdb_url: str = DEFAULT_EXPLOITDB_URL,
        metasploit_url: str = DEFAULT_METASPLOIT_URL,
        timeout_seconds: float = 60.0,
        *,
        transport: httpx.BaseTransport | None = None,
        nvd_api_key: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
        allow_shrink: bool = False,
        max_bytes: Mapping[Source, int] | None = None,
        max_seconds: float = DEFAULT_MAX_SECONDS,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else get_default_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._synchronizer = SourceSynchronizer(cache_dir=self.cache_dir, allow_shrink=allow_shrink)
        self._kev_url = kev_url
        self._epss_url = epss_url
        self._cve_org_url = cve_org_url.rstrip("/")
        self._vulnrichment_url = vulnrichment_url.rstrip("/")
        self._euvd_url = euvd_url
        self._nvd_url = nvd_url
        self._exploitdb_url = exploitdb_url
        self._metasploit_url = metasploit_url
        self._timeout = timeout_seconds
        self._transport = transport
        self._nvd_api_key = nvd_api_key or None
        self._sleep = sleep
        self._max_bytes = {**DEFAULT_MAX_BYTES, **(max_bytes or {})}
        self._max_seconds = max_seconds

    # ------------------------------------------------------------------ HTTP

    def _client(self) -> httpx.Client:
        return httpx.Client(
            transport=self._transport,
            timeout=httpx.Timeout(self._timeout, connect=min(15.0, self._timeout)),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        )

    def _fetch(
        self,
        client: httpx.Client,
        url: str,
        source: Source,
        *,
        params: Mapping[str, str | int] | None = None,
        headers: Mapping[str, str] | None = None,
        missing_ok: bool = False,
    ) -> bytes | None:
        """GET ``url`` within this source's bounds; None for a 404 when ``missing_ok``."""
        cap = self._max_bytes[source]
        current = httpx.URL(url, params=dict(params) if params else None)
        for _hop in range(MAX_REDIRECTS + 1):
            if current.scheme != "https":
                raise FeedFetchError(f"refusing non-https URL {current}")
            with client.stream("GET", current, headers=dict(headers or {})) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise FeedFetchError(f"redirect without Location from {current}")
                    current = current.join(location)
                    continue
                if response.status_code == 404 and missing_ok:
                    return None
                if response.status_code >= 400:
                    raise FeedFetchError(f"HTTP {response.status_code} from {current}")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > cap:
                    raise FeedFetchError(f"{source.value} download exceeds {cap} bytes")
                started = time.monotonic()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > cap:
                        raise FeedFetchError(f"{source.value} download exceeds {cap} bytes")
                    if time.monotonic() - started > self._max_seconds:
                        raise FeedFetchError(
                            f"{source.value} download exceeded {self._max_seconds:.0f}s"
                        )
                return bytes(body)
        raise FeedFetchError(f"too many redirects fetching {url}")

    def _failure(self, source: Source, exc: BaseException, url: str | None) -> SyncResult:
        message = f"{type(exc).__name__}: {exc}"
        logger.error("feed_sync: %s failed: %s", SOURCE_NAMES.get(source, source.value), message)
        return SyncResult(
            source=source,
            success=False,
            records_synced=0,
            target_path=mirror_path(self.cache_dir, source),
            error=message,
            source_url=url,
        )

    def _full_sync(
        self, source: Source, url: str, build: Callable[[bytes], tuple[Any, int]]
    ) -> SyncResult:
        try:
            with self._client() as client:
                body = self._fetch(client, url, source)
            if body is None:  # unreachable: missing_ok is False, so a 404 raises
                raise FeedFetchError(f"no body from {url}")
            payload, count = build(body)
        except Exception as exc:  # reported per source; one feed must not stop the rest
            return self._failure(source, exc, url)
        return self._synchronizer.sync_from_data(source, payload, count, source_url=url)

    # ------------------------------------------------------------ full mirrors

    def sync_kev(self) -> SyncResult:
        """Mirror the CISA Known Exploited Vulnerabilities catalog (full JSON)."""

        def build(body: bytes) -> tuple[Any, int]:
            payload = json.loads(body)
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vulnerabilities"), list
            ):
                raise ValueError("unexpected KEV catalog shape (no 'vulnerabilities' list)")
            return payload, len(payload["vulnerabilities"])

        return self._full_sync(Source.KEV, self._kev_url, build)

    def sync_epss(self) -> SyncResult:
        """Mirror FIRST EPSS from the daily bulk CSV (all scored CVEs).

        The CSV's first line is ``#model_version:<v>,score_date:<ISO-8601>``; that
        ``score_date`` is stored once at top level and becomes every record's date.
        """
        cap = self._max_bytes[Source.EPSS]

        def build(body: bytes) -> tuple[Any, int]:
            raw = _gunzip_bounded(body, cap, "epss") if body[:2] == b"\x1f\x8b" else body
            text = raw.decode("utf-8")
            first, _, rest = text.partition("\n")
            header: dict[str, str] = {}
            if first.startswith("#"):
                for part in first.lstrip("#").strip().split(","):
                    key, sep, value = part.partition(":")
                    if sep:
                        header[key.strip()] = value.strip()
            if "score_date" not in header:
                raise ValueError(
                    "EPSS CSV lacks the '#model_version:...,score_date:...' header line"
                )
            reader = csv.DictReader(io.StringIO(rest))
            if not reader.fieldnames or not {"cve", "epss", "percentile"} <= set(reader.fieldnames):
                raise ValueError(f"unexpected EPSS CSV columns: {reader.fieldnames}")
            rows = [
                {
                    "cve": row["cve"].strip().upper(),
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                }
                for row in reader
                if row.get("cve")
            ]
            payload = {
                "model_version": header.get("model_version"),
                "score_date": header["score_date"],
                "data": rows,
            }
            return payload, len(rows)

        return self._full_sync(Source.EPSS, self._epss_url, build)

    def sync_exploitdb(self) -> SyncResult:
        """Mirror the ExploitDB CVE -> EDB-ID mapping from ``files_exploits.csv``.

        Hard Rule 4: only the ``id`` and ``codes`` columns are read. Exploit files are
        never downloaded or stored.
        """

        def build(body: bytes) -> tuple[Any, int]:
            reader = csv.DictReader(io.StringIO(body.decode("utf-8", errors="replace")))
            if not reader.fieldnames or not {"id", "codes"} <= set(reader.fieldnames):
                raise ValueError(f"unexpected ExploitDB CSV columns: {reader.fieldnames}")
            records = {
                cve: {"cve_id": cve, "exploit_ids": ids, "has_public_exploit": True}
                for cve, ids in exploitdb_cve_map(reader).items()
            }
            return records, len(records)

        return self._full_sync(Source.EXPLOITDB, self._exploitdb_url, build)

    def sync_metasploit(self) -> SyncResult:
        """Mirror CVE -> Metasploit *exploit* module names (``fullname``).

        Hard Rule 4: only module names and CVE references are kept. Module source is
        never downloaded or stored.
        """

        def build(body: bytes) -> tuple[Any, int]:
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("unexpected Metasploit metadata shape (not an object)")
            records = {
                cve: {"cve_id": cve, "module_names": mods, "has_metasploit_module": True}
                for cve, mods in metasploit_cve_map(data).items()
            }
            return records, len(records)

        return self._full_sync(Source.METASPLOIT, self._metasploit_url, build)

    # ---------------------------------------------------------- targeted sync

    def _existing_mirror(self, source: Source) -> dict[str, Any]:
        path = mirror_path(self.cache_dir, source)
        if not path.exists():
            return {}
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("feed_sync: existing %s unreadable, rebuilding: %s", path, exc)
            return {}
        return (
            {k: v for k, v in data.items() if not k.startswith("_")}
            if isinstance(data, dict)
            else {}
        )

    def _targeted_sync(
        self,
        source: Source,
        cve_ids: Iterable[str],
        base_url: str,
        fetch_one: Callable[[httpx.Client, str], dict[str, Any] | None],
        delay_seconds: float = 0.0,
    ) -> SyncResult:
        target = mirror_path(self.cache_dir, source)
        ids = normalize_cve_ids(cve_ids)
        if not ids:
            return SyncResult(
                source=source,
                success=True,
                records_synced=0,
                target_path=target,
                source_url=base_url,
                note="no CVE IDs to sync; mirror left unchanged",
            )

        fetched: dict[str, Any] = {}
        errors: list[str] = []
        not_found = 0
        try:
            with self._client() as client:
                for index, cve in enumerate(ids):
                    if index and delay_seconds:
                        self._sleep(delay_seconds)
                    try:
                        record = fetch_one(client, cve)
                    except Exception as exc:  # one CVE's failure must not stop the rest
                        errors.append(f"{cve}: {type(exc).__name__}: {exc}")
                        continue
                    if record is None:
                        not_found += 1
                    else:
                        fetched[cve] = record
        except Exception as exc:
            return self._failure(source, exc, base_url)

        note = (
            f"{len(fetched)} fetched, {not_found} not found upstream, "
            f"{len(errors)} failed, of {len(ids)} requested"
        )
        sha256: str | None = None
        if fetched:
            merged = {**self._existing_mirror(source), **fetched}
            written = self._synchronizer.sync_from_data(
                source, merged, len(merged), source_url=base_url
            )
            if not written.success:
                return written
            sha256 = written.sha256

        error = None
        if errors:
            error = f"{len(errors)} of {len(ids)} lookups failed; first: {errors[0]}"
            logger.error("feed_sync: %s %s", SOURCE_NAMES[source], error)
        return SyncResult(
            source=source,
            success=not errors,
            records_synced=len(fetched),
            target_path=target,
            error=error,
            source_url=base_url,
            sha256=sha256,
            note=note,
        )

    def _json(self, body: bytes | None) -> Any | None:
        return None if body is None else json.loads(body)

    def sync_cve_org(self, cve_ids: Iterable[str]) -> SyncResult:
        """Fetch CVE Services 5.x records one by one (``{base}/{CVE-ID}``)."""

        def fetch_one(client: httpx.Client, cve: str) -> dict[str, Any] | None:
            url = f"{self._cve_org_url}/{cve}"
            record = self._json(self._fetch(client, url, Source.CVE_ORG, missing_ok=True))
            if record is None:
                return None
            got = record.get("cveMetadata", {}).get("cveId") if isinstance(record, dict) else None
            if not isinstance(got, str) or got.upper() != cve:
                raise ValueError(f"unexpected CVE record shape for {cve}")
            return dict(record)

        return self._targeted_sync(Source.CVE_ORG, cve_ids, self._cve_org_url, fetch_one)

    def sync_vulnrichment(self, cve_ids: Iterable[str]) -> SyncResult:
        """Fetch CISA Vulnrichment per-CVE files; a 404 means CISA has not enriched it."""

        def fetch_one(client: httpx.Client, cve: str) -> dict[str, Any] | None:
            url = f"{self._vulnrichment_url}/{vulnrichment_path(cve)}"
            record = self._json(self._fetch(client, url, Source.VULNRICHMENT, missing_ok=True))
            if record is None:
                return None
            if not isinstance(record, dict) or "containers" not in record:
                raise ValueError(f"unexpected Vulnrichment record shape for {cve}")
            return dict(record)

        return self._targeted_sync(Source.VULNRICHMENT, cve_ids, self._vulnrichment_url, fetch_one)

    def sync_euvd(self, cve_ids: Iterable[str]) -> SyncResult:
        """Look up each CVE in EUVD (``/api/search?text=``), keeping the exact alias match."""

        def fetch_one(client: httpx.Client, cve: str) -> dict[str, Any] | None:
            body = self._fetch(
                client,
                self._euvd_url,
                Source.EUVD,
                params={"text": cve, "size": 10},
                missing_ok=True,
            )
            payload = self._json(body)
            if payload is None:
                return None
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise ValueError(f"unexpected EUVD search shape for {cve}")
            for item in payload["items"]:
                if not isinstance(item, dict):
                    continue
                aliases = item.get("aliases")
                alias_list = aliases.splitlines() if isinstance(aliases, str) else aliases or []
                if cve in {str(a).strip().upper() for a in alias_list}:
                    return dict(item)
            return None

        return self._targeted_sync(Source.EUVD, cve_ids, self._euvd_url, fetch_one)

    def sync_nvd(self, cve_ids: Iterable[str]) -> SyncResult:
        """Fetch NVD API 2.0 records per CVE, respecting NVD's published rate limits."""
        headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else None
        delay = NVD_DELAY_WITH_KEY_SECONDS if self._nvd_api_key else NVD_DELAY_NO_KEY_SECONDS

        def fetch_one(client: httpx.Client, cve: str) -> dict[str, Any] | None:
            body = self._fetch(
                client,
                self._nvd_url,
                Source.NVD,
                params={"cveId": cve},
                headers=headers,
                missing_ok=True,
            )
            payload = self._json(body)
            if payload is None:
                return None
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vulnerabilities"), list
            ):
                raise ValueError(f"unexpected NVD response shape for {cve}")
            for item in payload["vulnerabilities"]:
                obj = item.get("cve") if isinstance(item, dict) else None
                if isinstance(obj, dict) and str(obj.get("id", "")).upper() == cve:
                    return dict(obj)
            return None

        return self._targeted_sync(Source.NVD, cve_ids, self._nvd_url, fetch_one, delay)

    def sync_cve_records(self, cve_ids: Iterable[str]) -> list[SyncResult]:
        """Targeted sync of every record-oriented source for ``cve_ids``."""
        ids = normalize_cve_ids(cve_ids)
        return [
            self.sync_cve_org(ids),
            self.sync_vulnrichment(ids),
            self.sync_euvd(ids),
            self.sync_nvd(ids),
        ]

    # ------------------------------------------------------------------ all

    def sync_all(
        self,
        cve_ids: Iterable[str] | None = None,
        sources: Sequence[str] | None = None,
    ) -> SyncReport:
        """Sync every source (or just ``sources``). Best-effort across sources.

        Full mirrors: KEV, EPSS, ExploitDB, Metasploit. Targeted: CVE.org,
        Vulnrichment, EUVD, NVD for ``cve_ids``.
        """
        selected = list(sources) if sources else list(ALL_SOURCES)
        unknown = [s for s in selected if s not in ALL_SOURCES]
        if unknown:
            raise ValueError(f"unknown feed source(s): {unknown}; expected {list(ALL_SOURCES)}")
        ids = normalize_cve_ids(cve_ids)
        full: dict[str, Callable[[], SyncResult]] = {
            "kev": self.sync_kev,
            "epss": self.sync_epss,
            "exploitdb": self.sync_exploitdb,
            "metasploit": self.sync_metasploit,
        }
        targeted: dict[str, Callable[[Iterable[str]], SyncResult]] = {
            "cve_org": self.sync_cve_org,
            "vulnrichment": self.sync_vulnrichment,
            "euvd": self.sync_euvd,
            "nvd": self.sync_nvd,
        }
        results: list[SyncResult] = []
        for name in ALL_SOURCES:
            if name not in selected:
                continue
            results.append(full[name]() if name in full else targeted[name](ids))
        return SyncReport(results=results)
