"""Base interface and domain models for enrichment intelligence sources.

Non-negotiable invariants:
1. Intelligence sources are mirrored locally. No live API calls happen during
   request-time enrichment.
2. Every piece of intelligence produced carries explicit Source and Confidence attribution.
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from packages.schema.models.finding import EnrichmentValue
from packages.schema.models.provenance import Attributed, Confidence, Provenance, Source

RecordT = TypeVar("RecordT", bound=BaseModel)


def parse_feed_date(value: object) -> datetime | None:
    """Parse a date/datetime string from a feed into an aware UTC datetime.

    Accepts ``YYYY-MM-DD`` and ISO-8601 timestamps (``Z`` suffix allowed). Naive
    values are taken as UTC, which is what CVE.org, CISA KEV and FIRST EPSS publish.
    Returns None for anything unparseable rather than guessing.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def meta_path(mirror_file: Path | str) -> Path:
    """Sidecar metadata path for a mirror file: ``cisa_kev.json`` -> ``cisa_kev.meta.json``."""
    mirror_file = Path(mirror_file)
    return mirror_file.with_name(f"{mirror_file.stem}.meta.json")


def read_mirror_meta(mirror_file: Path | str) -> dict[str, Any] | None:
    """Read the ``.meta.json`` sidecar written by ``SourceSynchronizer``, or None.

    The sidecar records ``synced_at``, ``source_url``, ``record_count`` and the
    ``sha256`` of the mirror file as written. A missing or unreadable sidecar is
    not an error: mirrors placed by hand (or by tests) have none.
    """
    try:
        with open(meta_path(mirror_file), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@dataclass(frozen=True)
class MirrorCacheEntry:
    """Cached in-memory record store for a loaded mirror file."""

    records: dict[str, Any]
    synced_at: datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict)


MirrorCacheKey = tuple[str, str, str | None, str | None, int, int]
_PROCESS_MIRROR_CACHE: dict[MirrorCacheKey, MirrorCacheEntry] = {}
_CACHE_LOCK = threading.Lock()


def mirror_cache_key(source: Source, cache_file: Path | str) -> MirrorCacheKey:
    """Calculate the cache key for an on-disk mirror file.

    Keyed by: (source, canonical_path, sha256, synced_at, mtime_ns, size).
    - If a .meta.json sidecar exists, sha256 and synced_at ensure sync cycles
      trigger an automatic cache invalidation.
    - mtime_ns and size protect hand-edited fixtures or mirrors without sidecars.
    """
    p = Path(cache_file).resolve()
    meta = read_mirror_meta(p)
    sha256 = meta.get("sha256") if meta else None
    synced_at = meta.get("synced_at") if meta else None
    try:
        st = p.stat()
        mtime_ns = st.st_mtime_ns
        size = st.st_size
    except OSError:
        mtime_ns = 0
        size = 0
    return (source.value, str(p), sha256, synced_at, mtime_ns, size)


def get_cached_mirror(key: MirrorCacheKey) -> MirrorCacheEntry | None:
    """Retrieve cached in-memory mirror entry if key matches."""
    with _CACHE_LOCK:
        return _PROCESS_MIRROR_CACHE.get(key)


def put_cached_mirror(
    key: MirrorCacheKey,
    records: dict[str, Any],
    synced_at: datetime | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Store loaded mirror records in process-level cache, evicting older versions."""
    with _CACHE_LOCK:
        source_val, path_str = key[0], key[1]
        # Purge any older entry for the same (source, path) to prevent memory leaks
        keys_to_remove = [
            k for k in _PROCESS_MIRROR_CACHE if k[0] == source_val and k[1] == path_str
        ]
        for k in keys_to_remove:
            del _PROCESS_MIRROR_CACHE[k]
        _PROCESS_MIRROR_CACHE[key] = MirrorCacheEntry(
            records=records,
            synced_at=synced_at,
            extra=extra or {},
        )


def clear_mirror_cache(source: Source | None = None) -> None:
    """Purge process-level mirror cache entries (all or filtered by Source)."""
    with _CACHE_LOCK:
        if source is None:
            _PROCESS_MIRROR_CACHE.clear()
        else:
            keys_to_remove = [k for k in _PROCESS_MIRROR_CACHE if k[0] == source.value]
            for k in keys_to_remove:
                del _PROCESS_MIRROR_CACHE[k]


#: One load lock per (source, canonical path): a slow parse of one mirror (EPSS is
#: ~385k rows) must not stall loads of every other source behind a global lock.
_LOAD_LOCKS: dict[tuple[str, str], threading.Lock] = {}


def _load_lock(key: MirrorCacheKey) -> threading.Lock:
    with _CACHE_LOCK:
        return _LOAD_LOCKS.setdefault((key[0], key[1]), threading.Lock())


def load_with_cache(
    source: Source,
    cache_file: Path | str,
    loader_fn: Any,
) -> tuple[dict[str, Any], datetime | None, dict[str, Any]]:
    """Thread-safe cached loading of an on-disk mirror file.

    Double-checked locking ensures that concurrent workers or requests
    read and parse the mirror at most once, and share the identical in-memory
    record dictionary. The lock is per (source, path), so different mirrors load
    in parallel.
    """
    key = mirror_cache_key(source, cache_file)
    cached = get_cached_mirror(key)
    if cached is not None:
        return cached.records, cached.synced_at, cached.extra

    with _load_lock(key):
        cached = get_cached_mirror(key)
        if cached is not None:
            return cached.records, cached.synced_at, cached.extra

        records, synced_at, extra = loader_fn()
        put_cached_mirror(key, records=records, synced_at=synced_at, extra=extra)
        return records, synced_at, extra


class BaseSourceRecord(BaseModel):
    """Common fields for an intelligence record tied to a CVE."""

    model_config = ConfigDict(frozen=True)

    cve_id: str
    source: Source
    confidence: Confidence = Confidence.HIGH
    retrieved_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_payload: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def to_attributed(
        self,
        value: EnrichmentValue,
        source: Source | None = None,
        confidence: Confidence | None = None,
        note: str | None = None,
    ) -> Attributed[EnrichmentValue]:
        """Wrap an extracted value into an immutable Attributed container."""
        prov = Provenance(
            source=source or self.source,
            confidence=confidence or self.confidence,
            retrieved_at=self.retrieved_at,
            note=note,
        )
        return Attributed[EnrichmentValue](value=value, provenance=prov)


class BaseEnrichmentSource(ABC, Generic[RecordT]):
    """Abstract contract for offline-mirrored enrichment intelligence sources.

    Subclasses load data from local files/mirrors and perform fast in-memory
    lookups without making request-time network calls.
    """

    source: Source
    priority: int  # 1 is highest priority (CVE.org) per services/enrichment/README.md

    def __init__(self, cache_file: Path | str | None = None) -> None:
        self.cache_file = Path(cache_file) if cache_file else None
        self._cache: dict[str, RecordT] = {}
        self._loaded: bool = False
        self._synced_at: datetime | None = None
        self._synced_at_read = False
        if self.cache_file and self.cache_file.exists():
            self.load()

    @abstractmethod
    def load(self) -> None:
        """Load data from local cache storage into memory."""
        ...

    def mirror_synced_at(self) -> datetime | None:
        """When the sync job last wrote this mirror (from its sidecar), if known."""
        if not self._synced_at_read:
            meta = read_mirror_meta(self.cache_file) if self.cache_file else None
            self._synced_at = parse_feed_date(meta.get("synced_at")) if meta else None
            self._synced_at_read = True
        return self._synced_at

    def default_retrieved_at(self) -> datetime:
        """``retrieved_at`` for a record that carries no date of its own.

        The mirror's ``synced_at`` is when the data was actually retrieved from
        upstream. Without a sidecar the file's modification time (UTC) is the best
        evidence of when the data was placed; it is also stable across reloads,
        unlike load time, which the process cache would otherwise freeze into every
        record. Load time is used only when the file cannot be stat-ed.
        """
        synced = self.mirror_synced_at()
        if synced is not None:
            return synced
        if self.cache_file is not None:
            try:
                return datetime.fromtimestamp(self.cache_file.stat().st_mtime, tz=UTC)
            except OSError:
                pass
        return datetime.now(UTC)

    def _load_cached(self, index: Callable[[Path], dict[str, Any]]) -> None:
        """Load the mirror through the process cache; ``index`` parses one file.

        A missing mirror rebinds ``_cache`` to a fresh empty dict rather than
        clearing it: the cached dict is shared by every instance on that file.
        """
        if not self.cache_file or not self.cache_file.exists():
            self._cache = {}
            self._loaded = True
            return
        path = self.cache_file

        def _do_load() -> tuple[dict[str, Any], datetime | None, dict[str, Any]]:
            return index(path), self.mirror_synced_at(), {}

        records, synced_at, _ = load_with_cache(self.source, path, _do_load)
        self._cache = records
        self._synced_at = synced_at
        self._synced_at_read = True
        self._loaded = True

    def _ensure_loaded(self) -> None:
        """Lazily load the mirror file if it exists and has not been loaded yet."""
        if not self._loaded and self.cache_file and self.cache_file.exists():
            self._synced_at_read = False
            self.load()

    @property
    def is_loaded(self) -> bool:
        """True only when a mirror has been loaded and holds at least one record.

        A missing file, an unreadable feed, or an empty catalog all count as
        *not loaded*: absence from such a mirror says nothing about the CVE, so
        callers must not turn a lookup miss into a confident negative.
        """
        self._ensure_loaded()
        return self._loaded and bool(self._cache)

    def is_cached(self, cve_id: str) -> bool:
        """Check if intelligence for a CVE is present in local cache."""
        self._ensure_loaded()
        return cve_id.strip().upper() in self._cache

    def lookup(self, cve_id: str) -> RecordT | None:
        """Look up intelligence for a CVE from local mirror.

        CRITICAL: Never initiates network calls. Returns None if the CVE is not
        in the local mirror.
        """
        self._ensure_loaded()
        return self._cache.get(cve_id.strip().upper())

    def count(self) -> int:
        """Return the number of records indexed in local cache."""
        self._ensure_loaded()
        return len(self._cache)

    def clear(self) -> None:
        """Clear this instance's in-memory index."""
        self._cache = {}
        self._loaded = False
        self._synced_at_read = False

    @classmethod
    def clear_mirror_cache(cls) -> None:
        """Clear the process-level mirror cache for this source."""
        clear_mirror_cache(cls.source)
