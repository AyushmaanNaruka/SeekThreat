"""Application configuration and environment settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: Must equal services.enrichment.sources.sync.DEFAULT_CACHE_DIR (the FeedSyncer
#: default). Not imported from there: importing services.enrichment from config is
#: circular (services.enrichment -> service -> apps.api.db -> config). The equality
#: is enforced by tests/unit/test_enrichment_wiring.py and test_feed_sync.py.
DEFAULT_ENRICHMENT_CACHE_DIR = Path("data") / "enrichment_cache"


def _normalize_db_url(url: str) -> str:
    """Ensure PostgreSQL URLs use the psycopg (psycopg3) driver for SQLAlchemy."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://seekthreat:changeme@localhost:5432/seekthreat",
        )
    )
    redis_url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    # NoDecode: pydantic-settings otherwise treats any list-typed field as
    # "complex" and tries to JSON-decode its raw env value before this class
    # ever sees it, which raises on a plain comma-separated string. NoDecode
    # hands the raw string to the "before" validator below instead.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            origin.strip()
            for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
            if origin.strip()
        ]
    )

    nmap_path: str | None = Field(
        default_factory=lambda: os.getenv("NMAP_PATH"),
        description=(
            "Absolute path to the nmap binary. "
            "If unset, shutil.which('nmap') is used. "
            "Set in .env on Windows: NMAP_PATH=C:\\Program Files (x86)\\Nmap\\nmap.exe"
        ),
    )
    nuclei_path: str | None = Field(
        default_factory=lambda: os.getenv("NUCLEI_PATH"),
        description=(
            "Absolute path to the nuclei binary. If unset, shutil.which('nuclei') is used."
        ),
    )

    enrichment_cache_dir: Path = Field(
        default=DEFAULT_ENRICHMENT_CACHE_DIR,
        description=(
            "Directory holding the local enrichment feed mirrors written by the feed "
            "sync job and read by EnrichmentService. Read from ENRICHMENT_CACHE_DIR; "
            "defaults to the same directory FeedSyncer writes to (data/enrichment_cache), "
            "so the writer and the readers can never disagree."
        ),
    )
    nvd_api_key: str | None = Field(
        default=None,
        description=(
            "Optional NVD API key (NVD_API_KEY) for the feed sync job's targeted NVD "
            "lookups. Without one NVD allows 5 requests per 30 seconds."
        ),
    )

    post_scan_max_cves: int = Field(
        default=200,
        ge=1,
        description=(
            "POST_SCAN_MAX_CVES: most distinct CVE IDs one post-scan enrichment run sends "
            "upstream. The rest are logged as deferred and picked up by the daily beat "
            "sync, which reads CVE IDs from VULN_CANDIDATE observations too. Bounds how "
            "long one large scan can hold the enrichment worker."
        ),
    )
    post_scan_soft_time_limit_seconds: int = Field(
        default=1800,
        ge=120,
        description=(
            "POST_SCAN_SOFT_TIME_LIMIT_SECONDS: Celery soft time limit of the post-scan "
            "enrichment task (the hard limit is 120 s more). The targeted sync gets a time "
            "budget inside it and defers what it cannot reach. 1800 s covers the default "
            "200-CVE cap against NVD without an API key (6 s per lookup)."
        ),
    )
    mirror_staleness_threshold_days: int = Field(
        default=7,
        ge=1,
        description=(
            "MIRROR_STALENESS_THRESHOLD_DAYS: Number of days after which a local feed mirror "
            "is considered stale. When a mirror is stale, negative assertions produced from it "
            "(in_kev=False, has_public_exploit=False, has_metasploit_module=False) are "
            "downgraded from Confidence.HIGH to Confidence.MEDIUM in the fusion engine, "
            "and an explanatory provenance note is attached. Positive hits are never downgraded. "
            "Default: 7 days. Set via MIRROR_STALENESS_THRESHOLD_DAYS in .env."
        ),
    )

    @field_validator("database_url", mode="after")
    @classmethod
    def _apply_psycopg_driver(cls, value: str) -> str:
        # Runs on every source (env var, .env file, and the default above), not
        # just the default -- a bare `postgresql://` DATABASE_URL set via
        # environment or .env previously bypassed this and resolved to
        # psycopg2 in SQLAlchemy, which this project does not install.
        return _normalize_db_url(value)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, value: Any) -> Any:
        # Only a raw env/`.env` string needs splitting; the default_factory
        # above already returns a parsed list when CORS_ORIGINS is unset.
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


settings = Settings()
