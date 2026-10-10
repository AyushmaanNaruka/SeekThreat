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
