"""Application configuration and environment settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator
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
    nikto_path: str | None = Field(
        default_factory=lambda: os.getenv("NIKTO_PATH"),
        description=(
            "Absolute path to the nikto executable (nikto or nikto.pl). "
            "If unset, shutil.which('nikto') is used."
        ),
    )
    ssh_audit_path: str | None = Field(
        default_factory=lambda: os.getenv("SSH_AUDIT_PATH"),
        description=(
            "Absolute path to the ssh-audit executable. "
            "If unset, shutil.which('ssh-audit') is used."
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

    # Neo4j is a read-only, disposable projection for visualization (D-003), served by
    # the `viz` compose profile. Unset NEO4J_URI or NEO4J_PASSWORD means "not
    # configured": the projection endpoint answers 503 and nothing else is affected.
    neo4j_uri: str | None = Field(
        default=None,
        description=(
            "NEO4J_URI: Bolt URI of the viz-profile Neo4j, e.g. bolt://localhost:7687 for "
            "native dev, bolt://neo4j:7687 inside the compose network."
        ),
    )
    neo4j_user: str = Field(default="neo4j", description="NEO4J_USER")
    neo4j_password: str | None = Field(
        default=None,
        description="NEO4J_PASSWORD: must match the password in the compose NEO4J_AUTH.",
    )
    neo4j_connection_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        description=(
            "NEO4J_CONNECTION_TIMEOUT_SECONDS: how long the projection waits for Neo4j "
            "before answering 503."
        ),
    )

    # Layer 4 assistant (D-006): one Ollama server behind the ModelClient interface,
    # served by the `model` compose profile. Unreachable Ollama never breaks the rest
    # of the API: the assistant endpoints answer 503 and say how to start it.
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        validation_alias=AliasChoices("OLLAMA_BASE_URL", "OLLAMA_HOST"),
        description=(
            "OLLAMA_BASE_URL (OLLAMA_HOST also accepted): http://localhost:11434 for "
            "native dev, http://ollama:11434 inside the compose network."
        ),
    )
    # D-006 names Foundation-Sec-8B-Reasoning as the target model. It is not pulled on
    # the dev machines yet, so the default is a general model that is; switch with
    # ASSISTANT_MODEL once Foundation-Sec is available in Ollama.
    assistant_model: str = Field(
        default="qwen2.5:7b",
        description="ASSISTANT_MODEL: Ollama tag of the text model that answers and narrates.",
    )
    assistant_embed_model: str = Field(
        default="nomic-embed-text",
        description=(
            "ASSISTANT_EMBED_MODEL: Ollama tag of the embedding model. Changing it needs a "
            "re-index (POST /engagements/{id}/assistant/index); vectors are stored per model."
        ),
    )
    assistant_timeout_seconds: float = Field(
        default=120.0,
        gt=0,
        description="ASSISTANT_TIMEOUT_SECONDS: per-request timeout for generate/embed calls.",
    )
    assistant_status_timeout_seconds: float = Field(
        default=3.0,
        gt=0,
        description=(
            "ASSISTANT_STATUS_TIMEOUT_SECONDS: timeout of the cheap /api/tags probe behind "
            "GET /assistant/status."
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
