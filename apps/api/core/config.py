"""Application configuration and environment settings."""

from __future__ import annotations

import os

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @field_validator("database_url", mode="after")
    @classmethod
    def _apply_psycopg_driver(cls, value: str) -> str:
        # Runs on every source (env var, .env file, and the default above), not
        # just the default -- a bare `postgresql://` DATABASE_URL set via
        # environment or .env previously bypassed this and resolved to
        # psycopg2 in SQLAlchemy, which this project does not install.
        return _normalize_db_url(value)


settings = Settings()
