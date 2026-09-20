"""Tests for apps.api.core.config.Settings.

The psycopg3 driver rewrite must apply regardless of where database_url comes
from. Settings.database_url previously normalized only its *default* value
(inside a default_factory), so a DATABASE_URL set via environment variable or
.env file passed through unnormalized -- a bare `postgresql://` URL resolves
to psycopg2 in SQLAlchemy, which this project does not install (it ships
psycopg[binary], i.e. psycopg3). See DECISIONS.md D-018.
"""

from __future__ import annotations

import importlib

import apps.api.core.config as config_module


def _settings_with_env(monkeypatch, **env: str) -> config_module.Settings:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    importlib.reload(config_module)
    return config_module.Settings()


def test_env_database_url_gets_psycopg_driver(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgresql://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert (
        settings.database_url == "postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat"
    )


def test_env_postgres_scheme_database_url_gets_psycopg_driver(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgres://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert (
        settings.database_url == "postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat"
    )


def test_env_database_url_already_normalized_is_unchanged(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert (
        settings.database_url == "postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat"
    )


def test_default_database_url_is_normalized(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(config_module)
    settings = config_module.Settings()
    assert settings.database_url.startswith("postgresql+psycopg://")
