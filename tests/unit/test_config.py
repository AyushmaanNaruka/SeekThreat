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
    return config_module.Settings(_env_file=None)


_PSYCOPG_URL = "postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat"


def test_env_database_url_gets_psycopg_driver(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgresql://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert settings.database_url == _PSYCOPG_URL


def test_env_postgres_scheme_database_url_gets_psycopg_driver(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgres://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert settings.database_url == _PSYCOPG_URL


def test_env_database_url_already_normalized_is_unchanged(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        DATABASE_URL="postgresql+psycopg://seekthreat:changeme@postgres:5432/seekthreat",
    )
    assert settings.database_url == _PSYCOPG_URL


def test_default_database_url_is_normalized(monkeypatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(config_module)
    settings = config_module.Settings(_env_file=None)
    assert settings.database_url.startswith("postgresql+psycopg://")


# ---------------------------------------------------------------------------
# cors_origins: comma-separated env var, split and stripped into a list.
#
# The browser-based dashboard (apps/web, a separate Next.js dev server on
# localhost:3000) needs CORS_ORIGINS to parse cleanly, including the messy
# whitespace a developer will actually type in a .env file.
# ---------------------------------------------------------------------------


def test_cors_origins_parses_comma_separated_env_with_whitespace(monkeypatch) -> None:
    settings = _settings_with_env(
        monkeypatch,
        CORS_ORIGINS="http://a.com, http://b.com ",
    )
    assert settings.cors_origins == ["http://a.com", "http://b.com"]


def test_cors_origins_defaults_to_localhost_3000_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    importlib.reload(config_module)
    settings = config_module.Settings(_env_file=None)
    assert settings.cors_origins == ["http://localhost:3000"]
