"""Unit tests verifying Alembic migrations upgrade and downgrade cleanly."""

from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "alembic.ini"


def test_alembic_upgrade_and_downgrade(tmp_path: Path) -> None:
    """Verify that migrations can upgrade to head and downgrade to base without error."""
    db_file = tmp_path / "test_migration.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    # 1. Upgrade to head
    command.upgrade(alembic_cfg, "head")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    assert "raw_artifacts" in tables
    assert "observations" in tables

    raw_cols = {c["name"] for c in inspector.get_columns("raw_artifacts")}
    assert {"artifact_id", "scanner", "content", "content_type", "captured_at"}.issubset(raw_cols)

    obs_cols = {c["name"] for c in inspector.get_columns("observations")}
    assert {
        "observation_id",
        "engagement_id",
        "scanner",
        "kind",
        "subject",
        "attributes",
        "artifact_id",
        "observed_at",
        "provenance",
    }.issubset(obs_cols)

    engine.dispose()

    # 2. Downgrade back to base
    command.downgrade(alembic_cfg, "base")

    engine = create_engine(db_url)
    inspector = inspect(engine)
    tables_after = set(inspector.get_table_names())
    assert "raw_artifacts" not in tables_after
    assert "observations" not in tables_after

    engine.dispose()


def test_migrations_match_orm_metadata_indexes(tmp_path: Path) -> None:
    """`alembic upgrade head` must produce the same indexes as `create_all`.

    models.py declared index=True on scans.artifact_id but migration 0002 never
    created it, so tests (which build the schema with create_all) and a real
    deployment (which runs migrations) disagreed about the schema -- the exact
    drift that makes a passing test suite stop meaning anything about prod.
    """
    from apps.api.db import models as _models  # noqa: F401 – registers ORM tables
    from apps.api.db.base import Base

    migrated_url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option("sqlalchemy.url", migrated_url)
    command.upgrade(alembic_cfg, "head")

    migrated_engine = create_engine(migrated_url)
    migrated = inspect(migrated_engine)

    create_all_url = f"sqlite:///{(tmp_path / 'create_all.db').as_posix()}"
    create_all_engine = create_engine(create_all_url)
    Base.metadata.create_all(bind=create_all_engine)
    expected = inspect(create_all_engine)

    for table in sorted(Base.metadata.tables):
        migrated_indexes = {
            (i["name"], tuple(i["column_names"])) for i in migrated.get_indexes(table)
        }
        expected_indexes = {
            (i["name"], tuple(i["column_names"])) for i in expected.get_indexes(table)
        }
        assert migrated_indexes == expected_indexes, (
            f"index drift on {table!r}: "
            f"missing from migrations={expected_indexes - migrated_indexes}, "
            f"unexpected in migrations={migrated_indexes - expected_indexes}"
        )

    migrated_engine.dispose()
    create_all_engine.dispose()
