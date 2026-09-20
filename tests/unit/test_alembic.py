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
