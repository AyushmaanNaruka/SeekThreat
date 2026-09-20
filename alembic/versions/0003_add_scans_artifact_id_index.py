"""add missing index on scans.artifact_id

apps/api/db/models.py declares index=True on ScanModel.artifact_id, but
migration 0002 created only ix_scans_engagement_id and ix_scans_status. So
create_all (used by the test suite) and `alembic upgrade head` (used by a real
deployment) produced different schemas -- meaning a green test run said
nothing about the indexes that would actually exist in production.

tests/unit/test_alembic.py::test_migrations_match_orm_metadata_indexes now
compares the two schemas directly and fails on any future drift.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-20 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_scans_artifact_id",
        "scans",
        ["artifact_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_artifact_id", table_name="scans")
