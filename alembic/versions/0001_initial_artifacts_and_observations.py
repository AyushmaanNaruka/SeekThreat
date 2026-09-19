"""create raw_artifacts and observations tables

Revision ID: 0001
Revises: 
Create Date: 2026-09-19 10:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "raw_artifacts",
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("artifact_id"),
    )

    op.create_table(
        "observations",
        sa.Column("observation_id", sa.String(length=128), nullable=False),
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("attributes", json_type, nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provenance", json_type, nullable=False),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["raw_artifacts.artifact_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("observation_id"),
    )

    op.create_index(
        "ix_observations_engagement_id",
        "observations",
        ["engagement_id"],
        unique=False,
    )
    op.create_index(
        "ix_observations_artifact_id",
        "observations",
        ["artifact_id"],
        unique=False,
    )
    op.create_index(
        "ix_observations_kind",
        "observations",
        ["kind"],
        unique=False,
    )
    op.create_index(
        "ix_observations_engagement_kind",
        "observations",
        ["engagement_id", "kind"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_observations_engagement_kind", table_name="observations")
    op.drop_index("ix_observations_kind", table_name="observations")
    op.drop_index("ix_observations_artifact_id", table_name="observations")
    op.drop_index("ix_observations_engagement_id", table_name="observations")
    op.drop_table("observations")
    op.drop_table("raw_artifacts")
