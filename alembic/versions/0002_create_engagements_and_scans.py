"""create engagements and scans tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-19 10:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("authorized_by", sa.String(length=128), nullable=False),
        sa.Column("allowlist", json_type, nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("engagement_id"),
    )

    op.create_table(
        "scans",
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("scanner", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("options", json_type, nullable=False),
        sa.Column("artifact_id", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.engagement_id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["raw_artifacts.artifact_id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("scan_id"),
    )

    op.create_index(
        "ix_scans_engagement_id",
        "scans",
        ["engagement_id"],
        unique=False,
    )
    op.create_index(
        "ix_scans_status",
        "scans",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_engagement_id", table_name="scans")
    op.drop_table("scans")
    op.drop_table("engagements")
