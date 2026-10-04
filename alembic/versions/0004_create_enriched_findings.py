"""create enriched_findings table

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-30 10:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "enriched_findings",
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("finding_id", sa.String(length=128), nullable=False),
        sa.Column("finding_data", json_type, nullable=False),
        sa.Column("fields", json_type, nullable=False),
        sa.Column("ers_value", sa.Float(), nullable=True),
        sa.Column("ers_components", json_type, nullable=True),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.engagement_id"],
            ondelete="CASCADE",
        ),
        # finding_id is unique only within an engagement; a global key would let
        # one engagement's enrichment overwrite another's row.
        sa.PrimaryKeyConstraint("engagement_id", "finding_id"),
    )

    op.create_index(
        "ix_enriched_findings_engagement_id",
        "enriched_findings",
        ["engagement_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_enriched_findings_engagement_id", table_name="enriched_findings")
    op.drop_table("enriched_findings")
