"""create engagement_topologies table

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-06 20:00:00.000000

One declared NetworkTopology per engagement (Layer 3 attack-graph input).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "engagement_topologies",
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("topology_id", sa.String(length=128), nullable=False),
        sa.Column("document", json_type, nullable=False),
        sa.Column("declared_by", sa.String(length=128), nullable=False),
        sa.Column("declared_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.engagement_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("engagement_id"),
    )


def downgrade() -> None:
    op.drop_table("engagement_topologies")
