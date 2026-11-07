"""create assistant_documents table (pgvector)

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-07 12:00:00.000000

The Layer 4 assistant's retrieval index: one row per retrievable fact per embedding
model. On PostgreSQL the embedding is a pgvector `vector` (D-005; the compose image is
pgvector/pgvector:pg16, which ships the extension). On SQLite (unit tests) it is JSON.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from apps.api.db.types import EMBEDDING_TYPE

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.create_table(
        "assistant_documents",
        sa.Column("engagement_id", sa.String(length=128), nullable=False),
        sa.Column("doc_id", sa.String(length=256), nullable=False),
        sa.Column("embed_model", sa.String(length=128), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("metadata", json_type, nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("embedding", EMBEDDING_TYPE, nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["engagement_id"],
            ["engagements.engagement_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("engagement_id", "doc_id", "embed_model"),
    )


def downgrade() -> None:
    # The `vector` extension is left installed: dropping it is a cluster-level change
    # other databases or a later migration may rely on.
    op.drop_table("assistant_documents")
