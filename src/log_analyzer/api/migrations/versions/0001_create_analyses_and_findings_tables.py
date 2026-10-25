"""Create analyses and findings tables

Revision ID: 0001
Revises:
Create Date: 2026-10-25 15:36:58.022271
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("scan_threshold", sa.Integer(), nullable=False),
        sa.Column("year", sa.Integer(), nullable=True),
        sa.Column("total_events", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("analyses", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_analyses_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_analyses_status"), ["status"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=False),
        sa.Column("detection", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_analysis_id"), ["analysis_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_ip"), ["ip"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_severity"), ["severity"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_severity"))
        batch_op.drop_index(batch_op.f("ix_findings_ip"))
        batch_op.drop_index(batch_op.f("ix_findings_analysis_id"))

    op.drop_table("findings")
    with op.batch_alter_table("analyses", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_analyses_status"))
        batch_op.drop_index(batch_op.f("ix_analyses_created_at"))

    op.drop_table("analyses")
