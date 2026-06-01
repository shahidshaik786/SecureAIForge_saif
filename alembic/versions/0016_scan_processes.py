"""add scan process tracking

Revision ID: 0016_scan_processes
Revises: 0015_engagement
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0016_scan_processes"
down_revision = "0015_engagement"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "scan_processes" in _tables():
        return
    op.create_table(
        "scan_processes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("pid", sa.Integer(), nullable=True),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=80), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("log_path", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    if "scan_processes" in _tables():
        op.drop_table("scan_processes")
