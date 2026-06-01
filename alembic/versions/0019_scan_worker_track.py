"""require scan id for scan worker processes

Revision ID: 0019_scan_worker_track
Revises: 0018_destructive_policy
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0019_scan_worker_track"
down_revision = "0018_destructive_policy"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    if "scan_id" in _columns("scan_processes"):
        op.execute(sa.text("DELETE FROM scan_processes WHERE scan_id IS NULL"))
        op.alter_column("scan_processes", "scan_id", existing_type=sa.Integer(), nullable=False)


def downgrade() -> None:
    if "scan_id" in _columns("scan_processes"):
        op.alter_column("scan_processes", "scan_id", existing_type=sa.Integer(), nullable=True)
