"""add scan event timestamps

Revision ID: 0014_scan_event_ts
Revises: 0013_scan_progress
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0014_scan_event_ts"
down_revision = "0013_scan_progress"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    if table not in _tables():
        return set()
    return {column["name"] for column in sa.inspect(op.get_bind()).get_columns(table)}


def _add(table: str, column: sa.Column) -> None:
    if column.name not in _columns(table):
        op.add_column(table, column)


def upgrade() -> None:
    _add("scan_events", sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
    _add("scan_events", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("update scan_events set created_at = now() where created_at is null")
    op.execute("update scan_events set updated_at = now() where updated_at is null")
    if "created_at" in _columns("scan_events"):
        op.alter_column("scan_events", "created_at", nullable=False)
    if "updated_at" in _columns("scan_events"):
        op.alter_column("scan_events", "updated_at", nullable=False)


def downgrade() -> None:
    for column in ["updated_at", "created_at"]:
        if column in _columns("scan_events"):
            op.drop_column("scan_events", column)
