"""add dashboard scan control fields

Revision ID: 0020_dash_control
Revises: 0019_scan_worker_track
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0020_dash_control"
down_revision = "0019_scan_worker_track"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _add(table: str, column: sa.Column) -> None:
    if column.name not in _columns(table):
        op.add_column(table, column)


def _add_bool(table: str, column: str) -> None:
    _add(table, sa.Column(column, sa.Boolean(), nullable=True))
    if column in _columns(table):
        op.execute(sa.text(f"UPDATE {table} SET {column}=false WHERE {column} IS NULL"))
        op.alter_column(table, column, nullable=False)


def upgrade() -> None:
    _add("scans", sa.Column("scan_config", sa.JSON(), nullable=True))
    _add_bool("scans", "pause_requested")
    _add_bool("scans", "stop_requested")


def downgrade() -> None:
    for column in ["stop_requested", "pause_requested", "scan_config"]:
        if column in _columns("scans"):
            op.drop_column("scans", column)
