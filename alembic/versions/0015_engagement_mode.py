"""add engagement mode metadata

Revision ID: 0015_engagement
Revises: 0014_scan_event_ts
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0015_engagement"
down_revision = "0014_scan_event_ts"
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
    _add("scans", sa.Column("engagement_mode", sa.String(length=40), nullable=True))
    _add("scans", sa.Column("credentials_path", sa.Text(), nullable=True))
    _add("scans", sa.Column("source_path", sa.Text(), nullable=True))


def downgrade() -> None:
    for column in ["source_path", "credentials_path", "engagement_mode"]:
        if column in _columns("scans"):
            op.drop_column("scans", column)
