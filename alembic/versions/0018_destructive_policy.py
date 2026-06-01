"""add destructive policy and process timestamps

Revision ID: 0018_destructive_policy
Revises: 0017_scan_policy
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0018_destructive_policy"
down_revision = "0017_scan_policy"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _tables() -> set[str]:
    return set(_inspector().get_table_names())


def _columns(table: str) -> set[str]:
    if table not in _tables():
        return set()
    return {column["name"] for column in _inspector().get_columns(table)}


def _add_column(table: str, column: sa.Column) -> None:
    if table in _tables() and column.name not in _columns(table):
        op.add_column(table, column)


def _drop_column(table: str, column: str) -> None:
    if table in _tables() and column in _columns(table):
        op.drop_column(table, column)


def _add_bool_not_null(table: str, column: str, default: bool = False) -> None:
    _add_column(table, sa.Column(column, sa.Boolean(), nullable=True))
    if column in _columns(table):
        value = "true" if default else "false"
        op.execute(sa.text(f"UPDATE {table} SET {column}={value} WHERE {column} IS NULL"))
        op.alter_column(table, column, nullable=False)


def _add_timestamp_not_null(table: str, column: str) -> None:
    _add_column(table, sa.Column(column, sa.DateTime(timezone=True), nullable=True))
    if column in _columns(table):
        op.execute(sa.text(f"UPDATE {table} SET {column}=now() WHERE {column} IS NULL"))
        op.alter_column(table, column, nullable=False)


def upgrade() -> None:
    if "scan_processes" in _tables():
        _add_timestamp_not_null("scan_processes", "created_at")
        _add_timestamp_not_null("scan_processes", "updated_at")

    if "scans" in _tables():
        _add_bool_not_null("scans", "enable_destructive_tests", False)
        _add_column("scans", sa.Column("destructive_test_policy", sa.String(length=80), nullable=True))
        if "destructive_test_policy" in _columns("scans"):
            op.execute(sa.text("UPDATE scans SET destructive_test_policy='detect_only' WHERE destructive_test_policy IS NULL"))
            op.alter_column("scans", "destructive_test_policy", nullable=False)
        _add_bool_not_null("scans", "allow_test_owned_object_creation", False)
        _add_bool_not_null("scans", "confirm_destructive_testing", False)


def downgrade() -> None:
    for column in [
        "confirm_destructive_testing",
        "allow_test_owned_object_creation",
        "destructive_test_policy",
        "enable_destructive_tests",
    ]:
        _drop_column("scans", column)
    for column in ["updated_at", "created_at"]:
        _drop_column("scan_processes", column)
