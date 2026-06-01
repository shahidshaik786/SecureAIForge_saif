"""add scan policy and test plan

Revision ID: 0017_scan_policy
Revises: 0016_scan_processes
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0017_scan_policy"
down_revision = "0016_scan_processes"
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
    _add("scans", sa.Column("auth_mode", sa.String(length=80), nullable=True))
    _add("scans", sa.Column("destructive_method_policy", sa.String(length=80), nullable=True))
    for column in [
        "allow_account_generation",
        "allow_authenticated_testing",
        "allow_authorization_testing",
        "allow_payload_testing",
        "allow_rate_limit_testing",
    ]:
        _add("scans", sa.Column(column, sa.Boolean(), nullable=True))
        op.execute(sa.text(f"UPDATE scans SET {column}=false WHERE {column} IS NULL"))
        op.alter_column("scans", column, nullable=False)

    if "scan_test_plan" not in _tables():
        op.create_table(
            "scan_test_plan",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("category", sa.String(length=160), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("status", sa.String(length=80), nullable=False),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("scan_id", "category", name="uq_scan_test_plan_category"),
        )


def downgrade() -> None:
    if "scan_test_plan" in _tables():
        op.drop_table("scan_test_plan")
    for column in [
        "allow_rate_limit_testing",
        "allow_payload_testing",
        "allow_authorization_testing",
        "allow_authenticated_testing",
        "allow_account_generation",
        "destructive_method_policy",
        "auth_mode",
    ]:
        if column in _columns("scans"):
            op.drop_column("scans", column)
