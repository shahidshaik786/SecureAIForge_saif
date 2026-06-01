"""add output summary to test runs

Revision ID: 0006_test_run_summary
Revises: 0005_orchestration
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0006_test_run_summary"
down_revision = "0005_orchestration"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    columns = _columns("test_runs")
    if columns and "output_summary" not in columns:
        op.add_column("test_runs", sa.Column("output_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    if "output_summary" in _columns("test_runs"):
        op.drop_column("test_runs", "output_summary")
