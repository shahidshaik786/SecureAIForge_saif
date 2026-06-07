"""mark observations separately from findings

Revision ID: 0024_finding_type_observations
Revises: 0023_test_case_scan_uniqueness
Create Date: 2026-06-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0024_finding_type_observations"
down_revision = "0023_test_case_scan_uniqueness"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = inspector.get_table_names()
    if "findings" not in tables:
        return
    columns = {item["name"] for item in inspector.get_columns("findings")}
    if "finding_type" not in columns:
        op.add_column("findings", sa.Column("finding_type", sa.String(length=40), nullable=False, server_default="finding"))
    op.execute("UPDATE findings SET finding_type = 'observation' WHERE severity = 'info' OR status = 'informational'")


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "findings" not in inspector.get_table_names():
        return
    columns = {item["name"] for item in inspector.get_columns("findings")}
    if "finding_type" in columns:
        op.drop_column("findings", "finding_type")
