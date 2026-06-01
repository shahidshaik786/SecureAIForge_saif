"""add timestamps to discovery pipeline tables

Revision ID: 0004_pipeline_timestamps
Revises: 0003_pipeline_discovery_tables
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_pipeline_timestamps"
down_revision = "0003_pipeline_discovery_tables"
branch_labels = None
depends_on = None


TABLES = [
    "discovered_assets",
    "discovered_endpoints",
    "discovered_parameters",
    "discovered_auth_flows",
    "discovered_tokens",
    "discovered_roles",
    "discovered_objects",
    "authorization_matrix",
    "pipeline_artifacts",
]


def _columns(table_name: str) -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    for table in TABLES:
        columns = _columns(table)
        if not columns:
            continue

        if "created_at" not in columns:
            op.add_column(table, sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
        if "updated_at" not in columns:
            op.add_column(table, sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))

        columns = _columns(table)
        if "created_at" in columns:
            op.execute(sa.text(f"UPDATE {table} SET created_at = now() WHERE created_at IS NULL"))
            op.alter_column(table, "created_at", nullable=False, existing_type=sa.DateTime(timezone=True))
        if "updated_at" in columns:
            op.execute(sa.text(f"UPDATE {table} SET updated_at = now() WHERE updated_at IS NULL"))
            op.alter_column(table, "updated_at", nullable=False, existing_type=sa.DateTime(timezone=True))


def downgrade() -> None:
    for table in reversed(TABLES):
        columns = _columns(table)
        if "updated_at" in columns:
            op.drop_column(table, "updated_at")
        if "created_at" in columns:
            op.drop_column(table, "created_at")
