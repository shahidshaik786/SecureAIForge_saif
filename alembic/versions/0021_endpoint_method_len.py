"""expand discovered endpoint method length

Revision ID: 0021_endpoint_method_len
Revises: 0020_dash_control
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0021_endpoint_method_len"
down_revision = "0020_dash_control"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in set(inspector.get_table_names()):
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def upgrade() -> None:
    if "method" in _columns("discovered_endpoints"):
        op.alter_column("discovered_endpoints", "method", existing_type=sa.String(length=20), type_=sa.String(length=80), nullable=True)


def downgrade() -> None:
    if "method" in _columns("discovered_endpoints"):
        op.alter_column("discovered_endpoints", "method", existing_type=sa.String(length=80), type_=sa.String(length=20), nullable=True)
