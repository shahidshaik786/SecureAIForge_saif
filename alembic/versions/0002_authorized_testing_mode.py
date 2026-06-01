"""rename legacy scan mode column to authorized testing mode

Revision ID: 0002_authorized_testing_mode
Revises: 0001_initial_foundation
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_authorized_testing_mode"
down_revision = "0001_initial_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "safe_mode" in columns and "authorized_testing_mode" not in columns:
        op.alter_column("scans", "safe_mode", new_column_name="authorized_testing_mode")
    elif "authorized_testing_mode" not in columns:
        op.add_column("scans", sa.Column("authorized_testing_mode", sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "authorized_testing_mode" in columns and "safe_mode" not in columns:
        op.alter_column("scans", "authorized_testing_mode", new_column_name="safe_mode")
