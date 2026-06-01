"""add scan progress and events

Revision ID: 0013_scan_progress
Revises: 0012_profiles_inv
Create Date: 2026-06-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0013_scan_progress"
down_revision = "0012_profiles_inv"
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
    _add("scans", sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True))
    _add("scans", sa.Column("current_phase", sa.String(length=120), nullable=True))
    _add("scans", sa.Column("current_agent", sa.String(length=120), nullable=True))
    _add("scans", sa.Column("current_tool", sa.String(length=120), nullable=True))
    _add("scans", sa.Column("progress_message", sa.Text(), nullable=True))
    _add("scans", sa.Column("progress_percent", sa.Integer(), nullable=True))
    if "scan_events" not in _tables():
        op.create_table(
            "scan_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("level", sa.String(length=40), nullable=False),
            sa.Column("phase", sa.String(length=120), nullable=True),
            sa.Column("agent_name", sa.String(length=120), nullable=True),
            sa.Column("tool_name", sa.String(length=120), nullable=True),
            sa.Column("event_type", sa.String(length=80), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("context_json", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )


def downgrade() -> None:
    if "scan_events" in _tables():
        op.drop_table("scan_events")
    for column in ["progress_percent", "progress_message", "current_tool", "current_agent", "current_phase", "last_activity_at"]:
        if column in _columns("scans"):
            op.drop_column("scans", column)
