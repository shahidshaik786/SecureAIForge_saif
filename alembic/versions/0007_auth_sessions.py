"""add authenticated sessions

Revision ID: 0007_auth_sessions
Revises: 0006_test_run_summary
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0007_auth_sessions"
down_revision = "0006_test_run_summary"
branch_labels = None
depends_on = None


def _has_table(table_name: str) -> bool:
    return table_name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table("authenticated_sessions"):
        op.create_table(
            "authenticated_sessions",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("credential_label", sa.String(length=120), nullable=False),
            sa.Column("username", sa.String(length=255), nullable=True),
            sa.Column("role", sa.String(length=120), nullable=True),
            sa.Column("tenant", sa.String(length=120), nullable=True),
            sa.Column("auth_type", sa.String(length=80), nullable=False),
            sa.Column("access_token", sa.Text(), nullable=True),
            sa.Column("refresh_token", sa.Text(), nullable=True),
            sa.Column("cookie", sa.Text(), nullable=True),
            sa.Column("authorization_header", sa.Text(), nullable=True),
            sa.Column("token_type", sa.String(length=80), nullable=True),
            sa.Column("login_status", sa.String(length=80), nullable=False),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )


def downgrade() -> None:
    if _has_table("authenticated_sessions"):
        op.drop_table("authenticated_sessions")
