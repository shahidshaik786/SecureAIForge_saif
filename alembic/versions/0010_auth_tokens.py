"""add authenticated session token metadata

Revision ID: 0010_auth_tokens
Revises: 0009_ai_calls
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0010_auth_tokens"
down_revision = "0009_ai_calls"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add(name: str, column_type) -> None:
    if name not in _columns("authenticated_sessions"):
        op.add_column("authenticated_sessions", sa.Column(name, column_type, nullable=True))


def upgrade() -> None:
    _add("access_token_secret", sa.Text())
    _add("access_token_hash", sa.String(length=128))
    _add("access_token_masked", sa.Text())
    _add("secret_ref", sa.Text())
    _add("authorization_header_type", sa.String(length=80))
    _add("session_status", sa.String(length=80))


def downgrade() -> None:
    for column in ["session_status", "authorization_header_type", "secret_ref", "access_token_masked", "access_token_hash", "access_token_secret"]:
        if column in _columns("authenticated_sessions"):
            op.drop_column("authenticated_sessions", column)
