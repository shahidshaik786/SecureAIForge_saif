"""add adaptive finding fields

Revision ID: 0008_adaptive_findings
Revises: 0007_auth_sessions
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0008_adaptive_findings"
down_revision = "0007_auth_sessions"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add(name: str, column_type) -> None:
    if name not in _columns("findings"):
        op.add_column("findings", sa.Column(name, column_type, nullable=True))


def upgrade() -> None:
    _add("affected_endpoint", sa.Text())
    _add("parameter", sa.String(length=255))
    _add("payload", sa.Text())
    _add("confidence", sa.String(length=40))
    _add("reproduction_steps", sa.Text())
    _add("remediation", sa.Text())
    _add("closure_evidence_path", sa.Text())
    _add("fixed_at", sa.DateTime(timezone=True))


def downgrade() -> None:
    for column in ["fixed_at", "closure_evidence_path", "remediation", "reproduction_steps", "confidence", "payload", "parameter", "affected_endpoint"]:
        if column in _columns("findings"):
            op.drop_column("findings", column)
