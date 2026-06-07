"""add ai decisions trace table

Revision ID: 0022_ai_decisions
Revises: 0021_endpoint_method_len
Create Date: 2026-06-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0022_ai_decisions"
down_revision = "0021_endpoint_method_len"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "ai_decisions" in tables:
        return
    op.create_table(
        "ai_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("ai_call_id", sa.String(length=160), nullable=False),
        sa.Column("stage", sa.String(length=80), nullable=False),
        sa.Column("phase", sa.String(length=120)),
        sa.Column("agent", sa.String(length=120)),
        sa.Column("tool", sa.String(length=120)),
        sa.Column("model", sa.String(length=160)),
        sa.Column("prompt_hash", sa.String(length=128)),
        sa.Column("response_hash", sa.String(length=128)),
        sa.Column("evidence_path", sa.Text()),
        sa.Column("parsed_response_json", sa.JSON()),
        sa.Column("decision", sa.Text()),
        sa.Column("confidence", sa.String(length=40)),
        sa.Column("accepted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rejected_reasons", sa.JSON()),
        sa.Column("used_for_execution", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("used_as_advisory", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "ai_decisions" in tables:
        op.drop_table("ai_decisions")
