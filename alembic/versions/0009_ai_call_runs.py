"""add AI call run records

Revision ID: 0009_ai_calls
Revises: 0008_adaptive_findings
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0009_ai_calls"
down_revision = "0008_adaptive_findings"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "ai_call_runs" in _tables():
        return
    op.create_table(
        "ai_call_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True),
        sa.Column("stage", sa.String(length=80), nullable=False),
        sa.Column("model", sa.String(length=160), nullable=False),
        sa.Column("prompt_tokens_estimate", sa.Integer(), nullable=True),
        sa.Column("response_status", sa.String(length=80), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("request_summary", sa.JSON(), nullable=True),
        sa.Column("response_summary", sa.Text(), nullable=True),
        sa.Column("evidence_path", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    if "ai_call_runs" in _tables():
        op.drop_table("ai_call_runs")
