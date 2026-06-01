"""add orchestration controls and tool registry

Revision ID: 0005_orchestration
Revises: 0004_pipeline_timestamps
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_orchestration"
down_revision = "0004_pipeline_timestamps"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _has_table(table_name: str) -> bool:
    return table_name in _inspector().get_table_names()


def _columns(table_name: str) -> set[str]:
    if not _has_table(table_name):
        return set()
    return {column["name"] for column in _inspector().get_columns(table_name)}


def _add_column_if_missing(table_name: str, column: sa.Column) -> None:
    if column.name not in _columns(table_name):
        op.add_column(table_name, column)


def _drop_column_if_present(table_name: str, column_name: str) -> None:
    if column_name in _columns(table_name):
        op.drop_column(table_name, column_name)


def upgrade() -> None:
    if _has_table("test_cases"):
        _add_column_if_missing("test_cases", sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("test_id", sa.String(length=160), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("agent_name", sa.String(length=120), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("category", sa.String(length=120), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("target", sa.Text(), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("applicability", sa.String(length=80), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("prerequisites", sa.JSON(), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("selected_tool", sa.String(length=120), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("alternate_tools", sa.JSON(), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("status", sa.String(length=40), nullable=True))
        _add_column_if_missing("test_cases", sa.Column("priority", sa.Integer(), nullable=True))
        op.execute(sa.text("UPDATE test_cases SET status = 'planned' WHERE status IS NULL"))
        op.execute(sa.text("UPDATE test_cases SET priority = 50 WHERE priority IS NULL"))
        op.alter_column("test_cases", "status", nullable=False, existing_type=sa.String(length=40))
        op.alter_column("test_cases", "priority", nullable=False, existing_type=sa.Integer())

    if _has_table("test_runs"):
        _add_column_if_missing("test_runs", sa.Column("agent_name", sa.String(length=120), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("tool_name", sa.String(length=120), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("command", sa.Text(), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("started_at", sa.DateTime(timezone=True), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("duration_ms", sa.Integer(), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("evidence_id", sa.Integer(), sa.ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("error_message", sa.Text(), nullable=True))
        _add_column_if_missing("test_runs", sa.Column("retry_count", sa.Integer(), nullable=True))
        op.execute(sa.text("UPDATE test_runs SET retry_count = 0 WHERE retry_count IS NULL"))
        op.alter_column("test_runs", "retry_count", nullable=False, existing_type=sa.Integer())

    if _has_table("tool_runs"):
        _add_column_if_missing("tool_runs", sa.Column("test_case_id", sa.Integer(), sa.ForeignKey("test_cases.id", ondelete="SET NULL"), nullable=True))
        _add_column_if_missing("tool_runs", sa.Column("agent_name", sa.String(length=120), nullable=True))
        _add_column_if_missing("tool_runs", sa.Column("duration_ms", sa.Integer(), nullable=True))
        _add_column_if_missing("tool_runs", sa.Column("evidence_path", sa.Text(), nullable=True))

    if not _has_table("tool_registry"):
        op.create_table(
            "tool_registry",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("tool_name", sa.String(length=120), nullable=False, unique=True),
            sa.Column("install_method", sa.String(length=120), nullable=True),
            sa.Column("command_path", sa.Text(), nullable=True),
            sa.Column("version", sa.String(length=255), nullable=True),
            sa.Column("status", sa.String(length=40), nullable=False, server_default="unknown"),
            sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_install_attempt_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("install_attempt_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )

    if not _has_table("agent_jobs"):
        op.create_table(
            "agent_jobs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("agent_name", sa.String(length=120), nullable=False),
            sa.Column("job_type", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False, server_default="queued"),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("input", sa.JSON(), nullable=True),
            sa.Column("output", sa.JSON(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )


def downgrade() -> None:
    if _has_table("agent_jobs"):
        op.drop_table("agent_jobs")
    if _has_table("tool_registry"):
        op.drop_table("tool_registry")

    for column in ["evidence_path", "duration_ms", "agent_name", "test_case_id"]:
        _drop_column_if_present("tool_runs", column)

    for column in [
        "retry_count",
        "error_message",
        "evidence_id",
        "duration_ms",
        "completed_at",
        "started_at",
        "command",
        "tool_name",
        "agent_name",
    ]:
        _drop_column_if_present("test_runs", column)

    for column in [
        "priority",
        "status",
        "alternate_tools",
        "selected_tool",
        "prerequisites",
        "applicability",
        "target",
        "category",
        "agent_name",
        "test_id",
        "scan_id",
    ]:
        _drop_column_if_present("test_cases", column)
