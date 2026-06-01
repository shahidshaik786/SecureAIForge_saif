"""add case management tables

Revision ID: 0011_case_mgmt
Revises: 0010_auth_tokens
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0011_case_mgmt"
down_revision = "0010_auth_tokens"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table_name not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table_name)}


def _add(table_name: str, name: str, column_type) -> None:
    if name not in _columns(table_name):
        op.add_column(table_name, sa.Column(name, column_type, nullable=True))


def upgrade() -> None:
    if "scan_phases" not in _tables():
        op.create_table(
            "scan_phases",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("phase_name", sa.String(length=120), nullable=False),
            sa.Column("status", sa.String(length=40), nullable=False, server_default="planned"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("agent_name", sa.String(length=120), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("summary_json", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.UniqueConstraint("scan_id", "phase_name", name="uq_scan_phase_name"),
        )

    finding_columns = {
        "finding_uid": sa.String(length=80),
        "http_method": sa.String(length=20),
        "payload_source": sa.Text(),
        "payload_type": sa.String(length=120),
        "vulnerability_type": sa.String(length=120),
        "agent_name": sa.String(length=120),
        "test_case_id": sa.String(length=160),
        "cwe": sa.String(length=80),
        "owasp_category": sa.String(length=160),
        "business_impact": sa.Text(),
        "technical_impact": sa.Text(),
        "secure_code_guidance": sa.Text(),
        "references_json": sa.JSON(),
        "baseline_evidence_path": sa.Text(),
        "attack_evidence_path": sa.Text(),
        "ai_reasoning_summary": sa.Text(),
        "retest_status": sa.String(length=80),
    }
    for name, column_type in finding_columns.items():
        _add("findings", name, column_type)
    if "uq_findings_finding_uid" not in {item["name"] for item in sa.inspect(op.get_bind()).get_unique_constraints("findings")}:
        try:
            op.create_unique_constraint("uq_findings_finding_uid", "findings", ["finding_uid"])
        except Exception:
            pass

    ai_columns = {
        "agent_name": sa.String(length=120),
        "status": sa.String(length=80),
        "prompt_summary": sa.Text(),
        "prompt_hash": sa.String(length=128),
        "parsed_response_json": sa.JSON(),
    }
    for name, column_type in ai_columns.items():
        _add("ai_call_runs", name, column_type)

    if "payload_attempts" not in _tables():
        op.create_table(
            "payload_attempts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
            sa.Column("test_case_id", sa.String(length=160), nullable=True),
            sa.Column("agent_name", sa.String(length=120), nullable=True),
            sa.Column("vulnerability_type", sa.String(length=120), nullable=False),
            sa.Column("endpoint", sa.Text(), nullable=False),
            sa.Column("method", sa.String(length=20), nullable=True),
            sa.Column("parameter_location", sa.String(length=80), nullable=True),
            sa.Column("parameter_name", sa.String(length=255), nullable=True),
            sa.Column("payload", sa.Text(), nullable=True),
            sa.Column("payload_masked", sa.Text(), nullable=True),
            sa.Column("payload_source", sa.Text(), nullable=True),
            sa.Column("baseline_status", sa.Integer(), nullable=True),
            sa.Column("baseline_body_hash", sa.String(length=80), nullable=True),
            sa.Column("attack_status", sa.Integer(), nullable=True),
            sa.Column("attack_body_hash", sa.String(length=80), nullable=True),
            sa.Column("body_length_delta", sa.Integer(), nullable=True),
            sa.Column("reflection_detected", sa.Boolean(), nullable=True),
            sa.Column("error_marker_detected", sa.Boolean(), nullable=True),
            sa.Column("protected_data_detected", sa.Boolean(), nullable=True),
            sa.Column("ai_decision_json", sa.JSON(), nullable=True),
            sa.Column("status", sa.String(length=80), nullable=False),
            sa.Column("evidence_path", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )


def downgrade() -> None:
    if "payload_attempts" in _tables():
        op.drop_table("payload_attempts")
    for column in ["parsed_response_json", "prompt_hash", "prompt_summary", "status", "agent_name"]:
        if column in _columns("ai_call_runs"):
            op.drop_column("ai_call_runs", column)
    for column in [
        "retest_status",
        "ai_reasoning_summary",
        "attack_evidence_path",
        "baseline_evidence_path",
        "references_json",
        "secure_code_guidance",
        "technical_impact",
        "business_impact",
        "owasp_category",
        "cwe",
        "test_case_id",
        "agent_name",
        "vulnerability_type",
        "payload_type",
        "payload_source",
        "http_method",
        "finding_uid",
    ]:
        if column in _columns("findings"):
            op.drop_column("findings", column)
    if "scan_phases" in _tables():
        op.drop_table("scan_phases")
