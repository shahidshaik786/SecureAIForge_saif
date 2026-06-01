"""add target profile inventory

Revision ID: 0012_profiles_inv
Revises: 0011_case_mgmt
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0012_profiles_inv"
down_revision = "0011_case_mgmt"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    if "application_profiles" not in _tables():
        op.create_table(
            "application_profiles",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("primary_profile", sa.String(length=120), nullable=False),
            sa.Column("secondary_profiles", sa.JSON(), nullable=True),
            sa.Column("lab_profile", sa.String(length=120), nullable=True),
            sa.Column("confidence", sa.String(length=40), nullable=True),
            sa.Column("detection_rules", sa.JSON(), nullable=True),
            sa.Column("observed", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
    if "discovered_services" not in _tables():
        op.create_table(
            "discovered_services",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("service_name", sa.String(length=160), nullable=True),
            sa.Column("host", sa.String(length=255), nullable=True),
            sa.Column("port", sa.Integer(), nullable=True),
            sa.Column("protocol", sa.String(length=40), nullable=True),
            sa.Column("product", sa.String(length=255), nullable=True),
            sa.Column("version", sa.String(length=120), nullable=True),
            sa.Column("source", sa.String(length=120), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
    if "discovered_api_specs" not in _tables():
        op.create_table(
            "discovered_api_specs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("spec_type", sa.String(length=80), nullable=False),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=80), nullable=True),
            sa.Column("title", sa.String(length=255), nullable=True),
            sa.Column("version", sa.String(length=120), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
    if "discovered_auth_mechanisms" not in _tables():
        op.create_table(
            "discovered_auth_mechanisms",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("mechanism_type", sa.String(length=120), nullable=False),
            sa.Column("endpoint", sa.Text(), nullable=True),
            sa.Column("confidence", sa.String(length=40), nullable=True),
            sa.Column("evidence", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
    if "discovered_session_mechanisms" not in _tables():
        op.create_table(
            "discovered_session_mechanisms",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("mechanism_type", sa.String(length=120), nullable=False),
            sa.Column("location", sa.String(length=120), nullable=True),
            sa.Column("token_type", sa.String(length=80), nullable=True),
            sa.Column("confidence", sa.String(length=40), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )
    if "discovered_tenants" not in _tables():
        op.create_table(
            "discovered_tenants",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
            sa.Column("tenant_ref", sa.String(length=255), nullable=False),
            sa.Column("source", sa.String(length=120), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )


def downgrade() -> None:
    for table in [
        "discovered_tenants",
        "discovered_session_mechanisms",
        "discovered_auth_mechanisms",
        "discovered_api_specs",
        "discovered_services",
        "application_profiles",
    ]:
        if table in _tables():
            op.drop_table(table)
