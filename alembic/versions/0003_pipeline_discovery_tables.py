"""add pipeline discovery tables

Revision ID: 0003_pipeline_discovery_tables
Revises: 0002_authorized_testing_mode
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_pipeline_discovery_tables"
down_revision = "0002_authorized_testing_mode"
branch_labels = None
depends_on = None


def _create_if_missing(table_name: str, *columns, **kwargs) -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if table_name not in inspector.get_table_names():
        op.create_table(table_name, *columns, **kwargs)


def upgrade() -> None:
    def scan_fk() -> sa.ForeignKey:
        return sa.ForeignKey("scans.id", ondelete="CASCADE")

    def timestamps() -> list[sa.Column]:
        return [
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        ]

    _create_if_missing(
        "discovered_assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("asset_type", sa.String(length=80), nullable=False),
        sa.Column("source", sa.String(length=120)),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=20)),
        sa.Column("endpoint_type", sa.String(length=80), nullable=False, server_default="web"),
        sa.Column("source", sa.String(length=120)),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_parameters",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("location", sa.String(length=80), nullable=False),
        sa.Column("endpoint", sa.Text()),
        sa.Column("source", sa.String(length=120)),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_auth_flows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("flow_type", sa.String(length=120), nullable=False),
        sa.Column("url", sa.Text()),
        sa.Column("evidence", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("token_type", sa.String(length=80), nullable=False),
        sa.Column("location", sa.String(length=120), nullable=False),
        sa.Column("sample", sa.Text()),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_roles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("role_name", sa.String(length=120), nullable=False),
        sa.Column("source", sa.String(length=120)),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "discovered_objects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("object_type", sa.String(length=120), nullable=False),
        sa.Column("object_ref", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=120)),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "authorization_matrix",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("subject", sa.String(length=120), nullable=False),
        sa.Column("role", sa.String(length=120)),
        sa.Column("endpoint", sa.Text()),
        sa.Column("object_ref", sa.Text()),
        sa.Column("expected_access", sa.String(length=80)),
        sa.Column("observed_access", sa.String(length=80)),
        sa.Column("status", sa.String(length=80), nullable=False),
        sa.Column("metadata", sa.JSON()),
        *timestamps(),
    )
    _create_if_missing(
        "pipeline_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), scan_fk(), nullable=False),
        sa.Column("artifact_type", sa.String(length=120), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        *timestamps(),
    )


def downgrade() -> None:
    for table in [
        "pipeline_artifacts",
        "authorization_matrix",
        "discovered_objects",
        "discovered_roles",
        "discovered_tokens",
        "discovered_auth_flows",
        "discovered_parameters",
        "discovered_endpoints",
        "discovered_assets",
    ]:
        op.drop_table(table)
