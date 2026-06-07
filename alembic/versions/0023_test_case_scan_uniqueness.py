"""scope test case uniqueness to scan

Revision ID: 0023_test_case_scan_uniqueness
Revises: 0022_ai_decisions
Create Date: 2026-06-07
"""

from alembic import op
import sqlalchemy as sa


revision = "0023_test_case_scan_uniqueness"
down_revision = "0022_ai_decisions"
branch_labels = None
depends_on = None


def _constraint_names(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {item.get("name") for item in inspector.get_unique_constraints(table_name)}


def upgrade() -> None:
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "test_cases" not in tables:
        return
    constraints = _constraint_names("test_cases")
    with op.batch_alter_table("test_cases") as batch:
        if "uq_test_case_profile" in constraints:
            batch.drop_constraint("uq_test_case_profile", type_="unique")
        if "uq_test_case_scan_case_profile" not in constraints:
            batch.create_unique_constraint("uq_test_case_scan_case_profile", ["scan_id", "case_id", "profile"])


def downgrade() -> None:
    tables = sa.inspect(op.get_bind()).get_table_names()
    if "test_cases" not in tables:
        return
    constraints = _constraint_names("test_cases")
    with op.batch_alter_table("test_cases") as batch:
        if "uq_test_case_scan_case_profile" in constraints:
            batch.drop_constraint("uq_test_case_scan_case_profile", type_="unique")
        if "uq_test_case_profile" not in constraints:
            batch.create_unique_constraint("uq_test_case_profile", ["case_id", "profile"])
