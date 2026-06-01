"""initial SAIF foundation schema

Revision ID: 0001_initial_foundation
Revises:
Create Date: 2026-05-30
"""

from alembic import op

from saif.db.base import Base
from saif.db import models  # noqa: F401

revision = "0001_initial_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
