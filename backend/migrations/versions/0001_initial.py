"""Initial schema

Revision ID: 0001
Create Date: 2024-01-01
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Tables are created by SQLAlchemy models via init_db()
    # This migration serves as a version checkpoint
    pass


def downgrade() -> None:
    pass
