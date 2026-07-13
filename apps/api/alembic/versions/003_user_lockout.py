"""Add account lockout columns to users

Revision ID: 003_user_lockout
Revises: 002_device_commands_and_audit
Create Date: 2026-07-13
"""
from alembic import op
import sqlalchemy as sa

revision = "003_user_lockout"
down_revision = "002_device_commands_and_audit"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_count")
