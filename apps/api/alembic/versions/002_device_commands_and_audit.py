"""Device commands and audit log

Revision ID: 002_device_commands_and_audit
Revises: 001_initial
Create Date: 2026-07-13
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "002_device_commands_and_audit"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "device_commands",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("params", JSONB, default={}, nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "dispatched", "acknowledged", "completed", "failed", "cancelled", name="commandstatus"),
            default="pending",
            nullable=False,
        ),
        sa.Column("justification", sa.Text, nullable=True),
        sa.Column("requested_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("auto_triggered", sa.Boolean, default=False, nullable=False),
        sa.Column("result", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_device_commands_tenant_id", "device_commands", ["tenant_id"])
    op.create_index("ix_device_commands_device_id", "device_commands", ["device_id"])
    op.create_index("ix_device_commands_status", "device_commands", ["status"])

    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "category",
            sa.Enum("auth", "authz", "device", "alert", "forensic", "billing", "command", "config", name="auditcategory"),
            nullable=False,
        ),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("info", "warning", "critical", name="auditseverity"),
            default="info",
            nullable=False,
        ),
        sa.Column("detail", JSONB, default={}, nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_category", "audit_logs", ["category"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade():
    op.drop_table("audit_logs")
    op.drop_table("device_commands")
