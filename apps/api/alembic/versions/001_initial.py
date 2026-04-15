"""Initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-04-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "tenants",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(100), unique=True, nullable=False),
        sa.Column("plan", sa.Enum("starter", "pro", "enterprise", name="plantype"), default="starter"),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("stripe_customer_id", sa.String(255), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(255), nullable=True),
        sa.Column("max_devices", sa.Integer, default=10),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"])

    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role", sa.Enum("owner", "admin", "analyst", "viewer", name="userrole"), default="analyst"),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("mfa_enabled", sa.Boolean, default=False),
        sa.Column("mfa_secret", sa.String(64), nullable=True),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_unique_constraint("uq_users_email_tenant", "users", ["email", "tenant_id"])

    op.create_table(
        "devices",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os", sa.Enum("windows", "linux", "macos", name="ostype"), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("agent_token_hash", sa.String(128), unique=True, nullable=False),
        sa.Column("agent_version", sa.String(50), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Enum("online", "offline", "warning", "critical", name="devicestatus"), default="offline"),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("metadata", JSONB, default={}),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_devices_tenant_id", "devices", ["tenant_id"])

    op.create_table(
        "events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("severity", sa.Enum("info", "low", "medium", "high", "critical", name="severitylevel"), default="info"),
        sa.Column("raw_data", JSONB, default={}),
        sa.Column("processed_data", JSONB, default={}),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("is_processed", sa.Boolean, default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_events_tenant_created", "events", ["tenant_id", "created_at"])
    op.create_index("ix_events_tenant_severity", "events", ["tenant_id", "severity"])
    op.create_index("ix_events_device_created", "events", ["device_id", "created_at"])

    op.create_table(
        "alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("event_id", UUID(as_uuid=True), sa.ForeignKey("events.id"), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, default="medium"),
        sa.Column("status", sa.Enum("open", "investigating", "resolved", "false_positive", name="alertstatus"), default="open"),
        sa.Column("assigned_to", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("llm_analysis", JSONB, nullable=True),
        sa.Column("mitre_tactic", sa.String(100), nullable=True),
        sa.Column("mitre_technique", sa.String(20), nullable=True),
        sa.Column("requires_approval", sa.Boolean, default=True),
        sa.Column("auto_action_taken", sa.Boolean, default=False),
        sa.Column("pending_action", JSONB, nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("alert_id", UUID(as_uuid=True), sa.ForeignKey("alerts.id"), nullable=True),
        sa.Column("evidence_type", sa.Enum("file","memory","log","network_capture","registry","process_dump", name="evidencetype")),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("file_size", sa.BigInteger, nullable=True),
        sa.Column("sha256_hash", sa.String(64), nullable=False),
        sa.Column("sha512_hash", sa.String(128), nullable=False),
        sa.Column("acquisition_method", sa.String(255), nullable=False),
        sa.Column("storage_path", sa.Text, nullable=False),
        sa.Column("is_immutable", sa.Boolean, default=True),
        sa.Column("metadata", JSONB, default={}),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("acquired_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("acquired_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "custody_chain",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence.id"), nullable=False),
        sa.Column("action", sa.Enum("acquired","accessed","transferred","archived","exported","verified", name="custodyaction")),
        sa.Column("performed_by", UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("performed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("metadata", JSONB, default={}),
    )
    op.create_index("ix_custody_evidence_id", "custody_chain", ["evidence_id"])

    op.create_table(
        "subscriptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("stripe_subscription_id", sa.String(255), unique=True, nullable=False),
        sa.Column("stripe_customer_id", sa.String(255), nullable=False),
        sa.Column("plan", sa.String(50), nullable=False, default="starter"),
        sa.Column("price_per_device", sa.Numeric(10, 2), nullable=False, default=9.0),
        sa.Column("active_devices", sa.Integer, default=0),
        sa.Column("status", sa.Enum("active","past_due","canceled","trialing","incomplete", name="subscriptionstatus"), default="trialing"),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Row Level Security for tenant isolation (PostgreSQL)
    op.execute("ALTER TABLE events ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;")


def downgrade():
    op.drop_table("subscriptions")
    op.drop_table("custody_chain")
    op.drop_table("evidence")
    op.drop_table("alerts")
    op.drop_table("events")
    op.drop_table("devices")
    op.drop_table("users")
    op.drop_table("tenants")
