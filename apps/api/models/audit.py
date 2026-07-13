import uuid
from datetime import datetime, timezone
from sqlalchemy import String, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID, JSONB
from apps.api.database import Base
import enum


class AuditCategory(str, enum.Enum):
    auth = "auth"
    authz = "authz"
    device = "device"
    alert = "alert"
    forensic = "forensic"
    billing = "billing"
    command = "command"
    config = "config"


class AuditSeverity(str, enum.Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class AuditLog(Base):
    """Append-only, tamper-evident security audit trail.

    Records are never updated or deleted. Every security-relevant action
    (logins, MFA, role changes, command dispatch, approvals) is written here
    for compliance and forensic reconstruction.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True
    )
    category: Mapped[AuditCategory] = mapped_column(SAEnum(AuditCategory), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[AuditSeverity] = mapped_column(
        SAEnum(AuditSeverity), default=AuditSeverity.info, nullable=False
    )
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False, index=True
    )
