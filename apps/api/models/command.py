import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum as SAEnum, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from apps.api.database import Base
import enum


class CommandStatus(str, enum.Enum):
    pending = "pending"        # created, not yet picked up by the collector
    dispatched = "dispatched"  # delivered to the collector
    acknowledged = "acknowledged"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class DeviceCommand(Base):
    """A remediation/response action dispatched to a collector for execution.

    Commands are queued in Redis (per-device list) for low-latency delivery and
    persisted here as the durable, auditable record. The collector polls
    pending commands, executes them, and reports the result back.
    """

    __tablename__ = "device_commands"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[CommandStatus] = mapped_column(
        SAEnum(CommandStatus), default=CommandStatus.pending, nullable=False, index=True
    )
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    auto_triggered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc)
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant")  # noqa: F821
    device: Mapped["Device"] = relationship("Device")  # noqa: F821
