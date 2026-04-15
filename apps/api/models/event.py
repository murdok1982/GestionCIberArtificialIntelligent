import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum as SAEnum, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from apps.api.database import Base
import enum


class SeverityLevel(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Event(Base):
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[SeverityLevel] = mapped_column(SAEnum(SeverityLevel), default=SeverityLevel.info, nullable=False, index=True)
    raw_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    processed_data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    mitre_tactic: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    is_processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="events")
    device: Mapped["Device"] = relationship("Device", back_populates="events")
    alert: Mapped["Alert | None"] = relationship("Alert", back_populates="event")

    __table_args__ = (
        Index("ix_events_tenant_created", "tenant_id", "created_at"),
        Index("ix_events_tenant_severity", "tenant_id", "severity"),
        Index("ix_events_device_created", "device_id", "created_at"),
    )
