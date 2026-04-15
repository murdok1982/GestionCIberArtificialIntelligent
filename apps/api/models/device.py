import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum as SAEnum, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from apps.api.database import Base
import enum


class OSType(str, enum.Enum):
    windows = "windows"
    linux = "linux"
    macos = "macos"


class DeviceStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    warning = "warning"
    critical = "critical"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os: Mapped[OSType] = mapped_column(SAEnum(OSType), nullable=False, default=OSType.linux)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    agent_token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(SAEnum(DeviceStatus), default=DeviceStatus.offline, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="devices")
    events: Mapped[list["Event"]] = relationship("Event", back_populates="device", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="device")
    evidence: Mapped[list["Evidence"]] = relationship("Evidence", back_populates="device")
