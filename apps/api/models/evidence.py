import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum as SAEnum, BigInteger, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB
from apps.api.database import Base
import enum


class EvidenceType(str, enum.Enum):
    file = "file"
    memory = "memory"
    log = "log"
    network_capture = "network_capture"
    registry = "registry"
    process_dump = "process_dump"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False, index=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)
    evidence_type: Mapped[EvidenceType] = mapped_column(SAEnum(EvidenceType), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    acquisition_method: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    is_immutable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    acquired_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant")
    device: Mapped["Device"] = relationship("Device", back_populates="evidence")
    alert: Mapped["Alert | None"] = relationship("Alert", back_populates="evidence")
    acquired_by_user: Mapped["User"] = relationship("User", back_populates="acquired_evidence")
    custody_chain: Mapped[list["CustodyChain"]] = relationship("CustodyChain", back_populates="evidence", order_by="CustodyChain.performed_at")
