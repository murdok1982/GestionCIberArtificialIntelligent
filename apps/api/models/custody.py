import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, Enum as SAEnum, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from apps.api.database import Base
import enum


class CustodyAction(str, enum.Enum):
    acquired = "acquired"
    accessed = "accessed"
    transferred = "transferred"
    archived = "archived"
    exported = "exported"
    verified = "verified"


class CustodyChain(Base):
    """
    Append-only custody chain. NEVER update or delete records.
    Each record is signed with HMAC-SHA256 for integrity verification.
    """
    __tablename__ = "custody_chain"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("evidence.id"), nullable=False, index=True)
    action: Mapped[CustodyAction] = mapped_column(SAEnum(CustodyAction), nullable=False)
    performed_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)  # HMAC-SHA256
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)

    # Relationships
    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="custody_chain")
    performed_by_user: Mapped["User"] = relationship("User", back_populates="custody_actions")
