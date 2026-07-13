"""Append-only security audit logging service."""
import uuid
import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.audit import AuditLog, AuditCategory, AuditSeverity

logger = logging.getLogger(__name__)


class AuditService:
    async def record(
        self,
        db: AsyncSession,
        *,
        category: AuditCategory,
        action: str,
        severity: AuditSeverity = AuditSeverity.info,
        tenant_id: Optional[uuid.UUID] = None,
        user_id: Optional[uuid.UUID] = None,
        detail: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLog:
        entry = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            category=category,
            action=action,
            severity=severity,
            detail=detail or {},
            ip_address=ip_address,
        )
        db.add(entry)
        await db.flush()
        logger.info("AUDIT [%s] %s user=%s tenant=%s", category.value, action, user_id, tenant_id)
        return entry
