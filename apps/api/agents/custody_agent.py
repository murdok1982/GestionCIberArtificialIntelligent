"""
CUSTODY AGENT
Manages append-only chain of custody for digital evidence.
Every access, transfer, or action is permanently recorded and cryptographically signed.
"""
import uuid
import json
import logging
from datetime import datetime, timezone
from apps.api.core.security import sign_custody_record, verify_custody_signature
from apps.api.models.custody import CustodyChain, CustodyAction

logger = logging.getLogger(__name__)


class CustodyAgent:

    async def record_action(
        self,
        db,
        evidence_id: uuid.UUID,
        action: CustodyAction,
        user_id: uuid.UUID,
        ip_address: str | None = None,
        notes: str | None = None,
        metadata: dict | None = None,
    ) -> CustodyChain:
        """
        Record an immutable custody action.
        NEVER updates or deletes custody records.
        """
        performed_at = datetime.now(timezone.utc)

        # Build canonical record string for signing
        record_data = json.dumps({
            "evidence_id": str(evidence_id),
            "action": action,
            "performed_by": str(user_id),
            "performed_at": performed_at.isoformat(),
            "ip_address": ip_address or "",
        }, sort_keys=True)

        signature = sign_custody_record(record_data)

        record = CustodyChain(
            id=uuid.uuid4(),
            evidence_id=evidence_id,
            action=action,
            performed_by=user_id,
            performed_at=performed_at,
            ip_address=ip_address,
            signature=signature,
            notes=notes,
            metadata_=metadata or {},
        )

        db.add(record)
        await db.flush()
        logger.info(f"Custody record: evidence={evidence_id} action={action} by={user_id}")
        return record

    async def verify_chain_integrity(self, evidence_id: uuid.UUID, db) -> dict:
        """Verify every record in the custody chain has a valid signature."""
        from sqlalchemy import select

        result = await db.execute(
            select(CustodyChain)
            .where(CustodyChain.evidence_id == evidence_id)
            .order_by(CustodyChain.performed_at)
        )
        records = result.scalars().all()

        verification_results = []
        all_valid = True

        for record in records:
            record_data = json.dumps({
                "evidence_id": str(record.evidence_id),
                "action": record.action,
                "performed_by": str(record.performed_by),
                "performed_at": record.performed_at.isoformat(),
                "ip_address": record.ip_address or "",
            }, sort_keys=True)

            is_valid = verify_custody_signature(record_data, record.signature)
            if not is_valid:
                all_valid = False
                logger.error(f"Custody chain integrity violation: record {record.id}")

            verification_results.append({
                "record_id": str(record.id),
                "action": record.action,
                "performed_at": record.performed_at.isoformat(),
                "is_valid": is_valid,
            })

        return {
            "evidence_id": str(evidence_id),
            "total_records": len(records),
            "all_valid": all_valid,
            "records": verification_results,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    async def get_chain(self, evidence_id: uuid.UUID, db) -> list[CustodyChain]:
        from sqlalchemy import select

        result = await db.execute(
            select(CustodyChain)
            .where(CustodyChain.evidence_id == evidence_id)
            .order_by(CustodyChain.performed_at)
        )
        return result.scalars().all()
