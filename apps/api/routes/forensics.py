import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional

from apps.api.database import get_db
from apps.api.middleware.auth import get_current_user
from apps.api.core.rbac import require_permission
from apps.api.models.evidence import Evidence, EvidenceType
from apps.api.models.custody import CustodyAction
from apps.api.models.user import User
from apps.api.agents.forensic_agent import ForensicAgent
from apps.api.agents.custody_agent import CustodyAgent

router = APIRouter(prefix="/forensics", tags=["Forensics"])
forensic_agent = ForensicAgent()
custody_agent = CustodyAgent()


class AcquireEvidenceRequest(BaseModel):
    device_id: uuid.UUID
    alert_id: Optional[uuid.UUID] = None
    evidence_type: EvidenceType
    filename: str
    acquisition_method: str
    notes: Optional[str] = None


@router.get("/evidence")
async def list_evidence(
    device_id: Optional[uuid.UUID] = None,
    alert_id: Optional[uuid.UUID] = None,
    current_user: User = Depends(require_permission("forensics:read")),
    db: AsyncSession = Depends(get_db),
):
    query = select(Evidence).where(Evidence.tenant_id == current_user.tenant_id)
    if device_id:
        query = query.where(Evidence.device_id == device_id)
    if alert_id:
        query = query.where(Evidence.alert_id == alert_id)
    query = query.order_by(Evidence.acquired_at.desc())

    result = await db.execute(query)
    evidence_list = result.scalars().all()
    return [_format_evidence(e) for e in evidence_list]


_MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB (ALTA-05)


@router.post("/evidence", status_code=201)
async def upload_evidence(
    file: UploadFile = File(...),
    device_id: uuid.UUID = None,
    alert_id: Optional[uuid.UUID] = None,
    evidence_type: EvidenceType = EvidenceType.file,
    acquisition_method: str = "manual_upload",
    notes: Optional[str] = None,
    current_user: User = Depends(require_permission("forensics:create")),
    db: AsyncSession = Depends(get_db),
):
    """Upload and register evidence with automatic hashing and S3 storage."""
    # ALTA-05: Enforce size limit by streaming rather than buffering the entire file first
    chunks: list[bytes] = []
    total = 0
    async for chunk in file:
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum allowed size of {_MAX_UPLOAD_BYTES // 1024 // 1024} MB",
            )
        chunks.append(chunk)
    file_data = b"".join(chunks)
    evidence_id = uuid.uuid4()

    storage_path, sha256, sha512 = await forensic_agent.store_evidence(
        tenant_id=current_user.tenant_id,
        device_id=device_id,
        evidence_id=evidence_id,
        filename=file.filename,
        file_data=file_data,
        evidence_type=evidence_type.value,
    )

    evidence = Evidence(
        id=evidence_id,
        tenant_id=current_user.tenant_id,
        device_id=device_id,
        alert_id=alert_id,
        evidence_type=evidence_type,
        filename=file.filename,
        file_size=len(file_data),
        sha256_hash=sha256,
        sha512_hash=sha512,
        acquisition_method=acquisition_method,
        storage_path=storage_path,
        is_immutable=True,
        notes=notes,
        acquired_by=current_user.id,
        acquired_at=datetime.now(timezone.utc),
        metadata_={"original_name": file.filename, "content_type": file.content_type},
    )
    db.add(evidence)
    await db.flush()

    # Record initial custody chain entry
    await custody_agent.record_action(
        db=db,
        evidence_id=evidence.id,
        action=CustodyAction.acquired,
        user_id=current_user.id,
        notes=f"Evidence acquired via {acquisition_method}",
        metadata={"filename": file.filename, "sha256": sha256},
    )

    return _format_evidence(evidence)


@router.get("/evidence/{evidence_id}")
async def get_evidence(
    evidence_id: uuid.UUID,
    current_user: User = Depends(require_permission("forensics:read")),
    db: AsyncSession = Depends(get_db),
):
    evidence = await _get_evidence_or_404(evidence_id, current_user.tenant_id, db)

    # Record access in custody chain
    await custody_agent.record_action(
        db=db,
        evidence_id=evidence.id,
        action=CustodyAction.accessed,
        user_id=current_user.id,
        notes="Evidence metadata viewed",
    )

    return _format_evidence(evidence, include_hashes=True)


@router.get("/evidence/{evidence_id}/custody-chain")
async def get_custody_chain(
    evidence_id: uuid.UUID,
    current_user: User = Depends(require_permission("forensics:read")),
    db: AsyncSession = Depends(get_db),
):
    evidence = await _get_evidence_or_404(evidence_id, current_user.tenant_id, db)
    chain = await custody_agent.get_chain(evidence.id, db)
    verification = await custody_agent.verify_chain_integrity(evidence.id, db)

    return {
        "evidence_id": str(evidence_id),
        "integrity_verified": verification["all_valid"],
        "total_records": len(chain),
        "chain": [_format_custody(r) for r in chain],
        "verification_details": verification,
    }


@router.get("/evidence/{evidence_id}/download")
async def download_evidence(
    evidence_id: uuid.UUID,
    current_user: User = Depends(require_permission("forensics:read")),
    db: AsyncSession = Depends(get_db),
):
    """Generate pre-signed download URL. Access is logged in custody chain."""
    evidence = await _get_evidence_or_404(evidence_id, current_user.tenant_id, db)

    url = await forensic_agent.generate_download_url(evidence.storage_path)

    # Record download in custody chain
    await custody_agent.record_action(
        db=db,
        evidence_id=evidence.id,
        action=CustodyAction.accessed,
        user_id=current_user.id,
        notes="Evidence download link generated",
        metadata={"expires_in_seconds": 3600},
    )

    return {
        "download_url": url,
        "expires_in": 3600,
        "sha256": evidence.sha256_hash,
        "filename": evidence.filename,
        "warning": "This download has been logged in the chain of custody.",
    }


@router.post("/evidence/{evidence_id}/verify")
async def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    current_user: User = Depends(require_permission("forensics:read")),
    db: AsyncSession = Depends(get_db),
):
    """Re-hash stored evidence to verify it hasn't been tampered with."""
    evidence = await _get_evidence_or_404(evidence_id, current_user.tenant_id, db)
    is_intact = await forensic_agent.verify_evidence_integrity(evidence.storage_path, evidence.sha256_hash)

    await custody_agent.record_action(
        db=db,
        evidence_id=evidence.id,
        action=CustodyAction.verified,
        user_id=current_user.id,
        notes=f"Integrity verification: {'PASSED' if is_intact else 'FAILED'}",
    )

    return {
        "evidence_id": str(evidence_id),
        "sha256_expected": evidence.sha256_hash,
        "integrity_intact": is_intact,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


async def _get_evidence_or_404(evidence_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> Evidence:
    result = await db.execute(
        select(Evidence).where(Evidence.id == evidence_id, Evidence.tenant_id == tenant_id)
    )
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


def _format_evidence(evidence: Evidence, include_hashes: bool = False) -> dict:
    data = {
        "id": str(evidence.id),
        "device_id": str(evidence.device_id),
        "alert_id": str(evidence.alert_id) if evidence.alert_id else None,
        "evidence_type": evidence.evidence_type,
        "filename": evidence.filename,
        "file_size": evidence.file_size,
        "sha256_hash": evidence.sha256_hash,
        "acquisition_method": evidence.acquisition_method,
        "is_immutable": evidence.is_immutable,
        "notes": evidence.notes,
        "acquired_by": str(evidence.acquired_by),
        "acquired_at": evidence.acquired_at.isoformat(),
    }
    if include_hashes:
        data["sha512_hash"] = evidence.sha512_hash
    return data


def _format_custody(record) -> dict:
    return {
        "id": str(record.id),
        "action": record.action,
        "performed_by": str(record.performed_by),
        "performed_at": record.performed_at.isoformat(),
        "ip_address": record.ip_address,
        "signature": record.signature,
        "notes": record.notes,
    }
