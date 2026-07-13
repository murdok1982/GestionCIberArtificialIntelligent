import uuid
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional

from apps.api.database import get_db
from apps.api.core.rbac import require_permission
from apps.api.core.request import client_ip
from apps.api.models.alert import Alert, AlertStatus
from apps.api.models.user import User
from apps.api.services.command_service import CommandService
from apps.api.services.audit_service import AuditService
from apps.api.models.audit import AuditCategory

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    notes: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None


class ActionApproval(BaseModel):
    approved: bool
    justification: str
    action_type: str
    params: dict = {}


@router.get("")
async def list_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("alerts:read")),
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).where(Alert.tenant_id == current_user.tenant_id)

    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)

    query = query.order_by(desc(Alert.created_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    alerts = result.scalars().all()
    return [_format_alert(a) for a in alerts]


@router.get("/{alert_id}")
async def get_alert(
    alert_id: uuid.UUID,
    current_user: User = Depends(require_permission("alerts:read")),
    db: AsyncSession = Depends(get_db),
):
    alert = await _get_alert_or_404(alert_id, current_user.tenant_id, db)
    return _format_alert(alert, include_llm=True)


@router.put("/{alert_id}/status")
async def update_alert_status(
    alert_id: uuid.UUID,
    data: AlertStatusUpdate,
    current_user: User = Depends(require_permission("alerts:update")),
    db: AsyncSession = Depends(get_db),
):
    alert = await _get_alert_or_404(alert_id, current_user.tenant_id, db)
    alert.status = data.status
    if data.status == AlertStatus.resolved:
        alert.resolved_at = datetime.now(timezone.utc)
    if data.assigned_to:
        alert.assigned_to = data.assigned_to
    alert.updated_at = datetime.now(timezone.utc)
    await db.flush()
    return _format_alert(alert)


@router.post("/{alert_id}/approve-action")
async def approve_remote_action(
    alert_id: uuid.UUID,
    approval: ActionApproval,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("actions:approve")),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    """
    Approve or reject a pending remote action on an endpoint.
    Requires explicit justification. Approved actions are dispatched as commands
    to the endpoint's collector and audit-logged.
    """
    alert = await _get_alert_or_404(alert_id, current_user.tenant_id, db)

    if not alert.requires_approval:
        raise HTTPException(status_code=400, detail="This alert does not require action approval")

    logger = logging.getLogger(__name__)

    if approval.approved:
        command = await CommandService().enqueue(
            db,
            tenant_id=current_user.tenant_id,
            device_id=alert.device_id,
            action_type=approval.action_type,
            params=approval.params,
            requested_by=current_user.id,
            justification=approval.justification,
            auto_triggered=False,
        )
        logger.warning(
            f"ACTION APPROVED: alert={alert_id} action={approval.action_type} "
            f"command={command.id} by={current_user.id}"
        )
        alert.auto_action_taken = True
        alert.pending_action = None
        alert.status = AlertStatus.investigating
        await AuditService().record(
            db, category=AuditCategory.command, action="action_approved",
            user_id=current_user.id, tenant_id=current_user.tenant_id,
            detail={
                "alert_id": str(alert.id),
                "command_id": str(command.id),
                "action_type": approval.action_type,
                "justification": approval.justification,
            },
            ip_address=client_ip(request) if request else None,
        )
        return {"status": "approved", "action": approval.action_type, "command_id": str(command.id)}
    else:
        logger.info(f"ACTION REJECTED: alert={alert_id} by={current_user.id}")
        alert.pending_action = None
        await AuditService().record(
            db, category=AuditCategory.command, action="action_rejected",
            user_id=current_user.id, tenant_id=current_user.tenant_id,
            detail={"alert_id": str(alert.id), "action_type": approval.action_type},
            ip_address=client_ip(request) if request else None,
        )
        return {"status": "rejected"}


@router.post("/{alert_id}/analyze")
async def trigger_llm_analysis(
    alert_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("alerts:update")),
    db: AsyncSession = Depends(get_db),
):
    """Trigger fresh Gemma LLM analysis for an alert."""
    await _get_alert_or_404(alert_id, current_user.tenant_id, db)
    background_tasks.add_task(_run_llm_analysis, str(alert_id))
    return {"status": "analysis_queued", "alert_id": str(alert_id)}


async def _get_alert_or_404(alert_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> Alert:
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _format_alert(alert: Alert, include_llm: bool = False) -> dict:
    data = {
        "id": str(alert.id),
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "device_id": str(alert.device_id),
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "requires_approval": alert.requires_approval,
        "auto_action_taken": alert.auto_action_taken,
        "pending_action": alert.pending_action,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "created_at": alert.created_at.isoformat(),
        "updated_at": alert.updated_at.isoformat(),
    }
    if include_llm:
        data["llm_analysis"] = alert.llm_analysis
    return data


async def _execute_approved_action(device_id: str, action_type: str, params: dict, approved_by: str):
    import logging
    logging.getLogger(__name__).warning(
        f"Executing approved action: {action_type} on {device_id} by {approved_by}"
    )


async def _run_llm_analysis(alert_id: str):
    import logging
    logging.getLogger(__name__).info(f"Running LLM analysis for alert {alert_id}")
