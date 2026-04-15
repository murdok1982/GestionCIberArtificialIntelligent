import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional

from apps.api.database import get_db
from apps.api.middleware.auth import get_current_user
from apps.api.core.rbac import require_permission
from apps.api.models.alert import Alert, AlertStatus
from apps.api.models.user import User

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
    limit: int = 50,
    offset: int = 0,
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
):
    """
    Approve or reject a pending remote action on an endpoint.
    Requires explicit justification. All approvals are audit-logged.
    """
    alert = await _get_alert_or_404(alert_id, current_user.tenant_id, db)

    if not alert.requires_approval or not alert.pending_action:
        raise HTTPException(status_code=400, detail="No pending action for this alert")

    import logging
    logger = logging.getLogger(__name__)

    if approval.approved:
        logger.warning(
            f"ACTION APPROVED: alert={alert_id} action={approval.action_type} "
            f"by={current_user.id} justification={approval.justification}"
        )
        alert.auto_action_taken = True
        alert.pending_action = None
        alert.status = AlertStatus.investigating
        background_tasks.add_task(
            _execute_approved_action,
            str(alert.device_id),
            approval.action_type,
            approval.params,
            str(current_user.id),
        )
        return {"status": "approved", "action": approval.action_type}
    else:
        logger.info(f"ACTION REJECTED: alert={alert_id} by={current_user.id}")
        alert.pending_action = None
        return {"status": "rejected"}


@router.post("/{alert_id}/analyze")
async def trigger_llm_analysis(
    alert_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission("alerts:update")),
    db: AsyncSession = Depends(get_db),
):
    """Trigger fresh Gemma LLM analysis for an alert."""
    alert = await _get_alert_or_404(alert_id, current_user.tenant_id, db)
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
