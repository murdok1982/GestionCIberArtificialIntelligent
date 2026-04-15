import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal

from apps.api.database import get_db
from apps.api.middleware.auth import get_current_user, get_device_from_token
from apps.api.core.rbac import require_permission
from apps.api.core.security import generate_device_token, hash_device_token
from apps.api.models.device import Device, OSType, DeviceStatus
from apps.api.models.user import User
from apps.api.agents.orchestrator import OrchestratorAgent

router = APIRouter(prefix="/devices", tags=["Devices"])
orchestrator = OrchestratorAgent()

# ─── CRIT-03 fix: strict Pydantic schema for telemetry ────────────────────────
# Prevents an attacker with a compromised device token from crafting a payload
# that artificially triggers imminent-danger detections.

class ProcessInfo(BaseModel):
    pid: int = Field(ge=0, le=4194304)
    name: str = Field(max_length=256)
    user: str = Field(default="", max_length=256)
    cmdline: list[str] = Field(default_factory=list, max_length=64)
    cpu_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    memory_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    status: str = Field(default="", max_length=32)
    create_time: Optional[float] = None
    ppid: Optional[int] = Field(default=None, ge=0)


class ConnectionInfo(BaseModel):
    local_address: str = Field(default="", max_length=64)
    remote_address: str = Field(default="", max_length=256)
    remote_port: Optional[int] = Field(default=None, ge=0, le=65535)
    status: str = Field(default="", max_length=32)
    pid: Optional[int] = None
    proto: Literal["tcp", "udp"] = "tcp"


class ServiceInfo(BaseModel):
    name: str = Field(max_length=256)
    state: str = Field(default="", max_length=32)
    description: str = Field(default="", max_length=512)


class FileOperations(BaseModel):
    encryption_count: int = Field(default=0, ge=0, le=100000)
    rename_count: int = Field(default=0, ge=0, le=100000)
    delete_count: int = Field(default=0, ge=0, le=100000)


class TelemetryRawData(BaseModel):
    collected_at: str = Field(max_length=32)
    system_info: dict = Field(default_factory=dict)
    processes: list[ProcessInfo] = Field(default_factory=list, max_length=1000)
    connections: list[ConnectionInfo] = Field(default_factory=list, max_length=500)
    services: list[ServiceInfo] = Field(default_factory=list, max_length=200)
    log_entries: list[str] = Field(default_factory=list, max_length=500)
    windows_events: list[dict] = Field(default_factory=list, max_length=200)
    registry_events: list[str] = Field(default_factory=list, max_length=50)
    network_stats: dict = Field(default_factory=dict)
    open_files_count: int = Field(default=0, ge=0)
    file_operations: FileOperations = Field(default_factory=FileOperations)

    @field_validator("log_entries", mode="before")
    @classmethod
    def truncate_log_lines(cls, v):
        if isinstance(v, list):
            return [str(e)[:2000] for e in v]
        return v


class TelemetryPayload(BaseModel):
    event_type: str = Field(
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
    )
    raw_data: TelemetryRawData
    agent_version: Optional[str] = Field(default=None, max_length=20)
    ip_address: Optional[str] = Field(default=None, max_length=45)


class DeviceCreate(BaseModel):
    hostname: str = Field(max_length=255)
    os: OSType


class RemoteActionRequest(BaseModel):
    action_type: str = Field(max_length=64)
    params: dict
    justification: str = Field(min_length=10, max_length=1000)
    justification: str


@router.get("")
async def list_devices(
    current_user: User = Depends(require_permission("devices:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device).where(
            Device.tenant_id == current_user.tenant_id,
            Device.is_active == True,
        ).order_by(Device.created_at.desc())
    )
    devices = result.scalars().all()
    return [_format_device(d) for d in devices]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_device(
    data: DeviceCreate,
    current_user: User = Depends(require_permission("devices:create")),
    db: AsyncSession = Depends(get_db),
):
    from apps.api.agents.billing_agent import BillingAgent
    billing = BillingAgent()

    if not await billing.check_device_limit(current_user.tenant_id, db):
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail="Device limit reached. Upgrade your plan to add more devices.",
        )

    raw_token = generate_device_token()
    token_hash = hash_device_token(raw_token)

    device = Device(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        hostname=data.hostname,
        os=data.os,
        agent_token_hash=token_hash,
        status=DeviceStatus.offline,
        is_active=True,
    )
    db.add(device)
    await db.flush()

    return {
        **_format_device(device),
        "agent_token": raw_token,  # Only shown ONCE at creation
        "install_command": _get_install_command(data.os, raw_token, device.id),
    }


@router.get("/{device_id}")
async def get_device(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices:read")),
    db: AsyncSession = Depends(get_db),
):
    device = await _get_device_or_404(device_id, current_user.tenant_id, db)
    return _format_device(device)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: uuid.UUID,
    current_user: User = Depends(require_permission("devices:delete")),
    db: AsyncSession = Depends(get_db),
):
    device = await _get_device_or_404(device_id, current_user.tenant_id, db)
    device.is_active = False
    await db.flush()


@router.post("/{device_id}/telemetry", status_code=status.HTTP_202_ACCEPTED)
async def receive_telemetry(
    device_id: uuid.UUID,
    payload: TelemetryPayload,
    background_tasks: BackgroundTasks,
    device: Device = Depends(get_device_from_token),
    db: AsyncSession = Depends(get_db),
):
    """Endpoint for collectors to send telemetry data."""
    if device.id != device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")

    # Update device status
    device.last_seen = datetime.now(timezone.utc)
    device.status = DeviceStatus.online
    if payload.ip_address:
        device.ip_address = payload.ip_address
    if payload.agent_version:
        device.agent_version = payload.agent_version

    # Create event record
    from apps.api.models.event import Event
    event = Event(
        id=uuid.uuid4(),
        tenant_id=device.tenant_id,
        device_id=device.id,
        event_type=payload.event_type,
        raw_data=payload.raw_data,
        processed_data={},
    )
    db.add(event)
    await db.flush()

    # Process in background
    event_data = {
        "event_id": str(event.id),
        "device_id": str(device.id),
        "tenant_id": str(device.tenant_id),
        "event_type": payload.event_type,
        "raw_data": payload.raw_data,
    }
    background_tasks.add_task(_process_event_background, event_data)

    return {"status": "accepted", "event_id": str(event.id)}


@router.post("/{device_id}/action")
async def execute_device_action(
    device_id: uuid.UUID,
    action_request: RemoteActionRequest,
    current_user: User = Depends(require_permission("actions:approve")),
    db: AsyncSession = Depends(get_db),
):
    """Execute a remote action on an endpoint. Requires explicit justification."""
    device = await _get_device_or_404(device_id, current_user.tenant_id, db)

    import logging
    logger = logging.getLogger(__name__)
    logger.warning(
        f"REMOTE ACTION requested: action={action_request.action_type} "
        f"device={device_id} user={current_user.id} "
        f"justification={action_request.justification}"
    )

    return {
        "status": "dispatched",
        "action_type": action_request.action_type,
        "device_id": str(device_id),
        "requested_by": str(current_user.id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def _get_device_or_404(device_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> Device:
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id, Device.is_active == True)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


def _format_device(device: Device) -> dict:
    return {
        "id": str(device.id),
        "hostname": device.hostname,
        "os": device.os,
        "ip_address": device.ip_address,
        "status": device.status,
        "agent_version": device.agent_version,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "is_active": device.is_active,
        "created_at": device.created_at.isoformat(),
    }


def _get_install_command(os_type: OSType, token: str, device_id: uuid.UUID) -> str:
    if os_type == OSType.linux:
        return f"curl -sSL https://your-domain.com/install.sh | AGENT_TOKEN={token} DEVICE_ID={device_id} bash"
    elif os_type == OSType.windows:
        return f"powershell -Command \"$env:AGENT_TOKEN='{token}'; $env:DEVICE_ID='{device_id}'; iwr https://your-domain.com/install.ps1 | iex\""
    return f"AGENT_TOKEN={token} DEVICE_ID={device_id} python collector.py"


async def _process_event_background(event_data: dict):
    """Background task: run orchestrator analysis on telemetry event."""
    try:
        # In production: push to Celery task queue
        pass
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Background event processing error: {e}")
