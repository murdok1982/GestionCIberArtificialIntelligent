import uuid
import json
import os
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Header, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal

from apps.api.database import get_db
from apps.api.middleware.auth import get_device_auth_context, DeviceAuthContext
from apps.api.core.rbac import require_permission
from apps.api.core.security import generate_device_token, hash_device_token, verify_telemetry_signature
from apps.api.core.redis_client import get_redis
from apps.api.core.request import client_ip
from apps.api.models.device import Device, OSType, DeviceStatus
from apps.api.models.user import User
from apps.api.models.command import CommandStatus
from apps.api.agents.orchestrator import OrchestratorAgent
from apps.api.agents.detection_agent import DetectionAgent
from apps.api.agents.threat_intel_agent import ThreatIntelAgent
from apps.api.agents.forensic_agent import ForensicAgent
from apps.api.agents.custody_agent import CustodyAgent
from apps.api.services.llm_service import GemmaAnalystService
from apps.api.services.command_service import CommandService
from apps.api.services.audit_service import AuditService
from apps.api.models.audit import AuditCategory
from apps.api.config import settings

router = APIRouter(prefix="/devices", tags=["Devices"])

# Dependency injection for OrchestratorAgent
def get_orchestrator() -> OrchestratorAgent:
    return OrchestratorAgent(
        detection_agent=DetectionAgent(),
        threat_intel_agent=ThreatIntelAgent(),
        forensic_agent=ForensicAgent(),
        custody_agent=CustodyAgent(),
        llm_service=GemmaAnalystService(),
    )
_TELEMETRY_MAX_SKEW_SECONDS = 300
_TELEMETRY_NONCE_TTL_SECONDS = 600
_ENROLLMENT_CODE_TTL_SECONDS = 3600  # 1 hour

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


class DeviceEnrollRequest(BaseModel):
    """Request to exchange enrollment code for agent token."""
    device_id: uuid.UUID
    enrollment_code: str = Field(min_length=32, max_length=64)


class RemoteActionRequest(BaseModel):
    action_type: str = Field(max_length=64)
    params: dict
    justification: str = Field(min_length=10, max_length=1000)


def _hash_enrollment_code(code: str) -> str:
    """SHA-256 hash of enrollment code for storage."""
    return hashlib.sha256(code.encode()).hexdigest()


@router.get("")
async def list_devices(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_permission("devices:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Device).where(
            Device.tenant_id == current_user.tenant_id,
            Device.is_active,
        ).order_by(Device.created_at.desc()).limit(limit).offset(offset)
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

    # Generate enrollment code (one-time use) instead of exposing token directly
    enrollment_code = secrets.token_urlsafe(32)
    enrollment_code_hash = _hash_enrollment_code(enrollment_code)

    device = Device(
        id=uuid.uuid4(),
        tenant_id=current_user.tenant_id,
        hostname=data.hostname,
        os=data.os,
        agent_token_hash="",  # Will be set when enrollment code is exchanged
        enrollment_code_hash=enrollment_code_hash,
        enrollment_code_used=False,
        status=DeviceStatus.offline,
        is_active=True,
    )
    db.add(device)
    await db.flush()

    return {
        **_format_device(device),
        "enrollment_code": enrollment_code,  # Only shown ONCE at creation
        "enrollment_url": f"{data.os.value}_enroll",
    }


@router.post("/enroll", status_code=status.HTTP_200_OK)
async def enroll_device(
    data: DeviceEnrollRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange one-time enrollment code for agent token. Can only be used once."""
    result = await db.execute(
        select(Device).where(Device.id == data.device_id, Device.is_active)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if device.enrollment_code_used or not device.enrollment_code_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enrollment code already used or expired")

    if not hmac.compare_digest(_hash_enrollment_code(data.enrollment_code), device.enrollment_code_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment code")

    # Generate the actual agent token now
    raw_token = generate_device_token()
    token_hash = hash_device_token(raw_token)

    device.agent_token_hash = token_hash
    device.enrollment_code_used = True
    device.enrollment_code_hash = None
    await db.flush()

    return {
        "agent_token": raw_token,
        "device_id": str(device.id),
        "backend_url": "https://api.your-domain.com",  # Should come from config
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
    auth_context: DeviceAuthContext = Depends(get_device_auth_context),
    telemetry_timestamp: str | None = Header(default=None, alias="X-Telemetry-Timestamp"),
    telemetry_nonce: str | None = Header(default=None, alias="X-Telemetry-Nonce"),
    telemetry_signature: str | None = Header(default=None, alias="X-Telemetry-Signature"),
    db: AsyncSession = Depends(get_db),
):
    """Endpoint for collectors to send telemetry data."""
    device = auth_context.device

    if device.id != device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")

    if not telemetry_timestamp or not telemetry_nonce or not telemetry_signature:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing telemetry signature headers")

    if not _validate_telemetry_timestamp(telemetry_timestamp):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Telemetry timestamp outside allowed window")

    payload_bytes = json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    if not verify_telemetry_signature(
        device_id=str(device.id),
        raw_token=auth_context.raw_token,
        timestamp=telemetry_timestamp,
        nonce=telemetry_nonce,
        payload_bytes=payload_bytes,
        signature=telemetry_signature,
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid telemetry signature")

    redis = await get_redis()
    nonce_key = f"telemetry_nonce:{device.id}:{telemetry_nonce}"
    nonce_reserved = await redis.set(nonce_key, "1", ex=_TELEMETRY_NONCE_TTL_SECONDS, nx=True)
    if not nonce_reserved:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected")

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
        raw_data=payload.raw_data.model_dump(mode="json"),
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
        "raw_data": payload.raw_data.model_dump(mode="json"),
    }
    background_tasks.add_task(_process_event_background, event_data)

    return {"status": "accepted", "event_id": str(event.id)}


@router.post("/{device_id}/action")
async def execute_device_action(
    device_id: uuid.UUID,
    action_request: RemoteActionRequest,
    current_user: User = Depends(require_permission("actions:approve")),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
):
    """Queue a remote action on an endpoint. Requires explicit justification.

    The command is persisted (auditable) and pushed to the device's Redis queue.
    The collector picks it up, executes it, and reports the result.
    """
    device = await _get_device_or_404(device_id, current_user.tenant_id, db)

    command = await CommandService().enqueue(
        db,
        tenant_id=current_user.tenant_id,
        device_id=device.id,
        action_type=action_request.action_type,
        params=action_request.params,
        requested_by=current_user.id,
        justification=action_request.justification,
        auto_triggered=False,
    )

    await AuditService().record(
        db, category=AuditCategory.command, action="command_dispatched",
        user_id=current_user.id, tenant_id=current_user.tenant_id,
        detail={
            "command_id": str(command.id),
            "action_type": action_request.action_type,
            "device_id": str(device.id),
            "justification": action_request.justification,
        },
        ip_address=client_ip(request) if request else None,
    )

    return {
        "status": "queued",
        "command_id": str(command.id),
        "action_type": action_request.action_type,
        "device_id": str(device.id),
        "requested_by": str(current_user.id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class CommandResultRequest(BaseModel):
    status: str
    result: str | None = None


@router.get("/{device_id}/commands")
async def poll_device_commands(
    device_id: uuid.UUID,
    auth_context: DeviceAuthContext = Depends(get_device_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Collector polling endpoint: returns pending commands to execute.

    Authorized by the device agent token (HMAC telemetry auth), not a user token.
    """
    if auth_context.device.id != device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")

    commands = await CommandService().fetch_pending(db, device_id=auth_context.device.id)
    return [
        {
            "command_id": str(c.id),
            "action_type": c.action_type,
            "params": c.params,
            "auto_triggered": c.auto_triggered,
        }
        for c in commands
    ]


@router.post("/{device_id}/commands/{command_id}/result")
async def report_command_result(
    device_id: uuid.UUID,
    command_id: uuid.UUID,
    payload: CommandResultRequest,
    auth_context: DeviceAuthContext = Depends(get_device_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Collector reports the execution result of a command."""
    if auth_context.device.id != device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device ID mismatch")

    try:
        status_enum = CommandStatus(payload.status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid command status")

    command = await CommandService().report_result(
        db, command_id=command_id, device_id=device_id, status=status_enum, result=payload.result
    )
    if command is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Command not found")

    await AuditService().record(
        db, category=AuditCategory.command, action="command_result",
        tenant_id=command.tenant_id,
        detail={
            "command_id": str(command.id),
            "action_type": command.action_type,
            "status": status_enum.value,
        },
        ip_address=auth_context.device.ip_address,
    )
    return {"status": "ok", "command_id": str(command.id)}


async def _get_device_or_404(device_id: uuid.UUID, tenant_id: uuid.UUID, db: AsyncSession) -> Device:
    result = await db.execute(
        select(Device).where(Device.id == device_id, Device.tenant_id == tenant_id, Device.is_active)
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


def _get_enroll_sha256(filename: str) -> Optional[str]:
    """Compute the SHA-256 of a local enrollment script to enable integrity verification."""
    base = getattr(settings, "ENROLL_SCRIPTS_DIR", None)
    if not base:
        return None
    path = os.path.join(base, filename)
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _get_install_command(os_type: OSType, enrollment_code: str, device_id: uuid.UUID) -> str:
    """Return a safe install command that downloads the script first (no pipe-to-shell).

    The operator is shown a checksum to verify before running, and the script is
    executed from a local file rather than piped directly into a shell.
    """
    base = settings.BACKEND_PUBLIC_URL.rstrip("/")
    code_export = f"ENROLLMENT_CODE={enrollment_code} DEVICE_ID={device_id}"
    if os_type == OSType.linux:
        linux_sha = _get_enroll_sha256("linux/enroll.sh")
        verify = f"echo '{linux_sha}  /tmp/cyberguard-enroll.sh' | sha256sum -c - && " if linux_sha else ""
        return (
            f"{code_export} curl -fsSL --proto =https {base}/enroll.sh -o /tmp/cyberguard-enroll.sh "
            f"&& {verify}bash /tmp/cyberguard-enroll.sh"
        )
    elif os_type == OSType.windows:
        win_sha = _get_enroll_sha256("windows/enroll.ps1")
        verify = f"if ((Get-FileHash /tmp/cyberguard-enroll.ps1 -Algorithm SHA256).Hash -ne '{win_sha.ToUpper()}') {{ Write-Error 'checksum mismatch'; exit 1 }} " if win_sha else ""
        return (
            f"$env:ENROLLMENT_CODE='{enrollment_code}'; $env:DEVICE_ID='{device_id}'; "
            f"Invoke-WebRequest -Uri {base}/enroll.ps1 -OutFile /tmp/cyberguard-enroll.ps1; "
            f"{verify}powershell -ExecutionPolicy Bypass -File /tmp/cyberguard-enroll.ps1"
        )
    return f"{code_export} python enroll.py"


async def _process_event_background(event_data: dict):
    """Background task: run orchestrator analysis on telemetry event."""
    try:
        from apps.api.services.event_service import EventService
        from apps.api.database import AsyncSessionLocal

        async with AsyncSessionLocal() as db:
            service = EventService(db)
            await service.process_event(event_data)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Background event processing error: {e}")


def _validate_telemetry_timestamp(timestamp_value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
    except ValueError:
        return False

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    skew = abs((datetime.now(timezone.utc) - parsed).total_seconds())
    return skew <= _TELEMETRY_MAX_SKEW_SECONDS