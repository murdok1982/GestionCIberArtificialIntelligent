import uuid
from dataclasses import dataclass
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from apps.api.database import get_db
from apps.api.core.security import verify_token
from apps.api.models.user import User
from apps.api.models.device import Device

security = HTTPBearer()
optional_security = HTTPBearer(auto_error=False)


@dataclass
class DeviceAuthContext:
    device: Device
    raw_token: str


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    try:
        token_data = verify_token(credentials.credentials, "access")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(
        select(User).where(
            User.id == uuid.UUID(token_data.user_id),
            User.is_active,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


async def get_device_from_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> Device:
    context = await get_device_auth_context(credentials, db)
    return context.device


async def get_device_auth_context(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> DeviceAuthContext:
    """Authenticate a collector/agent by its device token."""
    token = credentials.credentials
    token_hash = __import__("hashlib").sha256(token.encode()).hexdigest()

    result = await db.execute(
        select(Device).where(
            Device.agent_token_hash == token_hash,
            Device.is_active,
        )
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device token",
        )
    return DeviceAuthContext(device=device, raw_token=token)
