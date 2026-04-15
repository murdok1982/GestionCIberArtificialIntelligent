import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr

from apps.api.database import get_db
from apps.api.models.user import User, UserRole
from apps.api.models.tenant import Tenant, PlanType
from apps.api.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, verify_token, get_token_jti,
)
from apps.api.core.redis_client import get_redis
from apps.api.middleware.auth import get_current_user
from apps.api.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Account lockout settings (ALTA-01)
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 15 * 60          # 15 minutes
_ATTEMPT_WINDOW_SECONDS = 15 * 60   # sliding window

# Refresh token whitelist TTL (ALTA-04)
_REFRESH_TTL_SECONDS = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400


class RegisterRequest(BaseModel):
    company_name: str
    full_name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _lockout_key(email: str) -> str:
    return f"lockout:{email}"


def _refresh_whitelist_key(jti: str) -> str:
    return f"rt_whitelist:{jti}"


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    slug = _slug(data.company_name)
    tenant = Tenant(
        id=uuid.uuid4(),
        name=data.company_name,
        slug=slug,
        plan=PlanType.starter,
        is_active=True,
        max_devices=10,
    )
    db.add(tenant)
    await db.flush()

    user = User(
        id=uuid.uuid4(),
        tenant_id=tenant.id,
        email=data.email,
        full_name=data.full_name,
        password_hash=hash_password(data.password),
        role=UserRole.owner,
        is_active=True,
    )
    db.add(user)
    await db.flush()

    token_payload = {
        "sub": str(user.id),
        "tenant_id": str(tenant.id),
        "role": user.role,
    }

    refresh_token, jti = create_refresh_token(token_payload)

    redis = await get_redis()
    await redis.setex(_refresh_whitelist_key(jti), _REFRESH_TTL_SECONDS, str(user.id))

    return {
        "access_token": create_access_token(token_payload),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "tenant": {"id": str(tenant.id), "name": tenant.name, "plan": tenant.plan},
        "user": {"id": str(user.id), "email": user.email, "role": user.role, "full_name": user.full_name},
    }


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    redis = await get_redis()
    lockout_key = _lockout_key(data.email)

    # ALTA-01: Check if account is locked out
    failed_count = await redis.get(lockout_key)
    if failed_count and int(failed_count) >= _MAX_FAILED_ATTEMPTS:
        ttl = await redis.ttl(lockout_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )

    result = await db.execute(
        select(User).where(User.email == data.email, User.is_active == True)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        # ALTA-01: Increment failure counter
        pipe = redis.pipeline()
        pipe.incr(lockout_key)
        pipe.expire(lockout_key, _ATTEMPT_WINDOW_SECONDS)
        await pipe.execute()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Successful login — clear lockout counter
    await redis.delete(lockout_key)

    user.last_login = datetime.utcnow()

    token_payload = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
    }

    refresh_token, jti = create_refresh_token(token_payload)

    # ALTA-04: Whitelist new refresh token JTI in Redis
    await redis.setex(_refresh_whitelist_key(jti), _REFRESH_TTL_SECONDS, str(user.id))

    return TokenResponse(
        access_token=create_access_token(token_payload),
        refresh_token=refresh_token,
        user={
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "tenant_id": str(user.tenant_id),
            "mfa_enabled": user.mfa_enabled,
        },
    )


@router.post("/refresh")
async def refresh_token_endpoint(data: RefreshRequest, db: AsyncSession = Depends(get_db)):
    try:
        token_data = verify_token(data.refresh_token, "refresh")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # ALTA-04: Verify JTI is in whitelist (not used/revoked)
    jti = get_token_jti(data.refresh_token)
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    redis = await get_redis()
    whitelist_key = _refresh_whitelist_key(jti)
    stored_user_id = await redis.get(whitelist_key)
    if not stored_user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked or already used",
        )

    result = await db.execute(
        select(User).where(User.id == uuid.UUID(token_data.user_id), User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        await redis.delete(whitelist_key)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # ALTA-04: Rotate — delete old JTI, issue new token with new JTI
    await redis.delete(whitelist_key)

    token_payload = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
    }

    new_refresh_token, new_jti = create_refresh_token(token_payload)
    await redis.setex(_refresh_whitelist_key(new_jti), _REFRESH_TTL_SECONDS, str(user.id))

    return {
        "access_token": create_access_token(token_payload),
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(data: LogoutRequest):
    """Revoke the refresh token by removing its JTI from the whitelist."""
    jti = get_token_jti(data.refresh_token)
    if jti:
        redis = await get_redis()
        await redis.delete(_refresh_whitelist_key(jti))


@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "tenant_id": str(current_user.tenant_id),
        "mfa_enabled": current_user.mfa_enabled,
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
    }
