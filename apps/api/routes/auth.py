import uuid
import re
import pyotp
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, Field

from apps.api.database import get_db
from apps.api.models.user import User, UserRole
from apps.api.models.tenant import Tenant, PlanType
from apps.api.core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, verify_token, get_token_jti,
)
from apps.api.core.redis_client import get_redis
from apps.api.core.request import client_ip
from apps.api.middleware.auth import get_current_user
from apps.api.config import settings
from apps.api.services.audit_service import AuditService
from apps.api.models.audit import AuditCategory, AuditSeverity

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
    mfa_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _lockout_key(email: str) -> str:
    return f"lockout:{email}"


def _refresh_whitelist_key(jti: str) -> str:
    return f"rt_whitelist:{jti}"


def _validate_password_strength(password: str) -> None:
    if len(password) < 12:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters long")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one special character")


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    secure_cookie = settings.COOKIE_SECURE or settings.ENVIRONMENT.lower() == "production"
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=secure_cookie,
        samesite=settings.COOKIE_SAMESITE,
        max_age=_REFRESH_TTL_SECONDS,
        path="/api/v1/auth",
        domain=settings.COOKIE_DOMAIN or None,
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(data: RegisterRequest, response: Response, db: AsyncSession = Depends(get_db)):
    _validate_password_strength(data.password)

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

    await AuditService().record(
        db, category=AuditCategory.auth, action="register",
        user_id=user.id, tenant_id=tenant.id,
        detail={"company": data.company_name},
    )

    token_payload = {
        "sub": str(user.id),
        "tenant_id": str(tenant.id),
        "role": user.role,
    }

    refresh_token, jti = create_refresh_token(token_payload)
    _set_refresh_cookie(response, refresh_token)

    redis = await get_redis()
    await redis.setex(_refresh_whitelist_key(jti), _REFRESH_TTL_SECONDS, str(user.id))

    return {
        "access_token": create_access_token(token_payload),
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "tenant": {"id": str(tenant.id), "name": tenant.name, "plan": tenant.plan},
        "user": {"id": str(user.id), "email": user.email, "role": user.role, "full_name": user.full_name},
    }


class MfaEnableRequest(BaseModel):
    pass


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


@router.post("/mfa/enable", status_code=status.HTTP_200_OK)
async def mfa_enable(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Generate a TOTP secret. MFA is enabled only after confirming a valid code."""
    secret = pyotp.random_base32()
    current_user.mfa_secret = secret
    await db.flush()
    otpauth_url = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="CyberGuard"
    )
    return {"secret": secret, "otpauth_url": otpauth_url, "mfa_enabled": current_user.mfa_enabled}


@router.post("/mfa/confirm", status_code=status.HTTP_200_OK)
async def mfa_confirm(
    data: MfaConfirmRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enable MFA after verifying a TOTP code."""
    if not current_user.mfa_secret or not pyotp.TOTP(current_user.mfa_secret).verify(data.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
    current_user.mfa_enabled = True
    await AuditService().record(
        db, category=AuditCategory.auth, action="mfa_enabled",
        user_id=current_user.id, tenant_id=current_user.tenant_id,
    )
    return {"mfa_enabled": True}


@router.post("/mfa/disable", status_code=status.HTTP_200_OK)
async def mfa_disable(
    data: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA after verifying a TOTP code."""
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA is not enabled")
    if not pyotp.TOTP(current_user.mfa_secret).verify(data.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA code")
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await AuditService().record(
        db, category=AuditCategory.auth, action="mfa_disabled",
        user_id=current_user.id, tenant_id=current_user.tenant_id,
    )
    return {"mfa_enabled": False}


@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    redis = await get_redis()
    lockout_key = _lockout_key(data.email)
    audit = AuditService()
    ip = client_ip(request)

    # ALTA-01: Check if account is locked out
    failed_count = await redis.get(lockout_key)
    if failed_count and int(failed_count) >= _MAX_FAILED_ATTEMPTS:
        ttl = await redis.ttl(lockout_key)
        await audit.record(
            db, category=AuditCategory.auth, action="login_locked_out",
            severity=AuditSeverity.warning, detail={"email": data.email}, ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked. Try again in {ttl} seconds.",
            headers={"Retry-After": str(ttl)},
        )

    result = await db.execute(
        select(User).where(User.email == data.email, User.is_active)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password_hash):
        # ALTA-01: Increment failure counter
        pipe = redis.pipeline()
        pipe.incr(lockout_key)
        pipe.expire(lockout_key, _ATTEMPT_WINDOW_SECONDS)
        await pipe.execute()
        await audit.record(
            db, category=AuditCategory.auth, action="login_failed",
            severity=AuditSeverity.warning,
            detail={"email": data.email, "reason": "invalid_credentials"},
            ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # MFA (TOTP) verification when enabled
    if user.mfa_enabled:
        if not data.mfa_code or not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(data.mfa_code, valid_window=1):
            await audit.record(
                db, category=AuditCategory.auth, action="login_mfa_failed",
                severity=AuditSeverity.warning, user_id=user.id, tenant_id=user.tenant_id,
                detail={"email": data.email}, ip_address=ip,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing MFA code",
            )

    # Successful login — clear lockout counter
    await redis.delete(lockout_key)

    await audit.record(
        db, category=AuditCategory.auth, action="login_success",
        user_id=user.id, tenant_id=user.tenant_id, ip_address=ip,
    )

    user.last_login = datetime.now(timezone.utc)

    token_payload = {
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "role": user.role,
    }

    refresh_token, jti = create_refresh_token(token_payload)
    _set_refresh_cookie(response, refresh_token)

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
async def refresh_token_endpoint(
    response: Response,
    request: Request,
    data: RefreshRequest | None = None,
    db: AsyncSession = Depends(get_db),
):
    refresh_token = data.refresh_token if data else None
    if not refresh_token:
        refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")

    try:
        token_data = verify_token(refresh_token, "refresh")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    # ALTA-04: Verify JTI is in whitelist (not used/revoked)
    jti = get_token_jti(refresh_token)
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
        select(User).where(User.id == uuid.UUID(token_data.user_id), User.is_active)
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
    _set_refresh_cookie(response, new_refresh_token)

    return {
        "access_token": create_access_token(token_payload),
        "token_type": "bearer",
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response, request: Request, data: LogoutRequest | None = None, db: AsyncSession = Depends(get_db), current_user: User | None = Depends(get_current_user)):
    """Revoke the refresh token by removing its JTI from the whitelist."""
    if current_user is not None:
        await AuditService().record(
            db, category=AuditCategory.auth, action="logout",
            user_id=current_user.id, tenant_id=current_user.tenant_id, ip_address=client_ip(request),
        )
    refresh_token = data.refresh_token if data else None
    if not refresh_token:
        refresh_token = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    jti = get_token_jti(refresh_token) if refresh_token else None
    if jti:
        redis = await get_redis()
        await redis.delete(_refresh_whitelist_key(jti))
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        domain=settings.COOKIE_DOMAIN or None,
    )


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
