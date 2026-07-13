import secrets
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from apps.api.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenData(BaseModel):
    user_id: str
    tenant_id: str
    role: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _get_private_key() -> str:
    return settings.JWT_PRIVATE_KEY.get_secret_value()


def _get_public_key() -> str:
    return settings.JWT_PUBLIC_KEY.get_secret_value()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, _get_private_key(), algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> tuple[str, str]:
    """Returns (token, jti). Store jti in Redis whitelist."""
    to_encode = data.copy()
    jti = secrets.token_urlsafe(32)
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh", "jti": jti})
    token = jwt.encode(to_encode, _get_private_key(), algorithm=settings.JWT_ALGORITHM)
    return token, jti


def verify_token(token: str, token_type: str = "access") -> TokenData:
    try:
        payload = jwt.decode(token, _get_public_key(), algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != token_type:
            raise jwt.InvalidTokenError("Invalid token type")
        return TokenData(
            user_id=payload["sub"],
            tenant_id=payload["tenant_id"],
            role=payload["role"],
        )
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")


def get_token_jti(token: str) -> Optional[str]:
    """Decode without verification to extract jti field."""
    try:
        payload = jwt.decode(
            token, _get_public_key(), algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        return payload.get("jti")
    except jwt.InvalidTokenError:
        return None


def generate_device_token() -> str:
    """Generate a secure random token for device authentication."""
    return secrets.token_urlsafe(48)


def hash_device_token(token: str) -> str:
    """SHA-256 hash of the device token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def verify_device_token(plain_token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(plain_token.encode()).hexdigest(),
        stored_hash
    )


def sign_custody_record(record_data: str) -> str:
    """HMAC-SHA256 signature for custody chain integrity."""
    return hmac.new(
        settings.CUSTODY_HMAC_KEY.get_secret_value().encode(),
        record_data.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_custody_signature(record_data: str, signature: str) -> bool:
    expected = sign_custody_record(record_data)
    return hmac.compare_digest(expected, signature)


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_sha512(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sign_telemetry(device_id: str, raw_token: str, timestamp: str, nonce: str, payload_bytes: bytes) -> str:
    """Create HMAC signature for telemetry including device_id in signing input."""
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    signing_input = f"{device_id}.{timestamp}.{nonce}.{payload_hash}".encode("utf-8")
    return hmac.new(raw_token.encode("utf-8"), signing_input, hashlib.sha256).hexdigest()


def verify_telemetry_signature(device_id: str, raw_token: str, timestamp: str, nonce: str, payload_bytes: bytes, signature: str) -> bool:
    """Verify HMAC signature for telemetry."""
    expected = sign_telemetry(device_id, raw_token, timestamp, nonce, payload_bytes)
    return hmac.compare_digest(expected, signature)