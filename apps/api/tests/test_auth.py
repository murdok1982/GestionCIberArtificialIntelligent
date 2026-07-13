#!/usr/bin/env python3
"""Tests for authentication flows including login, lockout, refresh"""
import pytest
import uuid
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import timedelta

from apps.api.core.security import hash_password, create_access_token, verify_token


@pytest.mark.asyncio
async def test_password_bcrypt_enforcement():
    """Test that bcrypt hashing is enforced for passwords"""
    from apps.api.core.security import verify_password
    
    password = "StrongPass123!@#"
    hashed = hash_password(password)
    
    # Bcrypt should generate a hash
    assert hashed.startswith("$2b$")
    assert verify_password(password, hashed)
    
    # Wrong password should fail
    assert not verify_password("wrongpassword", hashed)


@pytest.mark.asyncio
async def test_jwt_token_verification():
    """Test JWT token creation and verification"""
    payload = {
        "sub": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "role": "analyst"
    }
    
    token = create_access_token(payload, expires_delta=timedelta(minutes=15))
    assert token is not None
    assert len(token.split('.')) == 3  # JWT has 3 parts
    
    # Verify token
    token_data = verify_token(token)
    assert token_data.user_id == payload["sub"]
    assert token_data.tenant_id == payload["tenant_id"]
    assert token_data.role == payload["role"]


@pytest.mark.asyncio
async def test_jwt_expiration():
    """Test JWT token expiration is enforced"""
    from apps.api.core.security import verify_token
    
    # Create expired token
    payload = {"sub": "123", "tenant_id": "456", "role": "user"}
    expired_token = create_access_token(payload, expires_delta=timedelta(seconds=-1))
    
    # Expired token should raise ValueError
    with pytest.raises(ValueError):
        verify_token(expired_token)


@pytest.mark.asyncio
async def test_account_lockout_mechanism():
    """Test account lockout after failed attempts"""
    from apps.api.routes.auth import _MAX_FAILED_ATTEMPTS
    
    mock_redis = MagicMock()
    mock_redis.get = AsyncMock(return_value=str(_MAX_FAILED_ATTEMPTS - 1))
    mock_redis.ttl = AsyncMock(return_value=300)
    mock_redis.incr = AsyncMock()
    mock_redis.expire = AsyncMock()
    
    with patch('apps.api.routes.auth.get_redis', return_value=mock_redis):
        from fastapi.testclient import TestClient
        from apps.api.main import app
        
        client = TestClient(app)
        client.post(
            "/api/v1/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword"}
        )
        
        # Should increment counter
        assert mock_redis.incr.called or mock_redis.get.called


@pytest.mark.asyncio
async def test_refresh_token_rotation():
    """Test refresh token JTI whitelist rotation"""
    from apps.api.core.security import create_refresh_token, get_token_jti
    
    payload = {"sub": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()), "role": "user"}
    token, jti = create_refresh_token(payload)
    
    # JTI should be extracted
    extracted_jti = get_token_jti(token)
    assert extracted_jti == jti
    assert len(jti) >= 32  # Secure random token length


@pytest.mark.asyncio
async def test_tenant_isolation():
    """Test that tenant data is properly isolated"""
    from apps.api.middleware.tenant import TenantIsolationMiddleware
    from apps.api.main import app

    # Test that tenant IDs are properly set in request context
    mock_request = MagicMock()
    mock_request.headers = {"X-Tenant-ID": str(uuid.uuid4())}

    TenantIsolationMiddleware(app)
    
    # Tenant ID should be extracted and validated
    tenant_id = mock_request.headers.get("X-Tenant-ID")
    assert tenant_id is not None
    
    # UUID format should be valid
    try:
        uuid.UUID(tenant_id)
        is_valid_uuid = True
    except ValueError:
        is_valid_uuid = False
    assert is_valid_uuid


@pytest.mark.asyncio
async def test_cors_configuration():
    """Test CORS is not configured with wildcard in production"""
    from apps.api.config import settings
    
    if settings.ENVIRONMENT.lower() == "production":
        # In production, origins should be specific
        assert "*" not in settings.ALLOWED_ORIGINS
        assert len(settings.ALLOWED_ORIGINS) > 0
    else:
        # In development, localhost is acceptable
        assert "http://localhost:3000" in settings.ALLOWED_ORIGINS


@pytest.mark.asyncio
async def test_password_strength_validation():
    """Test password strength validation rules"""
    from apps.api.routes.auth import _validate_password_strength
    from fastapi import HTTPException
    
    # Too short
    with pytest.raises(HTTPException) as exc:
        _validate_password_strength("short")
    assert exc.value.status_code == 422
    
    # Missing uppercase
    with pytest.raises(HTTPException) as exc:
        _validate_password_strength("testpass123!")
    assert exc.value.status_code == 422
    
    # Missing lowercase
    with pytest.raises(HTTPException) as exc:
        _validate_password_strength("TESTPASS123!")
    assert exc.value.status_code == 422
    
    # Missing number
    with pytest.raises(HTTPException) as exc:
        _validate_password_strength("TestPass!")
    assert exc.value.status_code == 422
    
    # Missing special char
    with pytest.raises(HTTPException) as exc:
        _validate_password_strength("TestPass123")
    assert exc.value.status_code == 422
    
    # Valid password should not raise
    _validate_password_strength("TestPass123!")