#!/usr/bin/env python3
"""Tests for HMAC, bcrypt, and other security primitives"""
from apps.api.core.security import (
    hash_password, verify_password,
    sign_custody_record, verify_custody_signature,
    compute_sha256, compute_sha512,
    generate_device_token, hash_device_token, verify_device_token
)


def test_bcrypt_hash_strength():
    """Test that bcrypt hashing works with proper salt generation"""
    password = "TestPassword123!"
    hashed = hash_password(password)
    
    assert isinstance(hashed, str)
    assert hashed.startswith("$2b$")  # bcrypt identifier
    assert len(hashed) == 60  # bcrypt hash length
    
    # Verify correct password
    assert verify_password(password, hashed)
    
    # Verify incorrect password fails
    assert not verify_password("WrongPassword123!", hashed)


def test_custody_hmac_integrity():
    """Test HMAC-SHA256 for custody chain integrity"""
    data = "Critical system log entry: User admin logged in from 192.168.1.100"
    signature = sign_custody_record(data)
    
    assert isinstance(signature, str)
    assert len(signature) == 64  # SHA256 hex digest length
    
    # Should verify correctly
    assert verify_custody_signature(data, signature)
    
    # Should fail for tampered data
    tampered_data = data + "X"  # Modified data
    assert not verify_custody_signature(tampered_data, signature)
    
    # Should fail for wrong signature
    wrong_signature = "a" * 64
    assert not verify_custody_signature(data, wrong_signature)


def test_hash_functions():
    """Test SHA256 and SHA512 hash functions"""
    data = b"test data for hashing"
    
    sha256_hash = compute_sha256(data)
    sha512_hash = compute_sha512(data)
    
    assert isinstance(sha256_hash, str)
    assert len(sha256_hash) == 64  # 32 bytes = 64 hex chars
    
    assert isinstance(sha512_hash, str)
    assert len(sha512_hash) == 128  # 64 bytes = 128 hex chars
    
    # Different inputs should give different outputs
    assert compute_sha256(b"different") != sha256_hash
    assert compute_sha512(b"different") != sha512_hash


def test_device_token_security():
    """Test secure device token generation and verification"""
    token = generate_device_token()
    assert isinstance(token, str)
    assert len(token) >= 48  # secrets.token_urlsafe(48)
    
    hashed = hash_device_token(token)
    assert isinstance(hashed, str)
    assert len(hashed) == 64  # SHA256
    
    # Should verify correctly
    assert verify_device_token(token, hashed)
    
    # Should reject wrong token
    assert not verify_device_token("wrong_token", hashed)
    
    # Should reject wrong hash
    assert not verify_device_token(token, "b" * 64)


def test_telemetry_signature():
    """Test telemetry HMAC signature with device_id"""
    from apps.api.core.security import sign_telemetry, verify_telemetry_signature
    
    device_id = "test-device-id"
    raw_token = "test-token"
    timestamp = "2024-01-01T00:00:00Z"
    nonce = "test-nonce"
    payload = b'{"test": "data"}'
    
    signature = sign_telemetry(device_id, raw_token, timestamp, nonce, payload)
    assert isinstance(signature, str)
    assert len(signature) == 64
    
    # Should verify correctly
    assert verify_telemetry_signature(device_id, raw_token, timestamp, nonce, payload, signature)
    
    # Should fail with different device_id
    assert not verify_telemetry_signature("different-device", raw_token, timestamp, nonce, payload, signature)
    
    # Should fail with tampered payload
    tampered_payload = b'{"test": "tampered"}'
    assert not verify_telemetry_signature(device_id, raw_token, timestamp, nonce, tampered_payload, signature)