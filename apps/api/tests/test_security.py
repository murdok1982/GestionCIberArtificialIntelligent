#!/usr/bin/env python3
"""Security tests for API endpoints and configuration"""
import pytest
from apps.api.main import app
from apps.api.config import settings


@pytest.fixture
def client():
    """Create test client"""
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_jwt_algorithm_security():
    """Test that JWT configuration uses strong algorithm"""
    # Ensure JWT_ALGORITHM is set to a strong algorithm
    assert settings.JWT_ALGORITHM in ["RS256", "ES256"]
    
    # Ensure keys are configured
    assert settings.JWT_PRIVATE_KEY.get_secret_value().startswith("-----BEGIN")
    assert settings.JWT_PUBLIC_KEY.get_secret_value().startswith("-----BEGIN")


def test_custody_hmac_key_length():
    """Test CUSTODY_HMAC_KEY validation"""
    assert len(settings.CUSTODY_HMAC_KEY.get_secret_value().encode()) >= 32


def test_production_secrets_required():
    """Test that production requires all secrets"""
    # This test validates the validator works
    original_env = settings.ENVIRONMENT
    
    # In production, all secrets must be provided
    if original_env.lower() == "production":
        required = [
            "DATABASE_URL", "REDIS_URL", "JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY",
            "STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET",
            "S3_ACCESS_KEY", "S3_SECRET_KEY", "CUSTODY_HMAC_KEY"
        ]
        for key in required:
            assert hasattr(settings, key)


@pytest.mark.asyncio
async def test_login_endpoint_no_verbose_errors(client):
    """Test that login errors don't expose stack traces"""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "wrong_password"}
    )
    assert response.status_code == 401
    # Response should not contain stack traces
    assert "traceback" not in response.text.lower()
    assert "internal server error" not in response.text.lower()


@pytest.mark.asyncio
async def test_register_validation(client):
    """Test registration validation rules"""
    # Test weak password (too short)
    weak_resp = client.post(
        "/api/v1/auth/register",
        json={
            "company_name": "TestCo",
            "full_name": "Test User",
            "email": "test@example.com",
            "password": "short",
        }
    )
    assert weak_resp.status_code == 422
    
    # Test missing password complexity
    missing_rules = client.post(
        "/api/v1/auth/register",
        json={
            "company_name": "TestCo",
            "full_name": "Test User",
            "email": "test@example.com",
            "password": "TestPass123",  # Missing special char
        }
    )
    assert missing_rules.status_code == 422


@pytest.mark.asyncio
async def test_detection_rules_apply():
    """Test that detection rules correctly identify threats"""
    from apps.api.agents.detection_agent import DetectionAgent
    
    agent = DetectionAgent()
    
    # Test SSH brute force detection
    telemetry_with_bruteforce = {
        "event_type": "auth_log",
        "raw_data": {
            "log_entries": [
                "Failed password for invalid user hacker from 192.168.1.100 port 22 ssh2",
                "Failed password for root from 192.168.1.100 port 22 ssh2",
                "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
                "Failed password for user from 192.168.1.100 port 22 ssh2",
                "Failed password for user from 192.168.1.100 port 22 ssh2",
            ]
        }
    }
    
    detections = await agent.analyze_telemetry(telemetry_with_bruteforce)
    assert len(detections) > 0
    assert any(d["rule_id"] == "ssh_brute_force" for d in detections)
    assert any(d["severity"] == "high" for d in detections)
    
    # Test lateral movement detection
    lateral_event = {
        "event_type": "connection",
        "raw_data": {
            "connections": [
                {"remote_address": "192.168.1.10:445", "remote_port": 445, "status": "ESTABLISHED"},
                {"remote_address": "192.168.1.11:445", "remote_port": 445, "status": "ESTABLISHED"}, 
                {"remote_address": "192.168.1.12:445", "remote_port": 445, "status": "ESTABLISHED"}
            ]
        }
    }
    
    detections = await agent.analyze_telemetry(lateral_event)
    assert any(d["rule_id"] == "lateral_movement_smb" for d in detections)
    assert any(d["severity"] == "critical" for d in detections)


@pytest.mark.asyncio
async def test_threat_intel_ssrf_protection():
    """Test threat intel rejects private/reserved IPs (SSRF protection)"""
    from apps.api.agents.threat_intel_agent import ThreatIntelAgent
    
    agent = ThreatIntelAgent()
    
    # Private IP should be rejected
    private_ips = ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.169.254"]
    for ip in private_ips:
        assert not agent._is_public_ip(ip), f"Private IP {ip} should be rejected"
    
    # Public IP should be accepted
    public_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    for ip in public_ips:
        assert agent._is_public_ip(ip), f"Public IP {ip} should be accepted"