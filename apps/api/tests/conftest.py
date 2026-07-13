"""
Pytest configuration for CyberGuard API tests.
"""
import os
import sys
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

# Add apps/api to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

# Set test environment variables before importing
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://cyberguard:testpassword@localhost:5432/cyberguard_test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ["JWT_PRIVATE_KEY"] = """-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDY2YDA2uaCiqAn
0sLLnSNCJBs8qYi7qcEH6LYlywb6bmEwh48Ln4ysxNeMa7TGPoucT1j4QridjljP
UbbrW5S51vPEU99gGZYOThjFvcs6BP3S79Soy1QNHOsg3J4e8QAdZCWCesdGuf2s
h8HLZCu4MjiCiHWaPDY/VcDkcTQ6eccFmwVUKBj7Ud5P/ZcowfaXOE7L/9H3tlad
XfQFxjgr+c5Enf1eC0B3VxBc29LA5ey9wtlSLxpE/G4spEeEC/Gw4D93hikdMmCT
/6c56Nv9ip8FTwrh7Lz+fiuUsrAJ5VKZ6P6VxP+l/PbvIyYOaL/+vuRouaI3YIq5
QEi/NMVPAgMBAAECgf8WBgENlS3UFEAvyzf9dfgev4wEnTNF2/e+1eOp8vTCenNk
emAMzid7ZIJ/wHCbsb58IZLno98cIVjjtWjefm6ccThQuDP3jqGu0j+x1ZTOT7N3
uOPgQMZIjqdSrxVgDxnz4jftCIs0o68f1qnX/lRyYKdcmn9XKsZXqF3u1ZB4X7X6
6ESlbpqpFJVsRnEySh4+s3rbceRkvv/U3tt0/HeakhmXIgjPqmQlSYsE23/JUk9X
loGzTrjd0q9dE54AY8CqldDlpTRTniU95j1wNv+bB3btdE+4bPtmcDl0oVVLsfOL
UJp8wRPXPNtq9BZpnLq9BTraKkrhLN+YLc/4MoECgYEA7G3jAuMM8uJ+e5sIAIam
p/8OWRxyTrR2XoSvKtF4WOmxiTWnjQdkYwa9sKLnRy7ZgoFZGVif4kox46Z/QwGY
zbWhZ4dIsWX7YK1PCntaG0YxnrlzvykT11qwWtw3KrRJwGidr0u65oKDv3YzA6nD
yUYF09qz9fMvzaUycbrCxeECgYEA6sy1kK8ih6XHIqyAwzhw0y2i0qZycSlF8mi7
skmJshCtpe8hhJSut+nrNVOM+2KVUAJXi+eycVfipjm45jOc8jL/BGuyn2BZvFxm
8gjZOKNiKBtsop3lrEcMlrARSvy2rV/nZO3m/5aGCaIwFPFyVbsvh/ZwjkluP1h2
JFMekS8CgYEAtloOtCRQ0WiVq1ooctdn5LzY4SwKkd+oSEBIJltHWjRsZOqIH0Lr
T2FcnscWYJWm13xSLzVmo48cKXw6PYEWzNpg8cuq6oBAwREKnIgFOHIMRWK9/lt9
XSUqTfn5ZquFEqzdqd1b+vwBB4Pv1sxyIGQsjHjrQjBd11upq4QjQ6ECgYB6DU14
V0GYx5j7MjaAxE8Jx1gzLeihYDYG62BeLhHQqRDLB8Ihm/Qyj/r/Ll5DspwxCfae
OCOu/WNIywqNR1kXIWEk2CLy6+/ZlSLCP81CvtNgS9ktsuxXoFsv3Xgvxavj9c1f
zrbcN0+XpGJgEJ5BaFstzvH1VMBlV0OaYEasawKBgCtI53n1u1fFw1xoa/1cnU1U
Y0cEnpjIT98ZweFrQ8FbRvLzo3IFKARhewmFKlQhUXHQN8X9zuny+HA4aPl3AfrT
YdZvMeRhIvgJxCwGraLkKaeYd+gsU8/rGMLboBRS0t9CE09SyOc1jvW4DI/33rzR
j6Bl7BVanE3Cy97FtfiM
-----END PRIVATE KEY-----"""
os.environ["JWT_PUBLIC_KEY"] = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2NmAwNrmgoqgJ9LCy50j
QiQbPKmIu6nBB+i2JcsG+m5hMIePC5+MrMTXjGu0xj6LnE9Y+EK4nY5Yz1G261uU
udbzxFPfYBmWDk4Yxb3LOgT90u/UqMtUDRzrINyeHvEAHWQlgnrHRrn9rIfBy2Qr
uDI4goh1mjw2P1XA5HE0OnnHBZsFVCgY+1HeT/2XKMH2lzhOy//R97ZWnV30BcY4
K/nORJ39XgtAd1cQXNvSwOXsvcLZUi8aRPxuLKRHhAvxsOA/d4YpHTJgk/+nOejb
/YqfBU8K4ey8/n4rlLKwCeVSmej+lcT/pfz27yMmDmi//r7kaLmiN2CKuUBIvzTF
TwIDAQAB
-----END PUBLIC KEY-----"""
os.environ.setdefault("STRIPE_SECRET_KEY", "sk_test_dummy")
os.environ.setdefault("STRIPE_WEBHOOK_SECRET", "whsec_dummy")
os.environ.setdefault("STRIPE_PRICE_STARTER", "price_starter_test")
os.environ.setdefault("STRIPE_PRICE_PRO", "price_pro_test")
os.environ.setdefault("STRIPE_PRICE_ENTERPRISE", "price_enterprise_test")
os.environ.setdefault("GEMMA_API_URL", "http://localhost:11434")
os.environ.setdefault("S3_ENDPOINT", "http://localhost:9000")
os.environ.setdefault("S3_BUCKET", "cyberguard-test")
os.environ.setdefault("S3_ACCESS_KEY", "test-access-key")
os.environ.setdefault("S3_SECRET_KEY", "test-secret-key")
os.environ.setdefault("S3_REGION", "us-east-1")
os.environ.setdefault("CUSTODY_HMAC_KEY", "test-hmac-key-minimum-32-bytes-long")
os.environ.setdefault("ALLOWED_ORIGINS", '["http://localhost:3000","http://localhost:8000"]')
os.environ.setdefault("ENVIRONMENT", "test")


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db():
    """Mock database session"""
    mock = AsyncMock()
    mock.execute = AsyncMock()
    mock.commit = AsyncMock()
    mock.rollback = AsyncMock()
    mock.close = AsyncMock()
    mock.flush = AsyncMock()
    return mock


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    mock = AsyncMock()
    mock.get = AsyncMock(return_value=None)
    mock.set = AsyncMock(return_value=True)
    mock.setex = AsyncMock(return_value=True)
    mock.delete = AsyncMock(return_value=True)
    mock.incr = AsyncMock(return_value=1)
    mock.expire = AsyncMock(return_value=True)
    mock.ttl = AsyncMock(return_value=300)
    mock.pipeline = MagicMock(return_value=AsyncMock(
        execute=AsyncMock(return_value=[1, True])
    ))
    return mock


@pytest.fixture
def mock_settings(monkeypatch):
    """Mock settings for testing"""
    from apps.api.config import Settings
    
    # Create test settings
    test_settings = Settings(
        DATABASE_URL="postgresql+asyncpg://cyberguard:test@localhost/test",
        REDIS_URL="redis://localhost:6379/0",
        JWT_PRIVATE_KEY="""-----BEGIN PRIVATE KEY-----
MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQDY2YDA2uaCiqAn
0sLLnSNCJBs8qYi7qcEH6LYlywb6bmEwh48Ln4ysxNeMa7TGPoucT1j4QridjljP
UbbrW5S51vPEU99gGZYOThjFvcs6BP3S79Soy1QNHOsg3J4e8QAdZCWCesdGuf2s
h8HLZCu4MjiCiHWaPDY/VcDkcTQ6eccFmwVUKBj7Ud5P/ZcowfaXOE7L/9H3tlad
XfQFxjgr+c5Enf1eC0B3VxBc29LA5ey9wtlSLxpE/G4spEeEC/Gw4D93hikdMmCT
/6c56Nv9ip8FTwrh7Lz+fiuUsrAJ5VKZ6P6VxP+l/PbvIyYOaL/+vuRouaI3YIq5
QEi/NMVPAgMBAAECgf8WBgENlS3UFEAvyzf9dfgev4wEnTNF2/e+1eOp8vTCenNk
emAMzid7ZIJ/wHCbsb58IZLno98cIVjjtWjefm6ccThQuDP3jqGu0j+x1ZTOT7N3
uOPgQMZIjqdSrxVgDxnz4jftCIs0o68f1qnX/lRyYKdcmn9XKsZXqF3u1ZB4X7X6
6ESlbpqpFJVsRnEySh4+s3rbceRkvv/U3tt0/HeakhmXIgjPqmQlSYsE23/JUk9X
loGzTrjd0q9dE54AY8CqldDlpTRTniU95j1wNv+bB3btdE+4bPtmcDl0oVVLsfOL
UJp8wRPXPNtq9BZpnLq9BTraKkrhLN+YLc/4MoECgYEA7G3jAuMM8uJ+e5sIAIam
p/8OWRxyTrR2XoSvKtF4WOmxiTWnjQdkYwa9sKLnRy7ZgoFZGVif4kox46Z/QwGY
zbWhZ4dIsWX7YK1PCntaG0YxnrlzvykT11qwWtw3KrRJwGidr0u65oKDv3YzA6nD
yUYF09qz9fMvzaUycbrCxeECgYEA6sy1kK8ih6XHIqyAwzhw0y2i0qZycSlF8mi7
skmJshCtpe8hhJSut+nrNVOM+2KVUAJXi+eycVfipjm45jOc8jL/BGuyn2BZvFxm
8gjZOKNiKBtsop3lrEcMlrARSvy2rV/nZO3m/5aGCaIwFPFyVbsvh/ZwjkluP1h2
JFMekS8CgYEAtloOtCRQ0WiVq1ooctdn5LzY4SwKkd+oSEBIJltHWjRsZOqIH0Lr
T2FcnscWYJWm13xSLzVmo48cKXw6PYEWzNpg8cuq6oBAwREKnIgFOHIMRWK9/lt9
XSUqTfn5ZquFEqzdqd1b+vwBB4Pv1sxyIGQsjHjrQjBd11upq4QjQ6ECgYB6DU14
V0GYx5j7MjaAxE8Jx1gzLeihYDYG62BeLhHQqRDLB8Ihm/Qyj/r/Ll5DspwxCfae
OCOu/WNIywqNR1kXIWEk2CLy6+/ZlSLCP81CvtNgS9ktsuxXoFsv3Xgvxavj9c1f
zrbcN0+XpGJgEJ5BaFstzvH1VMBlV0OaYEasawKBgCtI53n1u1fFw1xoa/1cnU1U
Y0cEnpjIT98ZweFrQ8FbRvLzo3IFKARhewmFKlQhUXHQN8X9zuny+HA4aPl3AfrT
YdZvMeRhIvgJxCwGraLkKaeYd+gsU8/rGMLboBRS0t9CE09SyOc1jvW4DI/33rzR
j6Bl7BVanE3Cy97FtfiM
-----END PRIVATE KEY-----""",
        JWT_PUBLIC_KEY="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2NmAwNrmgoqgJ9LCy50j
QiQbPKmIu6nBB+i2JcsG+m5hMIePC5+MrMTXjGu0xj6LnE9Y+EK4nY5Yz1G261uU
udbzxFPfYBmWDk4Yxb3LOgT90u/UqMtUDRzrINyeHvEAHWQlgnrHRrn9rIfBy2Qr
uDI4goh1mjw2P1XA5HE0OnnHBZsFVCgY+1HeT/2XKMH2lzhOy//R97ZWnV30BcY4
K/nORJ39XgtAd1cQXNvSwOXsvcLZUi8aRPxuLKRHhAvxsOA/d4YpHTJgk/+nOejb
/YqfBU8K4ey8/n4rlLKwCeVSmej+lcT/pfz27yMmDmi//r7kaLmiN2CKuUBIvzTF
TwIDAQAB
-----END PUBLIC KEY-----""",
        STRIPE_SECRET_KEY="sk_test_dummy",
        STRIPE_WEBHOOK_SECRET="whsec_dummy",
        GEMMA_API_URL="http://localhost:11434",
        S3_ENDPOINT="http://localhost:9000",
        CUSTODY_HMAC_KEY="test-hmac-key-minimum-32-bytes-long",
        ENVIRONMENT="test",
        ALLOWED_ORIGINS=["http://localhost:3000"],
    )
    
    # Patch the settings instance
    import apps.api.config
    monkeypatch.setattr(apps.api.config, "settings", test_settings)
    
    return test_settings