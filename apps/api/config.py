from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, field_validator
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    # App
    APP_NAME: str = "CyberGuard API"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://cyberguard:password@localhost:5432/cyberguard"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    SECRET_KEY: str = "CHANGE_THIS_IN_PRODUCTION_USE_SECRETS_TOKEN_HEX_64"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    # Stripe
    STRIPE_SECRET_KEY: str = "sk_test_..."
    STRIPE_WEBHOOK_SECRET: str = "whsec_..."
    STRIPE_PRICE_STARTER: str = "price_starter_id"
    STRIPE_PRICE_PRO: str = "price_pro_id"
    STRIPE_PRICE_ENTERPRISE: str = "price_enterprise_id"

    # LLM (Gemma via Ollama)
    GEMMA_API_URL: str = "http://localhost:11434"
    GEMMA_MODEL: str = "gemma3:12b"
    GEMMA_TIMEOUT: int = 120

    # S3 compatible storage
    S3_BUCKET: str = "cyberguard-evidence"
    S3_ENDPOINT: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "minioadmin"
    S3_SECRET_KEY: str = "minioadmin"
    S3_REGION: str = "us-east-1"

    # Threat Intel
    ABUSEIPDB_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    TELEMETRY_RATE_LIMIT: int = 300

    # HMAC secret for custody chain signatures (ALTA-03: minimum 32 bytes enforced)
    CUSTODY_HMAC_KEY: str = "CHANGE_THIS_CUSTODY_KEY_IN_PRODUCTION"

    @field_validator("CUSTODY_HMAC_KEY")
    @classmethod
    def validate_custody_hmac_key(cls, v: str) -> str:
        if len(v.encode()) < 32:
            raise ValueError("CUSTODY_HMAC_KEY must be at least 32 bytes long")
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v.encode()) < 32:
            raise ValueError("SECRET_KEY must be at least 32 bytes long")
        return v


settings = Settings()
