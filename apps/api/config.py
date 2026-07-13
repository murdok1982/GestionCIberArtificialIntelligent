from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator, SecretStr
from typing import List, Optional
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.getenv("DOTENV_FILE", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # App
    APP_NAME: str = "CyberGuard API"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database - no default in production
    DATABASE_URL: SecretStr

    # Redis - no default in production
    REDIS_URL: SecretStr

    # JWT - asymmetric key pair required (PEM content inline OR path to PEM file)
    JWT_PRIVATE_KEY: Optional[SecretStr] = None
    JWT_PUBLIC_KEY: Optional[SecretStr] = None
    JWT_PRIVATE_KEY_PATH: Optional[str] = None
    JWT_PUBLIC_KEY_PATH: Optional[str] = None
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_COOKIE_NAME: str = "cg_refresh_token"
    COOKIE_SECURE: bool = True
    COOKIE_SAMESITE: str = "strict"
    COOKIE_DOMAIN: str = ""

    # Public backend URL used in device enrollment responses (no hardcoded domains)
    BACKEND_PUBLIC_URL: str = "https://api.your-domain.com"

    # Directory containing the enrollment scripts (enroll.sh / enroll.ps1) used to
    # compute an integrity checksum shown in the install command. Optional.
    ENROLL_SCRIPTS_DIR: Optional[str] = None

    # CORS - explicit origins required
    ALLOWED_ORIGINS: List[str]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",")]
        return v

    # Stripe
    STRIPE_SECRET_KEY: SecretStr
    STRIPE_WEBHOOK_SECRET: SecretStr
    STRIPE_PRICE_STARTER: str
    STRIPE_PRICE_PRO: str
    STRIPE_PRICE_ENTERPRISE: str

    # LLM (Gemma via Ollama)
    GEMMA_API_URL: str = "http://localhost:11434"
    GEMMA_MODEL: str = "gemma3:12b"
    GEMMA_TIMEOUT: int = 120

    # S3 compatible storage
    S3_BUCKET: str
    S3_ENDPOINT: str
    S3_ACCESS_KEY: SecretStr
    S3_SECRET_KEY: SecretStr
    S3_REGION: str = "us-east-1"

    # Threat Intel
    ABUSEIPDB_API_KEY: SecretStr = SecretStr("")
    VIRUSTOTAL_API_KEY: SecretStr = SecretStr("")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    TELEMETRY_RATE_LIMIT: int = 300

    # HMAC secret for custody chain signatures
    CUSTODY_HMAC_KEY: SecretStr

    @field_validator("CUSTODY_HMAC_KEY")
    @classmethod
    def validate_custody_hmac_key(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value().encode()) < 32:
            raise ValueError("CUSTODY_HMAC_KEY must be at least 32 bytes long")
        return v

    @field_validator("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY", mode="before")
    @classmethod
    def _normalize_jwt_key(cls, v):
        # Allow empty string / None to fall through to PATH-based loading
        if v in (None, ""):
            return None
        return v

    @model_validator(mode="after")
    def _resolve_jwt_keys(self):
        """Resolve JWT keys from inline PEM content or from a PEM file path."""
        self.JWT_PRIVATE_KEY = self._load_pem(
            self.JWT_PRIVATE_KEY, self.JWT_PRIVATE_KEY_PATH, "JWT_PRIVATE_KEY"
        )
        self.JWT_PUBLIC_KEY = self._load_pem(
            self.JWT_PUBLIC_KEY, self.JWT_PUBLIC_KEY_PATH, "JWT_PUBLIC_KEY"
        )
        return self

    @staticmethod
    def _load_pem(content: Optional[SecretStr], path: Optional[str], field: str) -> Optional[SecretStr]:
        if content is not None:
            value = content.get_secret_value().strip()
            if not value.startswith("-----BEGIN"):
                raise ValueError(f"{field} must be a valid PEM key (starting with -----BEGIN)")
            return SecretStr(value)
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    value = f.read().strip()
            except OSError as e:
                raise ValueError(f"{field}_PATH points to an unreadable file: {path} ({e})")
            if not value.startswith("-----BEGIN"):
                raise ValueError(f"{field}_PATH does not contain a valid PEM key: {path}")
            return SecretStr(value)
        return None

    @field_validator("COOKIE_SAMESITE")
    @classmethod
    def validate_cookie_samesite(cls, v: str) -> str:
        normalized = v.lower().strip()
        if normalized not in {"strict", "lax", "none"}:
            raise ValueError("COOKIE_SAMESITE must be one of: strict, lax, none")
        return normalized

    @model_validator(mode="after")
    def validate_production_secrets(self):
        if self.ENVIRONMENT.lower() != "production":
            return self

        # All secrets must be provided via .env in production
        required_secrets = {
            "DATABASE_URL": self.DATABASE_URL,
            "REDIS_URL": self.REDIS_URL,
            "JWT_PRIVATE_KEY": self.JWT_PRIVATE_KEY,
            "JWT_PUBLIC_KEY": self.JWT_PUBLIC_KEY,
            "STRIPE_SECRET_KEY": self.STRIPE_SECRET_KEY,
            "STRIPE_WEBHOOK_SECRET": self.STRIPE_WEBHOOK_SECRET,
            "S3_ACCESS_KEY": self.S3_ACCESS_KEY,
            "S3_SECRET_KEY": self.S3_SECRET_KEY,
            "CUSTODY_HMAC_KEY": self.CUSTODY_HMAC_KEY,
        }

        for key, secret in required_secrets.items():
            value = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
            if not value:
                raise ValueError(f"{key} is required in production")

        return self


settings = Settings()