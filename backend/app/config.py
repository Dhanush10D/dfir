"""Application configuration (pydantic-settings).

Every value comes from an environment variable (guide Appendix C). Dev and test profiles have
safe local defaults; the ``prod`` profile fails fast on missing or placeholder secrets.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

AppEnv = Literal["dev", "test", "prod"]
SandboxMode = Literal["docker", "k8s", "none"]
LLMProvider = Literal["anthropic", "ollama", "openai_compat", "fake"]

# Values shipped in .env.example / compose defaults. Refused when APP_ENV=prod.
DEV_PLACEHOLDERS = frozenset(
    {
        "",
        "changeme",
        "change-me",
        "dfir_dev_password",
        "minio_dev_password",
        "dev-only-jwt-secret-change-me",
        "dev-only-totp-key-change-me",
    }
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Core
    app_env: AppEnv = "dev"
    log_level: str = "INFO"
    log_json: bool = True
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://localhost:8080"]
    )

    # Stores
    database_url: str = "postgresql+psycopg://dfir:dfir_dev_password@127.0.0.1:5432/dfirbench"
    redis_url: str = "redis://127.0.0.1:6379/0"
    enable_opensearch: bool = False
    opensearch_url: str | None = None

    # Evidence vault (MinIO / S3)
    s3_endpoint: str = "127.0.0.1:9000"
    s3_access_key: str = "dfir"
    s3_secret_key: SecretStr = SecretStr("minio_dev_password")
    s3_secure: bool = False
    s3_region: str | None = None
    vault_bucket: str = "evidence"
    artifacts_bucket: str = "artifacts"
    vault_retention_days: int = Field(default=3650, ge=1)

    # Auth (used from Phase 1)
    jwt_secret: SecretStr | None = SecretStr("dev-only-jwt-secret-change-me")
    jwt_private_key_path: str | None = None
    access_token_minutes: int = Field(default=15, ge=1)
    refresh_token_days: int = Field(default=7, ge=1)
    totp_enc_key: SecretStr | None = SecretStr("dev-only-totp-key-change-me")

    # Custody signing (Phase 1)
    custody_signing_key_path: str | None = None
    custody_key_id: str | None = None

    # Upload / processing limits
    max_upload_gb: int = Field(default=20, ge=1)
    parser_timeout_s: int = Field(default=3600, ge=1)
    parser_max_output_mb: int = Field(default=2048, ge=1)
    sandbox_mode: SandboxMode = "none"

    # AI (Phase 7)
    enable_ai: bool = False
    ai_local_only: bool = False
    llm_provider: LLMProvider = "fake"
    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model_fast: str | None = None
    llm_model_strong: str | None = None
    ai_redaction_policy: str = "standard"
    ai_max_tokens: int = Field(default=2000, ge=1)
    ai_daily_budget_usd: float = Field(default=10.0, ge=0)
    embedding_model: str | None = None
    embedding_dim: int = Field(default=384, ge=1)

    # Integrations (Phase 9)
    vt_api_key: SecretStr | None = None
    misp_url: str | None = None
    misp_key: SecretStr | None = None
    slack_webhook_url: SecretStr | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None

    # Readiness probe
    ready_timeout_s: float = Field(default=2.0, gt=0)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("["):
                import json

                return json.loads(text)
            return [part.strip() for part in text.split(",") if part.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        level = value.upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid LOG_LEVEL {value!r}")
        return level

    @model_validator(mode="after")
    def _prod_fail_fast(self) -> Settings:
        if self.app_env != "prod":
            return self
        problems: list[str] = []

        def placeholder(secret: SecretStr | None) -> bool:
            return secret is None or secret.get_secret_value().strip().lower() in DEV_PLACEHOLDERS

        if placeholder(self.jwt_secret) and not self.jwt_private_key_path:
            problems.append("JWT_SECRET or JWT_PRIVATE_KEY_PATH must be set")
        if placeholder(self.totp_enc_key):
            problems.append("TOTP_ENC_KEY must be set")
        if placeholder(self.s3_secret_key):
            problems.append("S3_SECRET_KEY must be set")
        if "dfir_dev_password" in self.database_url:
            problems.append("DATABASE_URL uses the dev password")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must not contain '*' in prod")
        if not self.custody_signing_key_path or not self.custody_key_id:
            problems.append("CUSTODY_SIGNING_KEY_PATH and CUSTODY_KEY_ID must be set")
        if problems:
            raise ValueError("invalid prod configuration: " + "; ".join(problems))
        return self

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings instance (cached). Tests call ``get_settings.cache_clear()``."""
    return Settings()
