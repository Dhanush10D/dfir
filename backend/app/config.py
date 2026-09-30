"""Application configuration (pydantic-settings).

Every value comes from an environment variable (guide Appendix C). Dev and test profiles have
safe local defaults; the ``prod`` profile fails fast on missing or placeholder secrets.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

S3_MAX_PARTS = 10_000

AppEnv = Literal["dev", "test", "prod"]
SandboxMode = Literal["docker", "k8s", "none"]
LLMProvider = Literal["anthropic", "ollama", "openai_compat", "fake"]
EmbeddingProvider = Literal["hashing", "ollama", "openai_compat"]
RedactionPolicy = Literal["none", "standard", "strict"]
# event_chunks.embedding is vector(384) (migrations 0001/0009); another size needs a migration.
SCHEMA_EMBEDDING_DIM = 384

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
    # Least-privilege role every app session runs as (SET ROLE at connect). Created by migration
    # 0002 with no UPDATE/DELETE/TRUNCATE on custody_log/audit_log. None = connect as the login.
    database_app_role: str | None = None
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

    # Auth (guide 16)
    jwt_secret: SecretStr | None = SecretStr("dev-only-jwt-secret-change-me")
    jwt_private_key_path: str | None = None  # Ed25519 PEM -> EdDSA tokens instead of HS256
    jwt_key_id: str = "jwt-1"
    jwt_issuer: str = "dfirbench"
    access_token_minutes: int = Field(default=15, ge=1, le=60)
    refresh_token_days: int = Field(default=7, ge=1)
    session_absolute_days: int = Field(default=30, ge=1)
    mfa_challenge_minutes: int = Field(default=5, ge=1, le=15)
    totp_enc_key: SecretStr | None = SecretStr("dev-only-totp-key-change-me")
    totp_issuer: str = "dfirbench"
    password_min_length: int = Field(default=12, ge=8)
    # Argon2id cost (argon2-cffi RFC 9106 low-memory profile by default).
    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_kib: int = Field(default=65536, ge=8)
    argon2_parallelism: int = Field(default=4, ge=1)
    # Exponential lockout: after `threshold` consecutive failures, lock for base * 2^(n-threshold)
    # seconds, capped at max.
    login_lockout_threshold: int = Field(default=5, ge=1)
    login_lockout_base_s: int = Field(default=60, ge=1)
    login_lockout_max_s: int = Field(default=3600, ge=1)
    auditor_all_cases: bool = True  # auditors may read every case without membership (16.1)
    audit_http_requests: bool = True  # AuditMiddleware writes one audit_log row per API request

    # Custody signing (guide 8.3, 20.3)
    custody_signing_key_path: str | None = None
    custody_signing_key_passphrase: SecretStr | None = None
    custody_key_id: str | None = None  # default: derived from the public key fingerprint
    # JSON {key_id: public key PEM} of retired/other trusted custody keys. Verification trusts ONLY
    # these plus the running signer, never whatever is in the signing_keys table.
    custody_trusted_keys_path: str | None = None

    # Upload / processing limits
    max_upload_gb: int = Field(default=20, ge=1)
    upload_part_size_mb: int = Field(default=8, ge=5, le=512)  # S3 multipart part (memory bound)
    parser_timeout_s: int = Field(default=3600, ge=1)
    parser_max_output_mb: int = Field(default=2048, ge=1)
    sandbox_mode: SandboxMode = "none"

    # Processing pipeline (Phase 2, guide 10.6)
    # Per-job scratch directories are created (0700) under this root and removed afterwards.
    # None = <system temp>/dfirbench-scratch. The worker container mounts a volume here.
    scratch_dir: str | None = None
    ingest_batch_size: int = Field(default=1000, ge=1, le=1500)  # events per INSERT/transaction
    ingest_flush_interval_s: float = Field(default=5.0, gt=0)  # heartbeat/cancel check cadence
    job_lease_s: int = Field(default=900, ge=30)  # a running job without heartbeat is reclaimable
    job_max_auto_retries: int = Field(default=3, ge=0, le=10)  # transient errors only
    parser_max_line_kb: int = Field(default=64, ge=1, le=4096)  # longer lines are counted errors
    parser_max_decompressed_mb: int = Field(default=4096, ge=1)  # gz bomb guard (absolute)
    parser_max_decompression_ratio: int = Field(default=200, ge=2)  # gz bomb guard (ratio)
    max_new_partitions_per_job: int = Field(default=48, ge=1)  # hostile timestamps -> default

    # Detection (Phase 3, guide 11)
    detect_after_parse: bool = True  # queue a case detection run when a parse job ends ok/partial
    detect_batch_size: int = Field(default=2000, ge=100, le=20000)  # events per fetch/heartbeat
    detect_max_alerts: int = Field(default=20000, ge=1, le=1_000_000)  # drafts per run
    detect_max_links_per_alert: int = Field(default=500, ge=1, le=100_000)  # alert_events rows

    # Analysis (Phase 4, guide 12)
    search_timeout_ms: int = Field(default=15000, ge=100, le=120000)  # per search/facet/histogram
    export_max_rows: int = Field(default=10000, ge=1, le=100000)
    entity_resolution: bool = True  # detection runs also resolve entities (guide 12.3)
    # Browser refresh-token cookie (HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth).
    # Browsers accept Secure cookies from http://localhost; set false only for plain-HTTP dev hosts.
    auth_cookie_secure: bool = True
    auth_cookie_name: str = Field(default="dfir_refresh", pattern=r"^[A-Za-z0-9_\-]{1,64}$")

    # Collection (Phase 5, guide 9): triage bundle ingest limits (hostile archives)
    bundle_max_members: int = Field(default=10000, ge=1, le=100000)
    bundle_max_total_mb: int = Field(default=4096, ge=1)  # declared AND actually extracted bytes
    bundle_max_member_mb: int = Field(default=2048, ge=1)
    bundle_max_ratio: int = Field(default=200, ge=2)  # per member and archive, above 1 MiB
    bundle_max_derived: int = Field(default=500, ge=1, le=10000)  # derived evidence per run
    # Extra trusted collector hashes (JSON, same format as app/collection/trusted_collectors.json);
    # a trust anchor: keep it on a read-only mount.
    collector_trusted_hashes_path: str | None = None

    # Deep parsers (Phase 6, guide 10.3): external engines, structured formats, YARA
    # Engine lookup path (os.pathsep-separated); unset = PATH. Engines get a clean environment.
    tool_search_path: str | None = None
    tool_timeout_s: int = Field(default=3600, ge=1)
    tool_max_output_mb: int = Field(default=1024, ge=1)
    parser_max_structured_mb: int = Field(default=1024, ge=1)  # hives, SQLite, PE (random access)
    parser_max_records: int = Field(default=5_000_000, ge=1)
    parser_sqlite_timeout_s: int = Field(default=600, ge=1)
    # Extra trusted YARA rule directory (read-only mount); the packaged pack is always loaded.
    yara_rules_dir: str | None = None
    yara_timeout_s: int = Field(default=600, ge=1)
    yara_max_file_mb: int = Field(default=2048, ge=1)
    # Volatility 3 symbol tables (ISF packs); unset = none (Volatility runs with --offline).
    volatility_symbols_dir: str | None = None

    # AI (Phase 7, guide 13). Model ids are configuration; the key is a secret (never logged).
    enable_ai: bool = False
    ai_local_only: bool = False  # refuse hosted providers
    llm_provider: LLMProvider = "anthropic"
    llm_base_url: str | None = None  # anthropic: API default; ollama/openai_compat: required
    llm_api_key: SecretStr | None = None
    llm_model_fast: str = Field(default="claude-haiku-4-5-20251001", min_length=1, max_length=128)
    llm_model_strong: str = Field(default="claude-sonnet-5-5", min_length=1, max_length=128)
    llm_timeout_s: float = Field(default=120.0, gt=0, le=900)  # per attempt
    llm_max_retries: int = Field(default=1, ge=0, le=3)  # transient errors, inside one deadline
    llm_effort: Literal["low", "medium", "high", "xhigh", "max"] | None = None  # Anthropic only
    llm_anthropic_fallbacks: bool = True  # server-side refusal fallback where supported
    llm_price_input_per_mtok: float | None = Field(default=None, ge=0)  # USD, for cost_usd
    llm_price_output_per_mtok: float | None = Field(default=None, ge=0)
    ai_redaction_policy: RedactionPolicy = "standard"
    ai_redact_local: bool = False  # also redact for local providers (ollama, local endpoints)
    ai_max_tokens: int = Field(default=8000, ge=256, le=64000)  # output cap per call
    ai_max_input_chars: int = Field(default=120_000, ge=1000, le=2_000_000)  # rendered prompt
    ai_max_field_chars: int = Field(default=512, ge=32, le=8192)  # per evidence field
    ai_max_pack_records: int = Field(default=150, ge=1, le=1000)
    ai_rate_limit_per_minute: int = Field(default=10, ge=1)  # per user
    ai_case_rate_limit_per_hour: int = Field(default=200, ge=1)  # per case
    ai_daily_token_budget: int = Field(default=2_000_000, ge=1)  # all calls, UTC day
    ai_daily_budget_usd: float = Field(default=10.0, ge=0)  # enforced when prices are set
    embedding_provider: EmbeddingProvider = "hashing"
    embedding_model: str = Field(default="hashing-v1", min_length=1, max_length=128)
    embedding_dim: int = Field(default=384, ge=1)
    embedding_base_url: str | None = None  # ollama / openai_compat embeddings endpoint
    embedding_api_key: SecretStr | None = None
    ai_index_max_events: int = Field(default=200_000, ge=1)
    ai_chat_top_k: int = Field(default=8, ge=1, le=50)
    ai_chat_max_events: int = Field(default=120, ge=1, le=1000)

    # Reporting (Phase 8, guide 18): snapshot caps and the organisation shown in reports/STIX
    report_max_key_events: int = Field(default=500, ge=1, le=10_000)
    report_max_alerts: int = Field(default=500, ge=1, le=10_000)
    report_max_iocs: int = Field(default=1000, ge=1, le=100_000)
    report_max_context_mb: int = Field(default=8, ge=1, le=64)
    report_org_name: str = Field(default="dfirbench", min_length=1, max_length=200)
    # Rendering is synchronous: one render (sign, verify, draft download) gets this budget; keep it
    # below the web proxy's 300 s read timeout.
    report_render_timeout_s: int = Field(default=120, ge=5, le=280)

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
    def _upload_parts_fit(self) -> Settings:
        # S3 multipart allows at most 10,000 parts: MAX_UPLOAD_GB must fit in that many parts.
        part = self.upload_part_size_mb * 1024 * 1024
        parts = -(-self.max_upload_bytes // part)
        if parts > S3_MAX_PARTS:
            needed = -(-self.max_upload_bytes // S3_MAX_PARTS // (1024 * 1024))
            raise ValueError(
                f"MAX_UPLOAD_GB={self.max_upload_gb} needs {parts} parts of "
                f"UPLOAD_PART_SIZE_MB={self.upload_part_size_mb} (S3 limit {S3_MAX_PARTS}); "
                f"raise UPLOAD_PART_SIZE_MB to at least {needed}"
            )
        return self

    @model_validator(mode="after")
    def _ai_consistent(self) -> Settings:
        if self.embedding_dim != SCHEMA_EMBEDDING_DIM:
            raise ValueError(
                f"EMBEDDING_DIM={self.embedding_dim} does not match the event_chunks.embedding "
                f"column (vector({SCHEMA_EMBEDDING_DIM})); another size needs a migration"
            )
        if self.embedding_provider == "hashing" and self.embedding_model != "hashing-v1":
            raise ValueError("EMBEDDING_PROVIDER=hashing only provides EMBEDDING_MODEL=hashing-v1")
        return self

    @model_validator(mode="after")
    def _prod_fail_fast(self) -> Settings:
        if self.app_env != "prod":
            return self
        problems: list[str] = []

        def placeholder(secret: SecretStr | None) -> bool:
            return secret is None or secret.get_secret_value().strip().lower() in DEV_PLACEHOLDERS

        if placeholder(self.jwt_secret) and not self.jwt_private_key_path:
            problems.append("JWT_SECRET or JWT_PRIVATE_KEY_PATH must be set")
        if (
            not self.jwt_private_key_path
            and self.jwt_secret is not None
            and len(self.jwt_secret.get_secret_value()) < 32
        ):
            problems.append("JWT_SECRET must be at least 32 characters")
        if placeholder(self.totp_enc_key):
            problems.append("TOTP_ENC_KEY must be set")
        elif self.totp_enc_key is not None and len(self.totp_enc_key.get_secret_value()) < 32:
            problems.append("TOTP_ENC_KEY must be at least 32 characters")
        if placeholder(self.s3_secret_key):
            problems.append("S3_SECRET_KEY must be set")
        if "dfir_dev_password" in self.database_url:
            problems.append("DATABASE_URL uses the dev password")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must not contain '*' in prod")
        if not self.custody_signing_key_path or not self.custody_key_id:
            problems.append("CUSTODY_SIGNING_KEY_PATH and CUSTODY_KEY_ID must be set")
        if self.enable_ai and self.llm_provider == "fake":
            problems.append("LLM_PROVIDER=fake is for tests and demos only")
        if problems:
            raise ValueError("invalid prod configuration: " + "; ".join(problems))
        return self

    @property
    def is_prod(self) -> bool:
        return self.app_env == "prod"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_gb * 1024**3


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings instance (cached). Tests call ``get_settings.cache_clear()``."""
    return Settings()
