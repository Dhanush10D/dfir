from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # CI (and developer shells) export APP_ENV, DATABASE_URL, ...; these tests assert defaults.
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def make(**kwargs: object) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


# A complete production configuration (Phase 10: sandboxed parsers, app-role database login).
PROD: dict[str, object] = {
    "app_env": "prod",
    "jwt_secret": "a-real-secret-0123456789-abcdefghijkl",
    "totp_enc_key": "another-real-secret-0123456789-abcdef",
    "s3_secret_key": "real-minio-secret",
    "database_url": "postgresql+psycopg://dfirbench_app:strong-app-pass@db:5432/dfirbench",
    "database_app_role": "dfirbench_app",
    "custody_signing_key_path": "/run/secrets/custody.key",
    "custody_key_id": "custody-2026-01",
    "cors_origins": ["https://dfir.example"],
    "sandbox_mode": "spool",
    "sandbox_in_dir": "/var/lib/dfirbench/spool/in",
    "sandbox_out_dir": "/var/lib/dfirbench/spool/out",
}


def test_defaults_are_local_dev() -> None:
    s = make()
    assert s.app_env == "dev"
    assert s.database_url.startswith("postgresql+psycopg://")
    assert "127.0.0.1" in s.database_url
    assert s.vault_bucket == "evidence"
    assert s.vault_retention_days == 3650
    assert s.access_token_minutes == 15
    assert s.refresh_token_days == 7
    assert s.embedding_dim == 384
    assert s.llm_provider == "anthropic"
    assert s.llm_model_fast == "claude-haiku-4-5-20251001"
    assert s.llm_model_strong == "claude-sonnet-5-5"
    assert s.llm_api_key is None
    assert s.enable_ai is False
    assert s.embedding_provider == "hashing"
    assert s.is_prod is False


def test_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
    monkeypatch.setenv("REDIS_URL", "redis://r:6379/1")
    monkeypatch.setenv("VAULT_BUCKET", "vault")
    monkeypatch.setenv("MAX_UPLOAD_GB", "5")
    monkeypatch.setenv("ENABLE_AI", "true")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    s = make()
    assert s.database_url == "postgresql+psycopg://u:p@db:5432/x"
    assert s.redis_url == "redis://r:6379/1"
    assert s.vault_bucket == "vault"
    assert s.max_upload_gb == 5
    assert s.enable_ai is True
    assert s.log_level == "DEBUG"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://a.example, https://b.example", ["https://a.example", "https://b.example"]),
        ('["https://a.example"]', ["https://a.example"]),
        ("", []),
    ],
)
def test_cors_origins_parsing(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: list[str]
) -> None:
    monkeypatch.setenv("CORS_ORIGINS", raw)
    assert make().cors_origins == expected


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValidationError):
        make(log_level="LOUD")


def test_invalid_numbers_rejected() -> None:
    with pytest.raises(ValidationError):
        make(max_upload_gb=0)


def test_secrets_are_not_leaked_in_repr() -> None:
    s = make(s3_secret_key="super-secret-value")
    assert "super-secret-value" not in repr(s)


def test_prod_rejects_dev_placeholders() -> None:
    with pytest.raises(ValidationError) as exc:
        make(app_env="prod")
    msg = str(exc.value)
    assert "JWT_SECRET" in msg
    assert "TOTP_ENC_KEY" in msg
    assert "S3_SECRET_KEY" in msg
    assert "DATABASE_URL" in msg
    assert "CUSTODY_SIGNING_KEY_PATH" in msg


def test_prod_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        make(
            app_env="prod",
            jwt_secret="a-real-secret-0123456789-abcdefghijkl",
            totp_enc_key="another-real-secret-0123456789-abcdef",
            s3_secret_key="real-minio-secret",
            database_url="postgresql+psycopg://dfir:strong@db:5432/dfirbench",
            custody_signing_key_path="/run/secrets/custody.key",
            custody_key_id="custody-2026-01",
            cors_origins=["*"],
        )


def test_prod_accepts_real_configuration() -> None:
    s = make(**PROD)
    assert s.is_prod
    assert s.migrate_database_url == s.database_url
    s = make(**PROD, database_migrate_url="postgresql+psycopg://dfir:owner-pass@db/dfirbench")
    assert s.migrate_database_url.startswith("postgresql+psycopg://dfir:")
    assert "owner-pass" not in repr(s)


def test_prod_requires_the_parser_sandbox() -> None:
    with pytest.raises(ValidationError, match="SANDBOX_MODE must be 'spool'"):
        make(**{**PROD, "sandbox_mode": "none"})


def test_spool_mode_needs_two_distinct_spool_dirs() -> None:
    with pytest.raises(ValidationError, match="SANDBOX_IN_DIR and SANDBOX_OUT_DIR"):
        make(sandbox_mode="spool", sandbox_in_dir="/in")
    with pytest.raises(ValidationError, match="must differ"):
        make(sandbox_mode="spool", sandbox_in_dir="/x", sandbox_out_dir="/x")
    with pytest.raises(ValidationError):
        make(sandbox_mode="docker")  # the never-implemented placeholder values are gone
    assert make(sandbox_mode="spool", sandbox_in_dir="/i", sandbox_out_dir="/o").sandbox_mode


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"database_url": "postgresql+psycopg://dfir:strong@db:5432/dfirbench"},
            "must log in as DATABASE_APP_ROLE",
        ),
        ({"database_app_role": None}, "DATABASE_APP_ROLE must be set"),
        (
            {"database_url": "postgresql+psycopg://dfirbench_app:dfir_app_dev_password@db/x"},
            "placeholder password",
        ),
        ({"database_url": "postgresql+psycopg://dfirbench_app@db/x"}, "placeholder password"),
        ({"metrics_token": "short"}, "METRICS_TOKEN"),
        ({"metrics_token": "dev-only-metrics-token-change-me"}, "METRICS_TOKEN"),
    ],
)
def test_prod_refuses_owner_logins_and_weak_values(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        make(**{**PROD, **overrides})
    assert make(**{**PROD, "metrics_token": "m" * 40}).metrics_token is not None


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()


def test_prod_rejects_short_secrets() -> None:
    with pytest.raises(ValidationError) as exc:
        make(
            app_env="prod",
            jwt_secret="short-but-not-placeholder",
            totp_enc_key="also-short-secret",
            s3_secret_key="real-minio-secret",
            database_url="postgresql+psycopg://dfir:strong@db:5432/dfirbench",
            custody_signing_key_path="/run/secrets/custody.key",
            custody_key_id="custody-2026-01",
            cors_origins=["https://dfir.example"],
        )
    msg = str(exc.value)
    assert "JWT_SECRET must be at least 32" in msg
    assert "TOTP_ENC_KEY must be at least 32" in msg


def test_phase1_defaults() -> None:
    s = make()
    assert s.database_app_role is None
    assert s.access_token_minutes == 15
    assert s.refresh_token_days == 7
    assert s.password_min_length == 12
    assert s.login_lockout_threshold == 5
    assert s.max_upload_bytes == 20 * 1024**3
    assert s.auditor_all_cases is True


def test_upload_limit_must_fit_s3_part_count() -> None:
    assert make(max_upload_gb=78, upload_part_size_mb=8).max_upload_gb == 78  # 9,984 parts
    with pytest.raises(ValidationError, match="UPLOAD_PART_SIZE_MB to at least 11"):
        make(max_upload_gb=100, upload_part_size_mb=8)
    assert make(max_upload_gb=100, upload_part_size_mb=11).upload_part_size_mb == 11


def test_embedding_dim_must_match_schema() -> None:
    with pytest.raises(ValidationError, match="needs a migration"):
        make(embedding_dim=768)
    with pytest.raises(ValidationError, match="hashing-v1"):
        make(embedding_model="bge-small")
    assert make(embedding_provider="ollama", embedding_model="all-minilm").embedding_dim == 384


def test_ai_limits_validated() -> None:
    with pytest.raises(ValidationError):
        make(ai_max_tokens=10)
    with pytest.raises(ValidationError):
        make(ai_redaction_policy="loose")
    with pytest.raises(ValidationError):
        make(llm_effort="extreme")


def test_llm_api_key_not_in_repr() -> None:
    s = make(llm_api_key="sk-ant-very-secret")
    assert "sk-ant-very-secret" not in repr(s)
    assert "sk-ant-very-secret" not in str(s.model_dump())


def test_prod_refuses_fake_llm_provider() -> None:
    real = dict(PROD)
    with pytest.raises(ValidationError, match="LLM_PROVIDER=fake"):
        make(**real, enable_ai=True, llm_provider="fake")
    assert make(**real, enable_ai=True, llm_provider="anthropic").enable_ai
