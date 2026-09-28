from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings


def make(**kwargs: object) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


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
    assert s.llm_provider == "fake"
    assert s.enable_ai is False
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
            jwt_secret="a-real-secret-0123456789",
            totp_enc_key="another-real-secret",
            s3_secret_key="real-minio-secret",
            database_url="postgresql+psycopg://dfir:strong@db:5432/dfirbench",
            custody_signing_key_path="/run/secrets/custody.key",
            custody_key_id="custody-2026-01",
            cors_origins=["*"],
        )


def test_prod_accepts_real_configuration() -> None:
    s = make(
        app_env="prod",
        jwt_secret="a-real-secret-0123456789",
        totp_enc_key="another-real-secret",
        s3_secret_key="real-minio-secret",
        database_url="postgresql+psycopg://dfir:strong@db:5432/dfirbench",
        custody_signing_key_path="/run/secrets/custody.key",
        custody_key_id="custody-2026-01",
        cors_origins=["https://dfir.example"],
    )
    assert s.is_prod


def test_get_settings_is_cached() -> None:
    assert get_settings() is get_settings()
