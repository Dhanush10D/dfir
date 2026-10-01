"""PostgreSQL fixtures for integration tests.

Uses TEST_DATABASE_URL, or the compose Postgres (DATABASE_URL / 127.0.0.1:5432) by default. Each
test session creates a throwaway database, migrates it with Alembic, and drops it afterwards, so
the dev database is never touched. If the server is unreachable every test here is skipped.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from app.config import Settings

BACKEND = Path(__file__).resolve().parents[2]


def _server_url() -> str:
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return explicit
    return Settings(_env_file=None).database_url  # type: ignore[call-arg]


def alembic_config(db_url: str) -> Config:
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.attributes["db_url"] = db_url
    cfg.attributes["configure_logger"] = False
    return cfg


def _admin_engine() -> Engine:
    url = make_url(_server_url()).set(database="postgres")
    return create_engine(
        url,
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 3},
        pool_pre_ping=True,
    )


@pytest.fixture(scope="session")
def admin_engine() -> Iterator[Engine]:
    engine = _admin_engine()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        engine.dispose()
        pytest.skip(
            "PostgreSQL not reachable (start it with "
            "`docker compose -f infra/compose.yaml up -d postgres` or set TEST_DATABASE_URL): "
            f"{type(exc).__name__}"
        )
    yield engine
    engine.dispose()


def create_temp_database(admin: Engine) -> str:
    name = f"dfirbench_test_{uuid.uuid4().hex[:10]}"
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    return make_url(_server_url()).set(database=name).render_as_string(hide_password=False)


def drop_temp_database(admin: Engine, db_url: str) -> None:
    name = make_url(db_url).database
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@pytest.fixture(scope="session")
def migrated_db_url(admin_engine: Engine) -> Iterator[str]:
    db_url = create_temp_database(admin_engine)
    try:
        command.upgrade(alembic_config(db_url), "head")
        yield db_url
    finally:
        drop_temp_database(admin_engine, db_url)


@pytest.fixture(scope="session")
def db_engine(migrated_db_url: str) -> Iterator[Engine]:
    engine = create_engine(
        migrated_db_url, connect_args={"options": "-c timezone=UTC", "connect_timeout": 5}
    )
    yield engine
    engine.dispose()


# ---------------------------------------------------------------------------------------------
# Phase 1: application-level fixtures (least-privilege engine, API client, users, fake vault)
# ---------------------------------------------------------------------------------------------

APP_ROLE = "dfirbench_app"


def make_test_settings(db_url: str, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "database_url": db_url,
        "database_app_role": APP_ROLE,
        # Cheap Argon2 for tests (production defaults are asserted in unit tests).
        "argon2_time_cost": 1,
        "argon2_memory_kib": 1024,
        "argon2_parallelism": 1,
        "jwt_secret": "integration-test-jwt-secret-0123456789",
        "totp_enc_key": "integration-test-totp-key-0123456789",
        "log_json": True,
        "upload_part_size_mb": 5,
        # AI on with the offline provider: explicit values, so CI/shell env vars cannot change them.
        "enable_ai": True,
        "llm_provider": "fake",
        "ai_local_only": False,
        "ai_redaction_policy": "standard",
        # Phase 9: explicit values too. A test KEK (outside the DB), the strict outbound policy,
        # enrichment on with the offline fake provider, no public links.
        "integration_kek": "integration-test-kek-0123456789abcdef",
        "integration_kek_path": None,
        "integration_kek_id": "test-kek-1",
        "integration_kek_previous_path": None,
        "outbound_allow_http": False,
        "outbound_allow_hosts": [],
        "outbound_max_attempts": 3,
        "outbound_backoff_base_s": 30,
        "public_base_url": None,
        "notify_dedup_window_s": 900,
        "notify_rate_limit_per_hour": 30,
        "webhook_rate_limit_per_hour": 1000,
        "ingest_max_body_kb": 64,
        "ingest_max_items": 50,
        "ingest_timestamp_window_s": 300,
        "ingest_rate_limit_per_minute": 1000,
        "approval_ttl_minutes": 60,
        "enable_enrichment": True,
        "enrichment_fake": True,
        "enrichment_cache_ttl_h": 24,
        "enrichment_max_per_request": 20,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def app_engine(migrated_db_url: str) -> Iterator[Engine]:
    """Engine whose sessions run as the least-privilege app role (like the API in compose)."""
    from app.db.session import make_engine

    engine = make_engine(migrated_db_url, role=APP_ROLE)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def test_settings(migrated_db_url: str) -> Settings:
    return make_test_settings(migrated_db_url)


@pytest.fixture(scope="session")
def signer() -> object:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from app.core.signing import CustodySigner

    return CustodySigner(key_id="test-custody-1", private_key=Ed25519PrivateKey.generate())


@pytest.fixture
def vault() -> object:
    from tests.fakes import FakeVault

    return FakeVault()


@pytest.fixture
def h(
    app_engine: Engine, test_settings: Settings, signer: object, vault: object
) -> Iterator[object]:
    """API harness on the migrated test database (fake vault, test custody signer)."""
    from tests.integration.harness import Harness

    harness = Harness(app_engine, test_settings, signer, vault)  # type: ignore[arg-type]
    with harness.client:
        yield harness
