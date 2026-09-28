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
