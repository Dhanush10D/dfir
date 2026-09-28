"""FastAPI dependency providers. Tests override these via ``app.dependency_overrides``."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import lru_cache

from minio import Minio
from redis import Redis
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db.session import get_engine, get_sessionmaker
from app.services.health import (
    CheckResult,
    check_database,
    check_redis,
    check_storage,
)
from app.storage import make_minio_client


def get_app_settings() -> Settings:
    return get_settings()


def get_db() -> Iterator[Session]:
    """One session per request; services own commit/rollback boundaries."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def get_db_engine() -> Engine:
    return get_engine()


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    settings = get_settings()
    timeout = settings.ready_timeout_s
    client: Redis = Redis.from_url(
        settings.redis_url, socket_connect_timeout=timeout, socket_timeout=timeout
    )
    return client


@lru_cache(maxsize=1)
def get_storage() -> Minio:
    settings = get_settings()
    return make_minio_client(settings, timeout_s=settings.ready_timeout_s, retries=0)


def get_readiness_checks() -> list[Callable[[], CheckResult]]:
    """The dependency checks behind ``/ready``; overridden in unit tests with fakes."""
    settings = get_settings()
    return [
        lambda: check_database(get_engine()),
        lambda: check_redis(get_redis()),
        lambda: check_storage(get_storage(), settings.vault_bucket),
    ]
