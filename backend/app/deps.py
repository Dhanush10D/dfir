"""FastAPI dependency providers. Tests override these via ``app.dependency_overrides``."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from functools import lru_cache

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from minio import Minio
from redis import Redis
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.signing import CustodySigner, SigningKeyError, load_signer, load_trusted_keys
from app.db.session import get_engine, get_sessionmaker
from app.repositories.vault import MinioVault, VaultStore
from app.services.audit import DbAuditSink
from app.services.health import (
    CheckResult,
    check_database,
    check_redis,
    check_storage,
)
from app.storage import make_minio_client

log = structlog.stdlib.get_logger("dfirbench.deps")


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


@lru_cache(maxsize=1)
def get_vault_client() -> Minio:
    """Client for evidence transfers: generous timeouts (a part may take a while), few retries."""
    return make_minio_client(get_settings(), timeout_s=120.0, retries=2)


def get_vault() -> VaultStore | None:
    return MinioVault(get_vault_client(), get_settings().vault_bucket)


@lru_cache(maxsize=1)
def get_custody_signer() -> CustodySigner | None:
    """The Ed25519 custody signer, or None (reads still work; writes answer 503)."""
    try:
        return load_signer(get_settings())
    except SigningKeyError as exc:
        log.warning("custody_signer_unavailable", reason=str(exc))
        return None


@lru_cache(maxsize=1)
def get_trusted_keys() -> dict[str, Ed25519PublicKey]:
    """Extra trusted custody keys from CUSTODY_TRUSTED_KEYS_PATH (the signer is added per use)."""
    try:
        return load_trusted_keys(get_settings())
    except SigningKeyError as exc:
        log.error("custody_trusted_keys_unreadable", reason=str(exc))
        return {}


def get_audit_sink() -> DbAuditSink:
    return DbAuditSink(get_sessionmaker())


def get_job_dispatcher() -> Callable[[uuid.UUID], None]:
    """Enqueues parse jobs on the Celery ``parse`` queue (tests override it)."""
    from app.workers.dispatch import dispatch_parse

    return dispatch_parse


def get_detect_dispatcher() -> Callable[[uuid.UUID], None]:
    """Enqueues detection jobs on the Celery ``detect`` queue (tests override it)."""
    from app.workers.dispatch import dispatch_detect

    return dispatch_detect
