"""MinIO / S3 client construction and bucket bootstrap for the evidence vault."""

from __future__ import annotations

import argparse

import structlog
import urllib3
from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.error import S3Error
from minio.objectlockconfig import DAYS, ObjectLockConfig

from app.config import Settings, get_settings

log = structlog.stdlib.get_logger("dfirbench.storage")


def make_minio_client(settings: Settings, *, timeout_s: float = 10.0, retries: int = 2) -> Minio:
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=timeout_s, read=timeout_s),
        retries=urllib3.Retry(total=retries, backoff_factor=0.2),
    )
    return Minio(
        settings.s3_endpoint,
        access_key=settings.s3_access_key,
        secret_key=settings.s3_secret_key.get_secret_value(),
        secure=settings.s3_secure,
        region=settings.s3_region,
        http_client=http,
    )


class VaultNotWormError(RuntimeError):
    """The vault bucket exists but was created without Object Lock (cannot be enabled later)."""


def get_object_lock(client: Minio, bucket: str) -> ObjectLockConfig | None:
    """The bucket's Object Lock configuration, or ``None`` if Object Lock is not enabled.

    A config whose ``mode`` is ``None`` means Object Lock is enabled without default retention.
    """
    try:
        return client.get_object_lock_config(bucket)
    except S3Error as exc:
        if exc.code == "ObjectLockConfigurationNotFoundError":
            return None
        raise


def ensure_buckets(client: Minio, settings: Settings, *, set_retention: bool = True) -> list[str]:
    """Create the vault bucket (Object Lock enabled, WORM) and the artifacts bucket if missing.

    Object Lock can only be enabled at bucket creation, so an existing vault without it is a hard
    error. Default retention (COMPLIANCE for ``VAULT_RETENTION_DAYS``) is re-checked on each run and
    re-applied if absent or different, so a partial earlier init cannot leave originals unprotected.
    """
    created: list[str] = []
    vault = settings.vault_bucket
    if not client.bucket_exists(vault):
        client.make_bucket(vault, object_lock=True)
        created.append(vault)
    lock = get_object_lock(client, vault)
    if lock is None:
        raise VaultNotWormError(f"bucket {vault!r} exists without Object Lock; recreate it")
    if set_retention:
        wanted = (COMPLIANCE, settings.vault_retention_days, DAYS)
        if (lock.mode, lock.duration, lock.duration_unit) != wanted:
            client.set_object_lock_config(vault, ObjectLockConfig(*wanted))
            log.info("vault_retention_applied", bucket=vault, days=settings.vault_retention_days)
    if not client.bucket_exists(settings.artifacts_bucket):
        client.make_bucket(settings.artifacts_bucket)
        created.append(settings.artifacts_bucket)
    return created


def main(argv: list[str] | None = None) -> int:
    """``python -m app.storage init``: idempotent bucket bootstrap (compose init job)."""
    parser = argparse.ArgumentParser(prog="python -m app.storage")
    parser.add_argument("command", choices=["init"])
    parser.add_argument("--no-retention", action="store_true", help="skip default WORM retention")
    args = parser.parse_args(argv)
    from app.core.logging import setup_logging

    settings = get_settings()
    setup_logging(settings.log_level, settings.log_json)
    client = make_minio_client(settings, retries=5)
    created = ensure_buckets(client, settings, set_retention=not args.no_retention)
    log.info("storage_init_done", created=created, vault=settings.vault_bucket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
