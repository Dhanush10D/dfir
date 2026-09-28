from __future__ import annotations

from typing import Any

import pytest
from minio.commonconfig import COMPLIANCE, GOVERNANCE
from minio.error import S3Error
from minio.objectlockconfig import DAYS, ObjectLockConfig

from app.config import Settings
from app.storage import VaultNotWormError, ensure_buckets, get_object_lock, make_minio_client


def not_found() -> S3Error:
    return S3Error(None, "ObjectLockConfigurationNotFoundError", "m", "/", "r", "h")  # type: ignore[arg-type]


class RecordingMinio:
    """In-memory stand-in: ``locks`` maps a bucket to its lock config (absent = no Object Lock)."""

    def __init__(
        self, existing: set[str], locks: dict[str, ObjectLockConfig] | None = None
    ) -> None:
        self.existing = set(existing)
        self.locks = dict(locks or {})
        self.calls: list[tuple[str, Any]] = []

    def bucket_exists(self, name: str) -> bool:
        return name in self.existing

    def make_bucket(self, name: str, object_lock: bool = False) -> None:
        self.calls.append(("make_bucket", (name, object_lock)))
        self.existing.add(name)
        if object_lock:
            self.locks[name] = ObjectLockConfig(None, None, None)

    def get_object_lock_config(self, name: str) -> ObjectLockConfig:
        if name not in self.locks:
            raise not_found()
        return self.locks[name]

    def set_object_lock_config(self, name: str, config: Any) -> None:
        self.calls.append(("lock", (name, config)))
        self.locks[name] = config


WORM = ObjectLockConfig(COMPLIANCE, 3650, DAYS)


def test_ensure_buckets_creates_worm_vault(settings: Settings) -> None:
    client = RecordingMinio(set())
    created = ensure_buckets(client, settings)  # type: ignore[arg-type]
    assert created == ["evidence", "artifacts"]
    assert ("make_bucket", ("evidence", True)) in client.calls
    assert ("make_bucket", ("artifacts", False)) in client.calls
    lock = next(c for c in client.calls if c[0] == "lock")
    name, config = lock[1]
    assert name == "evidence"
    assert config.mode == COMPLIANCE
    assert config.duration == 3650
    assert config.duration_unit == DAYS


def test_ensure_buckets_is_idempotent(settings: Settings) -> None:
    client = RecordingMinio({"evidence", "artifacts"}, {"evidence": WORM})
    assert ensure_buckets(client, settings) == []  # type: ignore[arg-type]
    assert client.calls == []


def test_ensure_buckets_reapplies_missing_retention(settings: Settings) -> None:
    # A previous init created the locked bucket but died before setting default retention.
    client = RecordingMinio(
        {"evidence", "artifacts"}, {"evidence": ObjectLockConfig(None, None, None)}
    )
    assert ensure_buckets(client, settings) == []  # type: ignore[arg-type]
    assert client.locks["evidence"].mode == COMPLIANCE
    assert client.locks["evidence"].duration == 3650


def test_ensure_buckets_replaces_weaker_retention(settings: Settings) -> None:
    weak = ObjectLockConfig(GOVERNANCE, 1, DAYS)
    client = RecordingMinio({"evidence", "artifacts"}, {"evidence": weak})
    ensure_buckets(client, settings)  # type: ignore[arg-type]
    assert client.locks["evidence"].mode == COMPLIANCE


def test_ensure_buckets_rejects_vault_without_object_lock(settings: Settings) -> None:
    client = RecordingMinio({"evidence"})
    with pytest.raises(VaultNotWormError):
        ensure_buckets(client, settings)  # type: ignore[arg-type]
    assert client.calls == []


def test_ensure_buckets_no_retention_leaves_lock_default(settings: Settings) -> None:
    client = RecordingMinio(set())
    ensure_buckets(client, settings, set_retention=False)  # type: ignore[arg-type]
    assert not any(c[0] == "lock" for c in client.calls)


def test_get_object_lock_propagates_other_errors() -> None:
    class Broken(RecordingMinio):
        def get_object_lock_config(self, name: str) -> ObjectLockConfig:
            raise S3Error(None, "AccessDenied", "m", "/", "r", "h")  # type: ignore[arg-type]

    assert get_object_lock(RecordingMinio(set()), "evidence") is None  # type: ignore[arg-type]
    with pytest.raises(S3Error):
        get_object_lock(Broken(set()), "evidence")  # type: ignore[arg-type]


def test_make_minio_client(settings: Settings) -> None:
    client = make_minio_client(settings)
    assert client is not None
