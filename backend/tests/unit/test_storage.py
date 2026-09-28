from __future__ import annotations

from typing import Any

from minio.commonconfig import COMPLIANCE
from minio.objectlockconfig import DAYS

from app.config import Settings
from app.storage import ensure_buckets, make_minio_client


class RecordingMinio:
    def __init__(self, existing: set[str]) -> None:
        self.existing = set(existing)
        self.calls: list[tuple[str, Any]] = []

    def bucket_exists(self, name: str) -> bool:
        return name in self.existing

    def make_bucket(self, name: str, object_lock: bool = False) -> None:
        self.calls.append(("make_bucket", (name, object_lock)))
        self.existing.add(name)

    def set_object_lock_config(self, name: str, config: Any) -> None:
        self.calls.append(("lock", (name, config)))


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
    client = RecordingMinio({"evidence", "artifacts"})
    assert ensure_buckets(client, settings) == []  # type: ignore[arg-type]
    assert client.calls == []


def test_make_minio_client(settings: Settings) -> None:
    client = make_minio_client(settings)
    assert client is not None
