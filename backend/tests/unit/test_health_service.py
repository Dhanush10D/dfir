from __future__ import annotations

from typing import Any

from minio.error import S3Error
from sqlalchemy import create_engine

from app.services.health import (
    CheckResult,
    check_database,
    check_redis,
    check_storage,
    run_readiness,
)


class FakeRedis:
    def __init__(self, result: Any = True, exc: Exception | None = None) -> None:
        self.result, self.exc = result, exc

    def ping(self) -> Any:
        if self.exc:
            raise self.exc
        return self.result


def s3_error(code: str) -> S3Error:
    return S3Error(None, code, "msg", "/evidence", "req", "host")  # type: ignore[arg-type]


class FakeStorage:
    def __init__(
        self, buckets: set[str], exc: Exception | None = None, locked: bool = True
    ) -> None:
        self.buckets, self.exc, self.locked = buckets, exc, locked

    def bucket_exists(self, bucket_name: str) -> bool:
        if self.exc:
            raise self.exc
        return bucket_name in self.buckets

    def get_object_lock_config(self, bucket_name: str) -> Any:
        if not self.locked:
            raise s3_error("ObjectLockConfigurationNotFoundError")
        return object()


def test_database_check_ok_with_sqlite() -> None:
    result = check_database(create_engine("sqlite://"))
    assert result.ok and result.name == "database" and result.error is None


def test_database_check_reports_exception_type_only() -> None:
    engine = create_engine(
        "postgresql+psycopg://u:secretpw@127.0.0.1:1/x", connect_args={"connect_timeout": 1}
    )
    result = check_database(engine)
    assert not result.ok
    assert result.error == "OperationalError"
    assert "secretpw" not in str(result.as_dict())


def test_redis_check() -> None:
    assert check_redis(FakeRedis()).ok
    assert check_redis(FakeRedis(result=False)).error == "ping_failed"
    assert check_redis(FakeRedis(exc=ConnectionError("down"))).error == "ConnectionError"


def test_storage_check() -> None:
    assert check_storage(FakeStorage({"evidence"}), "evidence").ok
    missing = check_storage(FakeStorage(set()), "evidence")
    assert missing.error == "vault_bucket_missing"
    assert check_storage(FakeStorage(set(), exc=TimeoutError()), "evidence").error == "TimeoutError"


def test_storage_check_requires_object_lock() -> None:
    unlocked = check_storage(FakeStorage({"evidence"}, locked=False), "evidence")
    assert not unlocked.ok
    assert unlocked.error == "vault_not_worm"


def test_run_readiness_aggregates() -> None:
    good = CheckResult("a", True, 1.0)
    bad = CheckResult("b", False, 2.0, "X")
    report = run_readiness([lambda: good, lambda: bad])
    assert not report.ok
    assert report.as_dict() == {
        "a": {"ok": True, "latency_ms": 1.0},
        "b": {"ok": False, "latency_ms": 2.0, "error": "X"},
    }
    assert run_readiness([lambda: good]).ok
