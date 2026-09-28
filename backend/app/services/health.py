"""Readiness checks for PostgreSQL, Redis and the evidence vault. No FastAPI imports (guide 6)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from minio.error import S3Error
from sqlalchemy import Engine, text


class RedisLike(Protocol):
    def ping(self) -> Any: ...


class StorageLike(Protocol):
    def bucket_exists(self, bucket_name: str) -> bool: ...

    def get_object_lock_config(self, bucket_name: str) -> Any: ...


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    latency_ms: float
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": self.ok, "latency_ms": self.latency_ms}
        if self.error:
            out["error"] = self.error
        return out


@dataclass(frozen=True)
class ReadinessReport:
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def as_dict(self) -> dict[str, dict[str, Any]]:
        return {c.name: c.as_dict() for c in self.checks}


def _timed(name: str, fn: Callable[[], str | None]) -> CheckResult:
    started = time.perf_counter()
    try:
        problem = fn()
    except Exception as exc:  # noqa: BLE001 - a probe must report, not raise
        # Only the exception type goes to the client; messages may contain hostnames/DSNs.
        problem = type(exc).__name__
    latency = round((time.perf_counter() - started) * 1000, 2)
    return CheckResult(name=name, ok=problem is None, latency_ms=latency, error=problem)


def check_database(engine: Engine) -> CheckResult:
    def run() -> str | None:
        with engine.connect() as conn:
            value: object = conn.execute(text("SELECT 1")).scalar_one()
        return None if value == 1 else "unexpected_result"

    return _timed("database", run)


def check_redis(client: RedisLike) -> CheckResult:
    def run() -> str | None:
        return None if client.ping() else "ping_failed"

    return _timed("redis", run)


def check_storage(client: StorageLike, bucket: str) -> CheckResult:
    def run() -> str | None:
        if not client.bucket_exists(bucket):
            return "vault_bucket_missing"
        try:
            client.get_object_lock_config(bucket)
        except S3Error as exc:
            if exc.code == "ObjectLockConfigurationNotFoundError":
                return "vault_not_worm"
            raise
        return None

    return _timed("storage", run)


def run_readiness(checks: list[Callable[[], CheckResult]]) -> ReadinessReport:
    return ReadinessReport(checks=[check() for check in checks])
