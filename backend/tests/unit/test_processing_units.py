"""Pure pieces of the processing pipeline: normalization, job parameters/idempotency keys, timeline
cursors, and the Celery task's retry decisions (no broker, no database)."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from celery.exceptions import Retry

from app.config import Settings
from app.core.exceptions import AppError
from app.parsers.base import Event
from app.parsers.normalize import NormalizationError, event_id, to_row
from app.services.events import EventFilter, decode_cursor, encode_cursor
from app.services.jobs import idempotency_key, validate_params
from app.services.processing import RunResult, manifest_sha256
from app.workers.tasks import parse as parse_task

TS = datetime(2026, 1, 2, 9, 0, tzinfo=UTC)


def _event(**kw: Any) -> Event:
    base: dict[str, Any] = {"ts": TS, "source_type": "t", "message": "m", "record_key": "line:1"}
    base.update(kw)
    return Event(**base)


def _row(event: Event) -> dict[str, Any]:
    row, _ = to_row(
        event, case_id="c", evidence_id="e", job_id="j", parser_name="p", parser_version="1"
    )
    return row


# ------------------------------------------------------------------------------ normalize


def test_to_row_converts_to_utc_and_keeps_original() -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    row = _row(_event(ts=datetime(2026, 1, 2, 14, 30, tzinfo=ist), ts_original="14:30 IST"))
    assert row["ts"] == TS and row["ts"].tzinfo is UTC
    assert row["ts_original"] == "14:30 IST"


def test_to_row_rejects_naive_timestamps_and_missing_keys() -> None:
    with pytest.raises(NormalizationError):
        _row(_event(ts=datetime(2026, 1, 2, 9, 0)))
    with pytest.raises(NormalizationError):
        _row(_event(record_key=""))


def test_to_row_sanitizes_hostile_values() -> None:
    row = _row(
        _event(
            message="a\x00b\ud800c",
            src_ip="300.1.1.1",
            dst_ip="::ffff:192.0.2.1",
            src_port=70000,
            pid=-1,
            ppid=2**40,
            tags=["x"] * 100,
            raw={"n": float("nan"), "k\x00": [1, {"deep": "v"}], "o": object()},
            cmdline="c" * 100_000,
        )
    )
    assert row["message"] == "a�b�c"
    assert row["src_ip"] is None
    assert ipaddress.ip_address(row["dst_ip"]) == ipaddress.ip_address("::ffff:192.0.2.1")
    assert row["src_port"] is None and row["pid"] is None and row["ppid"] is None
    assert len(row["tags"]) == 64
    assert row["raw"]["n"] is None and "k�" in row["raw"]
    assert row["cmdline"].endswith("...[truncated]") and len(row["cmdline"]) < 40_000


def test_to_row_bounds_raw_size() -> None:
    row = _row(_event(raw={"blob": ["x" * 60_000 for _ in range(20)]}))
    assert row["raw"]["_truncated"] is True and len(row["raw"]["summary"]) < 5000


def test_event_ids_are_deterministic() -> None:
    a = event_id("e", "p", "f", "line:1")
    assert a == event_id("e", "p", "f", "line:1")
    assert a != event_id("e", "p", "f", "line:2")
    assert a != event_id("e2", "p", "f", "line:1")
    assert a != event_id("e", "p2", "f", "line:1")
    assert _row(_event())["id"] == event_id("e", "p", None, "line:1")


# ------------------------------------------------------------------------------ job params


def test_validate_params() -> None:
    assert validate_params("linux_auth", {}) == {"timezone": "UTC"}
    assert validate_params("linux_auth", {"timezone": "Asia/Kolkata", "year": 2025}) == {
        "timezone": "Asia/Kolkata",
        "year": 2025,
    }
    assert validate_params("evtx", {"timezone": None}) == {}
    for parser, params in (
        ("evtx", {"year": 2025}),
        ("linux_auth", {"timezone": "Not/AZone"}),
        ("linux_auth", {"year": 1800}),
        ("linux_auth", {"year": True}),
        ("linux_auth", {"other": 1}),
    ):
        with pytest.raises(AppError) as info:
            validate_params(parser, params)
        assert info.value.status_code == 422


def test_idempotency_key_is_canonical() -> None:
    ev = uuid.uuid4()
    k1 = idempotency_key(ev, "linux_auth", "1.0.0", {"timezone": "UTC", "year": 2025})
    k2 = idempotency_key(ev, "linux_auth", "1.0.0", {"year": 2025, "timezone": "UTC"})
    assert k1 == k2 and len(k1) == 64
    assert k1 != idempotency_key(ev, "linux_auth", "1.0.1", {"timezone": "UTC", "year": 2025})
    assert k1 != idempotency_key(ev, "linux_auth", "1.0.0", {"timezone": "UTC"})


def test_manifest_hash_is_order_independent() -> None:
    assert manifest_sha256({"a": 1, "b": [1, 2]}) == manifest_sha256({"b": [1, 2], "a": 1})


# ------------------------------------------------------------------------------ cursors


def test_cursor_roundtrip_and_tamper() -> None:
    eid = uuid.uuid4()
    cursor = encode_cursor(TS, eid, "asc")
    assert decode_cursor(cursor, "asc") == (TS, eid)
    for bad in (cursor[:-3], "!!!", "e30", cursor + "A" * 300):
        with pytest.raises(AppError):
            decode_cursor(bad, "asc")
    with pytest.raises(AppError):
        decode_cursor(cursor, "desc")


def test_event_filter_validation() -> None:
    EventFilter(start=TS, end=TS, ip="2001:db8::1", q="x").validate()
    for flt in (
        EventFilter(start=datetime(2026, 1, 1)),
        EventFilter(start=TS, end=TS - timedelta(seconds=1)),
        EventFilter(ip="nope"),
        EventFilter(q="  "),
        EventFilter(q="x" * 201),
    ):
        with pytest.raises(AppError):
            flt.validate()


# ------------------------------------------------------------------------------ Celery task


class FakeRunner:
    def __init__(self, outcome: str | Exception) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        job_id: uuid.UUID,
        *,
        allow_retry: bool = False,
        stop_exceptions: tuple[type[BaseException], ...] = (),
    ) -> RunResult:
        self.calls.append({"job_id": job_id, "allow_retry": allow_retry, "stop": stop_exceptions})
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return RunResult(job_id, self.outcome)


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> Any:
    for var in ("JOB_MAX_AUTO_RETRIES", "JOB_LEASE_S"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(parse_task, "get_settings", lambda: Settings(_env_file=None))  # type: ignore[call-arg]

    def install(outcome: str | Exception) -> FakeRunner:
        fake = FakeRunner(outcome)
        monkeypatch.setattr(parse_task, "service_factory", lambda: fake)
        return fake

    return install


def test_task_returns_terminal_outcomes(runner: Any) -> None:
    from celery.exceptions import SoftTimeLimitExceeded

    fake = runner("succeeded")
    job_id = uuid.uuid4()
    result = parse_task.parse_evidence(str(job_id))  # called directly: no broker
    assert result["outcome"] == "succeeded" and result["job_id"] == str(job_id)
    assert fake.calls[0]["allow_retry"] is True
    assert fake.calls[0]["stop"] == (SoftTimeLimitExceeded,)
    assert parse_task.parse_evidence("not-a-uuid")["outcome"] == "skipped"
    assert len(fake.calls) == 1


@pytest.mark.parametrize("outcome", ["retry", "busy"])
def test_task_retries_transient_and_busy(runner: Any, outcome: str) -> None:
    runner(outcome)
    with pytest.raises(Retry):
        parse_task.parse_evidence(str(uuid.uuid4()))


def test_task_retries_unexpected_errors(runner: Any) -> None:
    runner(RuntimeError("db went away"))
    with pytest.raises(RuntimeError):  # called directly, retry() re-raises the cause
        parse_task.parse_evidence(str(uuid.uuid4()))


def test_task_stops_retrying_at_the_limit(runner: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = runner("busy")
    task = parse_task.parse_evidence
    monkeypatch.setattr(task.request, "retries", 3, raising=False)
    try:
        assert task(str(uuid.uuid4()))["outcome"] == "busy"
        assert fake.calls[-1]["allow_retry"] is False  # last attempt ends failed, not queued
    finally:
        monkeypatch.setattr(task.request, "retries", 0, raising=False)


def test_backoff_is_exponential_and_capped() -> None:
    assert [parse_task.backoff_seconds(n, rand=lambda: 0.0) for n in range(8)] == [
        10,
        20,
        40,
        80,
        160,
        320,
        600,
        600,
    ]
    assert parse_task.backoff_seconds(0, rand=lambda: 1.0) == 12


def test_task_is_registered_on_the_parse_queue() -> None:
    from app.workers.celery_app import celery_app

    task = celery_app.tasks["dfirbench.parse_evidence"]
    assert task.queue == "parse" and task.acks_late is True
    assert task.reject_on_worker_lost is True


def test_processing_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("INGEST_BATCH_SIZE", "JOB_LEASE_S", "JOB_MAX_AUTO_RETRIES", "SCRATCH_DIR"):
        monkeypatch.delenv(var, raising=False)
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.ingest_batch_size == 1000 and s.job_max_auto_retries == 3
    assert s.job_lease_s == 900 and s.scratch_dir is None
    monkeypatch.setenv("INGEST_BATCH_SIZE", "5000")
    with pytest.raises(ValueError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_bundle_task_follows_the_parse_retry_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.workers.tasks import bundle as bundle_task

    for var in ("JOB_MAX_AUTO_RETRIES", "JOB_LEASE_S"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(bundle_task, "get_settings", lambda: Settings(_env_file=None))  # type: ignore[call-arg]

    def install(outcome: str | Exception) -> FakeRunner:
        fake = FakeRunner(outcome)
        monkeypatch.setattr(bundle_task, "service_factory", lambda: fake)
        return fake

    fake = install("partial")
    assert bundle_task.ingest_bundle(str(uuid.uuid4()))["outcome"] == "partial"
    assert fake.calls[0]["allow_retry"] is True
    assert bundle_task.ingest_bundle("nope")["outcome"] == "skipped"
    for outcome in ("retry", "busy"):
        install(outcome)
        with pytest.raises(Retry):
            bundle_task.ingest_bundle(str(uuid.uuid4()))
    install(RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        bundle_task.ingest_bundle(str(uuid.uuid4()))
