"""Worker side of the sandbox (Phase 10): the exclusive slot and the untrusted output."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.parsers.base import Event, ParseLimits, ParseStats, ToolConfig
from app.sandbox.client import (
    BadLine,
    SandboxClient,
    SandboxOutput,
    SandboxUnavailableError,
    hold_slot,
)
from app.sandbox.protocol import (
    CANCEL_FILE,
    EVENTS_FILE,
    READY_FILE,
    REQUEST_FILE,
    ExitInfo,
    LimitsSpec,
    ProtocolError,
    SandboxRequest,
    ToolsSpec,
    encode_event,
    encode_result,
)


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    lock, spool_in, spool_out = tmp_path / "scratch", tmp_path / "in", tmp_path / "out"
    spool_in.mkdir()
    spool_out.mkdir()
    return lock, spool_in, spool_out


def test_slot_is_exclusive_and_cleans_up(roots: tuple[Path, Path, Path]) -> None:
    lock, spool_in, spool_out = roots
    stale = spool_in / f"job-{uuid.uuid4().hex}"
    stale.mkdir()
    (stale / "evidence.bin").write_bytes(b"old evidence")
    (stale / "evidence.bin").chmod(0o400)
    stale_out = spool_out / f"job-{uuid.uuid4().hex}"
    stale_out.mkdir()
    other = spool_in / "lost+found"
    other.mkdir()

    order: list[str] = []
    ticks: list[float] = []
    entered = threading.Event()
    release = threading.Event()

    def first() -> None:
        with hold_slot(lock, spool_in, spool_out, tick=lambda: None) as slot:
            order.append("first-in")
            assert not stale.exists() and not stale_out.exists() and other.exists()
            (slot.in_dir / "evidence.bin").write_bytes(b"x")
            (slot.in_dir / "evidence.bin").chmod(0o400)
            slot.out_dir.mkdir()
            entered.set()
            release.wait(10)
            order.append("first-out")
        assert not slot.in_dir.exists() and not slot.out_dir.exists()

    def second() -> None:
        entered.wait(10)
        with hold_slot(lock, spool_in, spool_out, tick=lambda: ticks.append(1), poll_s=0.05):
            order.append("second-in")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for t in threads:
        t.start()
    entered.wait(10)
    time.sleep(0.3)
    assert order == ["first-in"] and ticks  # the second holder waits and keeps ticking
    release.set()
    for t in threads:
        t.join(10)
    assert order == ["first-in", "first-out", "second-in"]
    assert sorted(p.name for p in spool_in.iterdir()) == ["lost+found"]


def test_slot_is_released_on_error_with_a_cancel_marker(roots: tuple[Path, Path, Path]) -> None:
    lock, spool_in, spool_out = roots
    seen: list[Path] = []
    with pytest.raises(RuntimeError), hold_slot(lock, spool_in, spool_out, tick=lambda: None) as s:
        seen.append(s.in_dir)
        raise RuntimeError("boom")
    assert not seen[0].exists()
    with hold_slot(lock, spool_in, spool_out, tick=lambda: None) as slot:  # not deadlocked
        assert slot.in_dir.is_dir() and not (slot.in_dir / CANCEL_FILE).exists()


def test_tick_errors_abort_the_wait(roots: tuple[Path, Path, Path]) -> None:
    lock, spool_in, spool_out = roots
    holding = threading.Event()
    done = threading.Event()

    def holder() -> None:
        with hold_slot(lock, spool_in, spool_out, tick=lambda: None):
            holding.set()
            done.wait(10)

    t = threading.Thread(target=holder)
    t.start()
    holding.wait(10)

    def cancelled() -> None:
        raise LookupError("job cancelled")

    with pytest.raises(LookupError), hold_slot(lock, spool_in, spool_out, tick=cancelled):
        pass
    done.set()
    t.join(10)


def _request() -> SandboxRequest:
    return SandboxRequest(
        job_id=uuid.uuid4(),
        parser="linux_auth",
        evidence_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        source_file="auth.log",
        limits=LimitsSpec.of(ParseLimits()),
        tools=ToolsSpec.of(ToolConfig()),
        timeout_s=5,
        max_output_bytes=1000,
    )


def test_run_without_a_sandbox_is_transient(roots: tuple[Path, Path, Path]) -> None:
    lock, spool_in, spool_out = roots
    ticks: list[float] = []
    client = SandboxClient(start_timeout_s=0.3, poll_s=0.05)
    with hold_slot(lock, spool_in, spool_out, tick=lambda: None) as slot:
        with pytest.raises(SandboxUnavailableError):
            client.run(slot, _request(), tick=ticks.append)
        assert (slot.in_dir / REQUEST_FILE).is_file() and (slot.in_dir / READY_FILE).is_file()
    assert ticks and all(t == 0.0 for t in ticks)


def _event(i: int) -> bytes:
    return encode_event(
        Event(ts=datetime(2026, 1, 1, tzinfo=UTC), source_type="t", message=f"m{i}", record_key=str(i))
    )


def _output(tmp_path: Path, data: bytes, **exit_overrides: object) -> SandboxOutput:
    out = tmp_path / "job-out"
    out.mkdir(exist_ok=True)
    (out / EVENTS_FILE).write_bytes(data)
    values: dict[str, object] = {
        "reason": "ok",
        "returncode": 0,
        "duration_ms": 1,
        "output_bytes": len(data),
        "lines": data.count(b"\n"),
        "sha256": hashlib.sha256(data).hexdigest(),
        "result_seen": True,
    }
    values.update(exit_overrides)
    return SandboxOutput(out, ExitInfo(**values))  # type: ignore[arg-type]


def test_output_must_match_its_exit_record(tmp_path: Path) -> None:
    data = _event(1) + encode_result("ok", ParseStats(records_read=1), 1)
    _output(tmp_path, data).verify()
    with pytest.raises(ProtocolError, match="size"):
        _output(tmp_path, data, output_bytes=len(data) - 1).verify()
    with pytest.raises(ProtocolError, match="hash"):
        _output(tmp_path, data, sha256="0" * 64).verify()


def test_items_decode_events_count_bad_lines_and_read_the_result(tmp_path: Path) -> None:
    data = _event(1) + b"E{broken\n" + _event(2) + encode_result("ok", ParseStats(), 3)
    output = _output(tmp_path, data)
    items = list(output.items())
    assert [type(i) for i in items] == [Event, BadLine, Event]
    assert isinstance(items[1], BadLine) and items[1].number == 2
    assert output.result is not None and output.result.yielded == 3


def test_items_refuse_lines_after_the_result(tmp_path: Path) -> None:
    data = encode_result("ok", ParseStats(), 0) + _event(1)
    with pytest.raises(ProtocolError):
        list(_output(tmp_path, data).items())


def test_a_bad_result_line_is_reported(tmp_path: Path) -> None:
    output = _output(tmp_path, _event(1) + b'R{"status": "ok"}\n')
    items = list(output.items())
    assert isinstance(items[-1], BadLine) and items[-1].reason.startswith("bad result")
    assert output.result is None
