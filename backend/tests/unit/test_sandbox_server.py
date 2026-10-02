"""Sandbox server (Phase 10): real child processes, every way a parser run can end.

The real child (``app.sandbox.child``) parses a fixture; ``tests.unit.sandbox_fake_child``
simulates crashes, floods, protocol violations, hangs and stray processes.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.parsers.base import ParseLimits, ToolConfig
from app.parsers.normalize import to_row
from app.parsers.registry import get_parser
from app.sandbox.client import SandboxOutput
from app.sandbox.protocol import (
    CANCEL_FILE,
    EVENTS_FILE,
    EVIDENCE_FILE,
    EXIT_FILE,
    READY_FILE,
    REQUEST_FILE,
    ExitInfo,
    LimitsSpec,
    SandboxRequest,
    ToolsSpec,
)
from app.sandbox.server import (
    HEARTBEAT_FILE,
    SandboxPolicy,
    SandboxServer,
    child_env,
    descendants,
    health,
    main,
    set_subreaper,
    uid_split_from_env,
)
from tests.unit.deep_helpers import context

BACKEND = Path(__file__).resolve().parents[2]
AUTH_LOG = BACKEND / "tests" / "fixtures" / "linux" / "auth.log"
LINUX = sys.platform.startswith("linux")
REFERENCE = datetime(2026, 1, 3, tzinfo=UTC)


@pytest.fixture
def spool(tmp_path: Path) -> dict[str, Path]:
    dirs = {name: tmp_path / name for name in ("in", "out", "work")}
    for path in dirs.values():
        path.mkdir()
    return dirs


def make_job(
    spool: dict[str, Path],
    params: dict[str, Any] | None = None,
    *,
    parser: str = "linux_auth",
    evidence: bytes = b"",
    timeout_s: int = 60,
    max_output_bytes: int = 10_000_000,
) -> str:
    name = f"job-{uuid.uuid4().hex}"
    job = spool["in"] / name
    job.mkdir()
    (job / EVIDENCE_FILE).write_bytes(evidence)
    request = SandboxRequest(
        job_id=uuid.uuid4(),
        parser=parser,
        evidence_id=uuid.UUID("00000000-0000-4000-8000-0000000e0006"),
        case_id=uuid.UUID("00000000-0000-4000-8000-00000000c0de"),
        source_file="auth.log",
        reference_time=REFERENCE,
        reference_source="test",
        params=params or {},
        limits=LimitsSpec.of(ParseLimits()),
        tools=ToolsSpec.of(ToolConfig()),
        timeout_s=timeout_s,
        max_output_bytes=max_output_bytes,
    )
    (job / REQUEST_FILE).write_bytes(request.encode())
    (job / READY_FILE).write_bytes(b"1")
    return name


def make_server(spool: dict[str, Path], *, fake: bool = True, **policy: Any) -> SandboxServer:
    policy.setdefault("sweep", False)
    return SandboxServer(
        spool["in"],
        spool["out"],
        spool["work"],
        SandboxPolicy(
            poll_s=0.05,
            child_module="tests.unit.sandbox_fake_child" if fake else "app.sandbox.child",
            extra_env=(("PYTHONPATH", str(BACKEND)),),
            **policy,
        ),
    )


def exit_info(spool: dict[str, Path], name: str) -> ExitInfo:
    return ExitInfo.decode((spool["out"] / name / EXIT_FILE).read_bytes())


def run(spool: dict[str, Path], name: str, **policy: Any) -> ExitInfo:
    server = make_server(spool, **policy)
    assert server.run_once() == name
    assert not (spool["work"] / name).exists()  # scratch removed after every job
    return exit_info(spool, name)


# ------------------------------------------------------------------ real parser child


def test_real_child_output_equals_in_process_parsing(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"timezone": "UTC"}, evidence=AUTH_LOG.read_bytes())
    info = run(spool, name, fake=False)
    assert info.reason == "ok" and info.returncode == 0 and info.result_seen
    output = SandboxOutput(spool["out"] / name, info)
    output.verify()
    sandboxed = list(output.items())
    assert output.result is not None and output.result.status == "ok"
    assert output.result.yielded == len(sandboxed)

    parser = get_parser("linux_auth")
    ctx = context(AUTH_LOG, params={"timezone": "UTC"}, source_file="auth.log")
    direct = list(parser.parse(ctx))
    ids = {"case_id": "c", "evidence_id": "e", "job_id": "j", "parser_name": "p"}
    assert [to_row(e, parser_version="1", **ids) for e in sandboxed] == [
        to_row(e, parser_version="1", **ids) for e in direct
    ]
    assert output.result.stats.records_read == ctx.stats.records_read


def test_real_child_reports_unusable_input(spool: dict[str, Path]) -> None:
    name = make_job(spool, parser="evtx", evidence=b"not an evtx file" * 10)
    info = run(spool, name, fake=False)
    assert info.reason == "ok"
    output = SandboxOutput(spool["out"] / name, info)
    assert list(output.items()) == []
    assert output.result is not None and output.result.status == "input_error"
    assert output.result.message


# ------------------------------------------------------------------ misbehaving children


def test_child_environment_holds_no_credentials(
    spool: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://dfir:secret@db/x")
    monkeypatch.setenv("S3_SECRET_KEY", "minio-secret")
    env = child_env(spool["work"])
    assert "DATABASE_URL" not in env and "S3_SECRET_KEY" not in env
    name = make_job(spool, {"mode": "env"})
    info = run(spool, name)
    output = SandboxOutput(spool["out"] / name, info)
    list(output.items())
    assert output.result is not None and output.result.message == "-"


def test_timeout_kills_the_child_and_keeps_what_it_wrote(spool: dict[str, Path]) -> None:
    # 5 s: the child must get past interpreter start-up and imports to write its first line.
    name = make_job(spool, {"mode": "sleep"}, timeout_s=5)
    started = time.monotonic()
    info = run(spool, name)
    assert info.reason == "timeout" and not info.result_seen
    assert info.lines == 1 and time.monotonic() - started < 30


def test_policy_caps_the_requested_timeout(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "sleep"}, timeout_s=3600)
    info = run(spool, name, max_run_s=1)
    assert info.reason == "timeout"


def test_cancel_marker_stops_the_child(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "sleep"})
    server = make_server(spool)
    worker = threading.Thread(target=server.run_once)
    worker.start()
    deadline = time.monotonic() + 30
    while not (spool["out"] / name / EVENTS_FILE).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    (spool["in"] / name / CANCEL_FILE).write_bytes(b"1")
    worker.join(timeout=30)
    assert not worker.is_alive()
    assert exit_info(spool, name).reason == "cancelled"


def test_vanished_job_is_abandoned_without_output(spool: dict[str, Path]) -> None:
    from app.sandbox.server import remove_tree

    name = make_job(spool, {"mode": "sleep"})
    server = make_server(spool)
    result: list[ExitInfo | None] = []
    worker = threading.Thread(target=lambda: result.append(server.run_job(name)))
    worker.start()
    deadline = time.monotonic() + 30
    while not (spool["out"] / name).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.5)
    remove_tree(spool["in"] / name)
    worker.join(timeout=30)
    assert result == [None]
    assert not (spool["out"] / name).exists()


def test_output_flood_hits_the_cap(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "flood"}, max_output_bytes=1000)
    info = run(spool, name, max_output_bytes=200_000)
    assert info.reason == "output_limit"
    assert info.output_bytes <= 200_000
    assert (spool["out"] / name / EVENTS_FILE).stat().st_size == info.output_bytes


@pytest.mark.parametrize("mode", ["garbage", "long_line", "after_result"])
def test_protocol_violations_stop_the_child(spool: dict[str, Path], mode: str) -> None:
    name = make_job(spool, {"mode": mode, "size": 300_000})
    info = run(spool, name, max_line_bytes=100_000)
    assert info.reason == "protocol"


def test_exit_without_result_is_a_child_error(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "crash"})
    info = run(spool, name)
    assert info.reason == "child_error" and info.returncode == 3 and info.lines == 1


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_killed_child_is_reported(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "kill_self"})
    info = run(spool, name)
    assert info.reason == "killed" and info.returncode == -9


def test_bad_request_starts_nothing(spool: dict[str, Path]) -> None:
    name = make_job(spool)
    (spool["in"] / name / REQUEST_FILE).write_bytes(b'{"v": 1}')
    info = run(spool, name)
    assert info.reason == "bad_request" and info.lines == 0


@pytest.mark.skipif(not LINUX, reason="/proc process tree")
def test_stray_processes_are_killed_after_the_job(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "sleep_tree"}, timeout_s=2)
    info = run(spool, name, sweep=True)
    assert info.reason == "timeout"
    assert descendants(os.getpid(), Path("/proc")) == []


@pytest.mark.skipif(not LINUX, reason="/proc process tree")
def test_orphan_holding_stdout_does_not_hang_the_server(spool: dict[str, Path]) -> None:
    # As in `main`: the server is a subreaper, so the orphan stays its descendant for the sweep
    # (otherwise it re-parents to the container's init and keeps the pipe open).
    set_subreaper()
    name = make_job(spool, {"mode": "orphan"})
    started = time.monotonic()
    info = run(spool, name, sweep=True)
    assert info.reason == "ok"
    assert time.monotonic() - started < 9  # the sweep closes the pipe, not the 10 s join timeout


# ------------------------------------------------------------------ housekeeping


def test_pending_ignores_unready_and_claimed_jobs(spool: dict[str, Path]) -> None:
    server = make_server(spool)
    assert server.pending() is None
    first = make_job(spool)
    (spool["in"] / first / READY_FILE).unlink()
    assert server.pending() is None
    (spool["in"] / first / READY_FILE).write_bytes(b"1")
    assert server.pending() == first
    (spool["out"] / first).mkdir()
    assert server.pending() is None
    (spool["in"] / "not-a-job").mkdir()
    assert server.pending() is None


def test_startup_forgets_unfinished_work(spool: dict[str, Path]) -> None:
    unfinished = spool["out"] / f"job-{uuid.uuid4().hex}"
    unfinished.mkdir()
    (unfinished / EVENTS_FILE).write_bytes(b"E{}\n")
    finished = spool["out"] / f"job-{uuid.uuid4().hex}"
    finished.mkdir()
    (finished / EXIT_FILE).write_bytes(b"{}")
    scratch = spool["work"] / f"job-{uuid.uuid4().hex}"
    scratch.mkdir()
    make_server(spool).startup()
    assert not unfinished.exists() and finished.exists() and not scratch.exists()
    assert health(spool["work"]) == 0


def test_a_new_job_removes_older_outputs(spool: dict[str, Path]) -> None:
    old = spool["out"] / f"job-{uuid.uuid4().hex}"
    old.mkdir()
    (old / EXIT_FILE).write_bytes(b"{}")
    name = make_job(spool, {"mode": "ok"})
    info = run(spool, name)
    assert info.reason == "ok" and info.lines == 4  # 3 events + result (progress not copied)
    assert not old.exists()


def test_descendants_follow_parent_links(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    tree = {1: 0, 10: 1, 11: 10, 12: 11, 13: 10, 20: 1, 21: 20}
    for pid, ppid in tree.items():
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "stat").write_bytes(f"{pid} (odd (name) x) S {ppid} 1 1 0".encode())
    (proc / "self").mkdir()
    (proc / "99").mkdir()  # vanished between listing and reading
    assert descendants(10, proc) == [11, 12, 13]
    assert descendants(20, proc) == [21]
    assert descendants(12, proc) == []


def test_health_needs_a_recent_heartbeat(tmp_path: Path) -> None:
    assert health(tmp_path) == 1
    beat = tmp_path / HEARTBEAT_FILE
    beat.write_bytes(b"1")
    assert health(tmp_path) == 0
    old = time.time() - 600
    os.utime(beat, (old, old))
    assert health(tmp_path) == 1


UID_SPLIT_VARS = (
    "SANDBOX_SERVER_UID",
    "SANDBOX_CHILD_UID",
    "SANDBOX_GID",
    "SANDBOX_ALLOW_SAME_UID",
)


def test_server_refuses_root_without_a_uid_split(
    spool: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in UID_SPLIT_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    argv = ["--in", str(spool["in"]), "--out", str(spool["out"]), "--work", str(spool["work"])]
    assert main(argv) == 2
    assert main([]) == 2  # directories are required
    # The child must not share the server's uid.
    monkeypatch.setenv("SANDBOX_SERVER_UID", "10001")
    monkeypatch.setenv("SANDBOX_CHILD_UID", "10001")
    monkeypatch.setenv("SANDBOX_GID", "10001")
    assert main(argv) == 2


def test_server_refuses_a_shared_uid_unless_allowed(
    spool: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in UID_SPLIT_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 10001, raising=False)
    argv = ["--in", str(spool["in"]), "--out", str(spool["out"]), "--work", str(spool["work"])]
    assert main(argv) == 2  # a parser could stop a same-uid server and outlive its job


def test_uid_split_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in UID_SPLIT_VARS:
        monkeypatch.delenv(name, raising=False)
    assert uid_split_from_env() is None
    monkeypatch.setenv("SANDBOX_SERVER_UID", "10001")
    monkeypatch.setenv("SANDBOX_CHILD_UID", "10002")
    assert uid_split_from_env() is None  # all three are required
    monkeypatch.setenv("SANDBOX_GID", "10001")
    assert uid_split_from_env() == (10001, 10002, 10001)
    monkeypatch.setenv("SANDBOX_CHILD_UID", "0")
    with pytest.raises(ValueError):
        uid_split_from_env()  # never root
    assert not SandboxPolicy().uid_split
    assert SandboxPolicy(child_uid=10002, fs_uid=10001, gid=10001).uid_split


def test_exit_record_is_valid_json(spool: dict[str, Path]) -> None:
    name = make_job(spool, {"mode": "ok"})
    run(spool, name)
    body = json.loads((spool["out"] / name / EXIT_FILE).read_bytes())
    assert body["reason"] == "ok" and len(body["sha256"]) == 64
