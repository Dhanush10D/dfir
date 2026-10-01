"""Phase 10: parse jobs through the parser sandbox (SANDBOX_MODE=spool) on the test database.

A ``SandboxServer`` runs in a thread on temporary spool directories and starts real child
processes (the real parser child, or the misbehaving fake for failure paths). The worker side is
the unchanged ``ProcessingService``: claim, integrity check, slot, request, wait, strict decoding,
fenced batches, run manifest and custody.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.db.models import UserRole
from app.sandbox.server import SandboxPolicy, SandboxServer
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

BACKEND = Path(__file__).resolve().parents[2]
FIXTURES = BACKEND / "tests" / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
AUTH_COUNTS = {"records_read": 24, "events_emitted": 22, "skipped": 1, "errors": 1}
COLUMNS = (
    "ts, ts_original, source_type, source_file, host, \"user\", event_code, action, outcome, "
    "process_name, pid, cmdline, src_ip, dst_ip, src_port, message, tags, raw, parser_name"
)


class Sandbox:
    def __init__(self, root: Path, *, fake_mode: str | None = None) -> None:
        self.dirs = {name: root / name for name in ("in", "out", "work", "scratch")}
        for path in self.dirs.values():
            path.mkdir(parents=True, exist_ok=True)
        env: tuple[tuple[str, str], ...] = (("PYTHONPATH", str(BACKEND)),)
        if fake_mode:
            env += (("FAKE_CHILD_MODE", fake_mode),)
        self.server = SandboxServer(
            self.dirs["in"],
            self.dirs["out"],
            self.dirs["work"],
            SandboxPolicy(
                poll_s=0.05,
                sweep=False,
                child_module="tests.unit.sandbox_fake_child" if fake_mode else "app.sandbox.child",
                extra_env=env,
            ),
        )
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.server.serve_forever, args=(self.stop,))

    def settings(self, **extra: Any) -> dict[str, Any]:
        return {
            "sandbox_mode": "spool",
            "sandbox_in_dir": str(self.dirs["in"]),
            "sandbox_out_dir": str(self.dirs["out"]),
            "scratch_dir": str(self.dirs["scratch"]),
            "sandbox_start_timeout_s": 10,
            "ingest_flush_interval_s": 0.2,
            **extra,
        }

    def spool_empty(self) -> bool:
        return not any(self.dirs["in"].iterdir()) and not any(self.dirs["out"].iterdir())

    def __enter__(self) -> Sandbox:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        self.thread.join(timeout=30)


@pytest.fixture
def analyst(h: Harness) -> UserCtx:
    return h.make_user(UserRole.analyst)


@pytest.fixture
def sandbox(tmp_path: Path) -> Iterator[Sandbox]:
    with Sandbox(tmp_path / "real") as box:
        yield box


def _job(h: Harness, user: UserCtx, data: bytes, name: str = "auth.log", **body: Any) -> str:
    case = h.create_case(user, f"Sandbox {uuid.uuid4().hex[:6]}")
    ev = h.stored_evidence(
        user, case["id"], data, original_name=name, acquired_at="2026-01-03T00:00:00Z"
    )
    r = h.post(f"/evidence/{ev['id']}/process", user, json=body or {"parsers": ["linux_auth"]})
    assert r.status_code == 202, r.text
    return str(r.json()["jobs"][0]["id"])


def _manifest(db_engine: Engine, job_id: str) -> dict[str, Any]:
    with db_engine.connect() as conn:
        row = conn.execute(
            text("SELECT status, error, run_manifest FROM jobs WHERE id = :j"), {"j": job_id}
        ).one()
    return {"status": row.status, "error": row.error, **(row.run_manifest or {})}


def _rows(db_engine: Engine, job_id: str) -> list[tuple[Any, ...]]:
    with db_engine.connect() as conn:
        return [
            tuple(r)
            for r in conn.execute(
                text(f"SELECT {COLUMNS} FROM events WHERE job_id = :j ORDER BY ts, message"),
                {"j": job_id},
            )
        ]


def test_sandboxed_job_stores_the_same_events_as_in_process(
    h: Harness, analyst: UserCtx, db_engine: Engine, sandbox: Sandbox
) -> None:
    direct = _job(h, analyst, AUTH_LOG)
    assert h.processing().run(uuid.UUID(direct)).outcome == "succeeded"
    boxed = _job(h, analyst, AUTH_LOG)
    result = h.processing(**sandbox.settings()).run(uuid.UUID(boxed))
    assert result.outcome == "succeeded", result
    assert result.counts == AUTH_COUNTS
    assert _rows(db_engine, boxed) == _rows(db_engine, direct)
    manifest = _manifest(db_engine, boxed)
    assert manifest["sandbox"]["mode"] == "spool"
    assert manifest["sandbox"]["reason"] == "ok"
    assert len(manifest["sandbox"]["output_sha256"]) == 64
    assert _manifest(db_engine, direct)["sandbox"] == {"mode": "none"}
    assert sandbox.spool_empty()
    with db_engine.connect() as conn:  # custody: processed entry signed as before
        actions = conn.execute(
            text(
                "SELECT c.action FROM custody_log c JOIN jobs j ON j.evidence_id = c.evidence_id "
                "WHERE j.id = :j ORDER BY c.seq"
            ),
            {"j": boxed},
        ).scalars()
        assert list(actions)[-1] == "processed"


def test_unusable_input_fails_like_in_process(
    h: Harness, analyst: UserCtx, db_engine: Engine, sandbox: Sandbox
) -> None:
    job = _job(h, analyst, b"definitely not evtx" * 20, "x.evtx", parsers=["evtx"])
    result = h.processing(**sandbox.settings()).run(uuid.UUID(job))
    assert result.outcome == "failed"
    assert result.error is not None and result.error.startswith("unusable input:")
    assert sandbox.spool_empty()


def test_sandbox_down_is_retried(h: Harness, analyst: UserCtx, tmp_path: Path) -> None:
    box = Sandbox(tmp_path / "down")  # server never started
    job = _job(h, analyst, AUTH_LOG)
    result = h.processing(**box.settings(sandbox_start_timeout_s=1)).run(
        uuid.UUID(job), allow_retry=True
    )
    assert result.outcome == "retry"
    assert box.spool_empty()
    assert h.get(f"/jobs/{job}", analyst).json()["status"] == "queued"


def test_crashing_parser_fails_the_job(
    h: Harness, analyst: UserCtx, db_engine: Engine, tmp_path: Path
) -> None:
    with Sandbox(tmp_path / "crash", fake_mode="crash") as box:
        job = _job(h, analyst, AUTH_LOG)
        result = h.processing(**box.settings()).run(uuid.UUID(job))
    assert result.outcome == "failed"
    assert result.error == "parser sandbox: child_error"
    assert _manifest(db_engine, job)["sandbox"]["reason"] == "child_error"
    assert box.spool_empty()


def test_sandbox_timeout_keeps_a_partial_result(
    h: Harness, analyst: UserCtx, db_engine: Engine, tmp_path: Path
) -> None:
    with Sandbox(tmp_path / "slow", fake_mode="sleep") as box:
        job = _job(h, analyst, AUTH_LOG)
        result = h.processing(**box.settings(parser_timeout_s=1)).run(uuid.UUID(job))
    assert result.outcome == "partial", result
    assert result.error == "stopped: parser sandbox time limit"
    assert len(_rows(db_engine, job)) == 1


def test_protocol_violation_fails_the_job(h: Harness, analyst: UserCtx, tmp_path: Path) -> None:
    with Sandbox(tmp_path / "garbage", fake_mode="garbage") as box:
        job = _job(h, analyst, AUTH_LOG)
        result = h.processing(**box.settings()).run(uuid.UUID(job))
    assert result.outcome == "failed" and result.error == "parser sandbox: protocol"


def test_cancel_stops_the_sandboxed_parser(
    h: Harness, analyst: UserCtx, tmp_path: Path
) -> None:
    with Sandbox(tmp_path / "cancel", fake_mode="sleep") as box:
        job = _job(h, analyst, AUTH_LOG)
        outcome: list[str] = []
        runner = threading.Thread(
            target=lambda: outcome.append(
                h.processing(**box.settings()).run(uuid.UUID(job)).outcome
            )
        )
        runner.start()
        deadline = time.monotonic() + 30
        while not any(box.dirs["out"].iterdir()) and time.monotonic() < deadline:
            time.sleep(0.05)
        r = h.post(f"/jobs/{job}/cancel", analyst)
        assert r.status_code in (200, 202), r.text
        runner.join(timeout=60)
        assert outcome == ["cancelled"]
        deadline = time.monotonic() + 10
        while not box.spool_empty() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert box.spool_empty()


def test_integrity_is_checked_before_anything_reaches_the_sandbox(
    h: Harness, analyst: UserCtx, sandbox: Sandbox
) -> None:
    assert h.vault is not None
    case = h.create_case(analyst, "Tampered sandbox")
    ev = h.stored_evidence(analyst, case["id"], AUTH_LOG, original_name="auth.log")
    h.vault.corrupt(h.key_of(ev))
    r = h.post(f"/evidence/{ev['id']}/process", analyst, json={"parsers": ["linux_auth"]})
    assert r.status_code == 202, r.text
    result = h.processing(**sandbox.settings()).run(uuid.UUID(r.json()["jobs"][0]["id"]))
    assert result.outcome == "failed"
    assert result.error is not None and "integrity" in result.error
    assert sandbox.spool_empty()


def test_concurrent_jobs_share_the_sandbox_one_at_a_time(
    h: Harness, analyst: UserCtx, sandbox: Sandbox
) -> None:
    jobs = [_job(h, analyst, AUTH_LOG) for _ in range(2)]
    outcomes: list[str] = []

    def run(job: str) -> None:
        outcomes.append(h.processing(**sandbox.settings()).run(uuid.UUID(job)).outcome)

    threads = [threading.Thread(target=run, args=(job,)) for job in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    assert outcomes == ["succeeded", "succeeded"]
    assert sandbox.spool_empty()
