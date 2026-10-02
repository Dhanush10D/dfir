"""Parser sandbox server: the long-running process of the ``parser-sandbox`` container.

    python -m app.sandbox.server            # serve (as root only with the uid split below)
    python -m app.sandbox.server --health   # healthcheck: the loop wrote its heartbeat recently

The container has no network, a read-only root and resource limits (compose). It starts as root
with only the SETUID, SETGID, KILL and DAC_OVERRIDE capabilities: the server keeps euid 0 so it
can start each child as a separate uid (``SANDBOX_CHILD_UID``, no capabilities, shared group
``SANDBOX_GID``) and kill it, and it reads and writes files as ``SANDBOX_SERVER_UID``. A
compromised child therefore cannot signal (stop) the server, outlive its job, read the output
spool or claim a later job. Without root the server refuses to run unless
``SANDBOX_ALLOW_SAME_UID=1`` (development only). The evidence spool (``SANDBOX_IN_DIR``) is
mounted read-only; the server writes only the output spool (``SANDBOX_OUT_DIR``) and its own work
volume (``SANDBOX_WORK_DIR``).

For each job (one at a time) the server:

1. claims it by creating ``<out>/<job dir>/`` (only ``ready`` jobs without an output dir);
2. starts ``python -m app.sandbox.child`` in a new session with a clean environment and its
   resource limits, copying the child's ``E``/``R`` lines to ``events.jsonl`` (output and line
   caps, strict line kinds, nothing after the result) and its progress to ``progress``;
3. stops the child on timeout, cancel marker, a vanished job directory, an output overflow or a
   protocol violation;
4. kills and reaps **every** remaining descendant (the server is a child subreaper, so orphans
   are re-parented to it) and deletes the job's work directory;
5. only then writes ``exit.json`` (reason, return code, size and SHA-256 of ``events.jsonl``).

The child's stderr is never copied anywhere: it may contain evidence content. Only the exception
class name of its last line is logged.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import shutil
import signal
import subprocess  # nosec B404 - fixed argv ([python, -m, app.sandbox.child, ...]), shell=False
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import IO, Any

import structlog

from app.sandbox.protocol import (
    CANCEL_FILE,
    EVENTS_FILE,
    EXIT_FILE,
    JOB_DIR,
    MAX_LINE_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESULT_BYTES,
    PROGRESS_FILE,
    READY_FILE,
    REQUEST_FILE,
    ExitInfo,
    ProtocolError,
    SandboxRequest,
    decode_progress,
)

log = structlog.stdlib.get_logger("dfirbench.sandbox")

MIB = 1024 * 1024
HEARTBEAT_FILE = ".alive"
HEALTH_MAX_AGE_S = 60.0
PR_SET_CHILD_SUBREAPER = 36
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_EXC_NAME = re.compile(rb"^([A-Za-z_][A-Za-z0-9_.]{0,100}(?:Error|Exception|Exit|Interrupt))\b")


@dataclass(frozen=True)
class SandboxPolicy:
    """The sandbox's own limits; a request can only ask for less."""

    child_memory_mb: int = 2048
    child_cpu_s: int = 3600
    max_run_s: int = 3600
    max_output_bytes: int = 4096 * MIB
    max_line_bytes: int = MAX_LINE_BYTES
    child_fsize_mb: int = 4096
    child_nofile: int = 1024
    poll_s: float = 0.2
    python: str = sys.executable
    sweep: bool = True  # kill every descendant after each job (needs /proc)
    child_module: str = "app.sandbox.child"  # tests substitute a misbehaving fake
    extra_env: tuple[tuple[str, str], ...] = ()  # tests: PYTHONPATH for the fake child
    # uid split (the container, see ``main``): the child runs as ``child_uid`` with group ``gid``
    # and no capabilities; the server keeps euid 0 (it can start and kill the child, the child
    # cannot signal it) and touches files as ``fs_uid``:``gid``. None: same uid (tests).
    child_uid: int | None = None
    fs_uid: int | None = None
    gid: int | None = None

    @property
    def uid_split(self) -> bool:
        return self.child_uid is not None and self.fs_uid is not None and self.gid is not None


def set_fs_ids(uid: int, gid: int) -> None:
    """Set this thread's file-system uid/gid (Linux); threads started later inherit them.

    With a non-zero fsuid the kernel drops the file capabilities (DAC override) from the
    effective set and files are created as ``uid:gid``; ``set_fs_ids(0, 0)`` restores them.
    """
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    libc.setfsgid(gid)
    libc.setfsuid(uid)
    # Both calls return the previous id and never report failure: read the ids back (-1 is
    # invalid, so it changes nothing and returns the current id).
    if libc.setfsuid(-1) != uid or libc.setfsgid(-1) != gid:
        raise OSError("setfsuid/setfsgid failed")


def set_subreaper() -> None:
    """Make orphaned descendants re-parent to this process (Linux ``prctl``)."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "prctl(PR_SET_CHILD_SUBREAPER) failed")


def _ppid(stat_file: Path) -> int | None:
    try:
        data = stat_file.read_bytes()
    except OSError:
        return None
    # "pid (comm) state ppid ...": comm may contain spaces and parentheses.
    tail = data[data.rfind(b")") + 1 :].split()
    if len(tail) < 2 or not tail[1].isdigit():
        return None
    return int(tail[1])


def descendants(root_pid: int, proc_root: Path) -> list[int]:
    """Every process below ``root_pid`` (from ``/proc/<pid>/stat`` parent links)."""
    parents: dict[int, int] = {}
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        ppid = _ppid(entry / "stat")
        if ppid is not None:
            parents[int(entry.name)] = ppid
    found: set[int] = set()
    frontier = {root_pid}
    while frontier:
        kids = {pid for pid, ppid in parents.items() if ppid in frontier}
        kids -= found | {root_pid}
        found |= kids
        frontier = kids
    return sorted(found)


def kill_tree(root_pid: int, proc_root: Path, *, include_root: bool = False) -> int:
    """SIGKILL every descendant of ``root_pid`` (and the root itself if asked) until none is left.

    Killed processes are reaped when they are this process's children (the server is a child
    subreaper, so orphans are); returns how many signals were sent.
    """
    if sys.platform == "win32":
        return 0
    killed = 0
    for _ in range(50):
        pids = descendants(root_pid, proc_root)
        if include_root and proc_root.joinpath(str(root_pid)).is_dir():
            pids.append(root_pid)
        if not pids:
            break
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
        killed += len(pids)
        time.sleep(0.05)
        _reap()
    _reap()
    return killed


def _reap() -> None:
    if sys.platform == "win32":
        return
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def remove_tree(path: Path) -> None:
    """``rmtree`` that also removes read-only files (Windows test hosts)."""

    def retry(func: Any, target: str, _exc: BaseException) -> None:
        with contextlib.suppress(OSError):
            os.chmod(target, 0o700)
            func(target)

    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, onexc=retry)
    else:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def child_env(work: Path) -> dict[str, str]:
    """Clean environment for the child: no inherited variables (credentials) besides PATH."""
    tmp = str(work / "tmp")
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": tmp,
        "TMPDIR": tmp,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in ("DFIR_TOOL_VERSIONS",):
        if key in os.environ:
            env[key] = os.environ[key]
    if sys.platform == "win32":  # CreateProcess and the interpreter need these on test hosts
        for key in ("SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "PYTHONPATH"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


class _OutputPump:
    """Copies the child's stdout lines into ``events.jsonl`` with caps (reader thread)."""

    def __init__(self, out_dir: Path, max_bytes: int, max_line: int) -> None:
        self.events_path = out_dir / EVENTS_FILE
        self.progress_path = out_dir / PROGRESS_FILE
        self.max_bytes = max_bytes
        self.max_line = max_line
        self.bytes = 0
        self.lines = 0
        self.result_seen = False
        self.violation: str | None = None
        self.hash = hashlib.sha256()
        self._last_progress = 0.0
        fd = os.open(self.events_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.fh = os.fdopen(fd, "wb")

    def _progress(self, payload: bytes) -> bool:
        if decode_progress(payload) is None:
            return False
        now = time.monotonic()
        if now - self._last_progress >= 0.2:
            self._last_progress = now
            with contextlib.suppress(OSError):
                self.progress_path.write_bytes(payload[:32])
        return True

    def pump(self, stream: IO[bytes]) -> None:
        try:
            while True:
                line = stream.readline(self.max_line + 1)
                if not line:
                    return
                if len(line) > self.max_line or not line.endswith(b"\n") or self.result_seen:
                    self.violation = "protocol"
                    return
                kind = line[:1]
                if kind == b"P":
                    if not self._progress(line[1:].strip()):
                        self.violation = "protocol"
                        return
                    continue
                if kind not in (b"E", b"R") or (kind == b"R" and len(line) > MAX_RESULT_BYTES):
                    self.violation = "protocol"
                    return
                if self.bytes + len(line) > self.max_bytes:
                    self.violation = "output_limit"
                    return
                self.fh.write(line)
                self.hash.update(line)
                self.bytes += len(line)
                self.lines += 1
                self.result_seen = kind == b"R"
        except (OSError, ValueError):
            self.violation = self.violation or "protocol"

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.fh.flush()
            os.fsync(self.fh.fileno())
        with contextlib.suppress(OSError):
            self.fh.close()


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ProtocolError(f"{path.name} too large")
    return data


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class SandboxServer:
    def __init__(
        self,
        in_dir: Path,
        out_dir: Path,
        work_dir: Path,
        policy: SandboxPolicy | None = None,
        *,
        proc_root: Path = Path("/proc"),
    ) -> None:
        self.in_dir = in_dir
        self.out_dir = out_dir
        self.work_dir = work_dir
        self.policy = policy or SandboxPolicy()
        self.proc_root = proc_root
        self._last_beat = 0.0

    # ------------------------------------------------------------------ housekeeping

    def heartbeat(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_beat < 5.0:
            return
        self._last_beat = now
        with contextlib.suppress(OSError):
            (self.work_dir / HEARTBEAT_FILE).write_bytes(str(int(time.time())).encode())

    @contextlib.contextmanager
    def _fs_root(self) -> Iterator[None]:
        """Root file access while removing what the child wrote (uid split only)."""
        if not self.policy.uid_split:
            yield
            return
        set_fs_ids(0, 0)
        try:
            yield
        finally:
            set_fs_ids(self.policy.fs_uid, self.policy.gid)  # type: ignore[arg-type]

    def _remove_work(self, path: Path) -> None:
        with self._fs_root():
            remove_tree(path)

    def startup(self) -> None:
        """Forget unfinished work of an earlier server run (its outputs and scratch dirs)."""
        if self.policy.uid_split:
            # The child (group ``gid``) may only traverse to its own job's work directory and
            # never sees the output spool, so it cannot claim or answer a job itself.
            os.chmod(self.work_dir, 0o710)  # noqa: S103  # nosec B103 - group: traverse only
            os.chmod(self.out_dir, 0o700)
        for entry in self._job_entries(self.out_dir):
            if not (entry / EXIT_FILE).is_file():
                remove_tree(entry)
        for entry in self._job_entries(self.work_dir):
            self._remove_work(entry)
        self.heartbeat(force=True)

    @staticmethod
    def _job_entries(root: Path) -> list[Path]:
        try:
            return sorted(p for p in root.iterdir() if JOB_DIR.fullmatch(p.name))
        except OSError:
            return []

    def pending(self) -> str | None:
        """A ready job without an output directory (the worker keeps at most one)."""
        for entry in self._job_entries(self.in_dir):
            if (entry / READY_FILE).is_file() and not (self.out_dir / entry.name).exists():
                return entry.name
        return None

    def sweep(self) -> int:
        """Kill and reap every descendant of this process; returns how many were killed."""
        if not self.policy.sweep or sys.platform == "win32" or not self.proc_root.is_dir():
            _reap()
            return 0
        return kill_tree(os.getpid(), self.proc_root)

    # ------------------------------------------------------------------ jobs

    def run_once(self) -> str | None:
        name = self.pending()
        if name is None:
            return None
        self.run_job(name)
        return name

    def serve_forever(self, stop: threading.Event | None = None) -> None:
        self.startup()
        while stop is None or not stop.is_set():
            self.heartbeat()
            try:
                name = self.run_once()
            except Exception:  # keep serving; the worker times out the job
                log.exception("sandbox_job_error")
                name = None
            if name is None:
                if stop is not None:
                    stop.wait(self.policy.poll_s)
                else:
                    time.sleep(self.policy.poll_s)

    def _kill(self, proc: subprocess.Popen[bytes]) -> None:
        if proc.poll() is None:
            if sys.platform != "win32":
                with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                    os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(OSError):
                proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=10)

    def run_job(self, name: str) -> ExitInfo | None:
        job_in = self.in_dir / name
        out = self.out_dir / name
        for stale in self._job_entries(self.out_dir):  # one slot: earlier outputs are stale
            if stale.name != name:
                remove_tree(stale)
        try:
            out.mkdir(mode=0o700)
        except FileExistsError:
            return None
        started = time.monotonic()
        pump = _OutputPump(out, self.policy.max_output_bytes, self.policy.max_line_bytes)

        def finish(reason: str, returncode: int | None) -> ExitInfo | None:
            pump.close()
            if not job_in.is_dir():  # the worker gave up: nobody will read this
                remove_tree(out)
                log.info("sandbox_job_abandoned", job=name)
                return None
            info = ExitInfo(
                reason=reason,
                returncode=returncode,
                duration_ms=int((time.monotonic() - started) * 1000),
                output_bytes=pump.bytes,
                lines=pump.lines,
                sha256=pump.hash.hexdigest() if pump.bytes else EMPTY_SHA256,
                result_seen=pump.result_seen,
            )
            with contextlib.suppress(OSError):
                _write_atomic(out / EXIT_FILE, info.encode())
            log.info("sandbox_job_finished", job=name, **info.summary())
            return info

        try:
            request = SandboxRequest.decode(_read_bounded(job_in / REQUEST_FILE, MAX_REQUEST_BYTES))
        except (OSError, ProtocolError):
            return finish("bad_request", None)
        timeout = min(request.timeout_s, self.policy.max_run_s)
        pump.max_bytes = min(request.max_output_bytes + MAX_RESULT_BYTES, pump.max_bytes)
        work = self.work_dir / name
        self._remove_work(work)
        work.mkdir(mode=0o700)
        (work / "tmp").mkdir(mode=0o700)
        split = self.policy.uid_split
        if split:  # writable for the child through the shared group, nothing else is
            os.chmod(work, 0o770)  # noqa: S103  # nosec B103 - the child group, no others
            os.chmod(work / "tmp", 0o770)  # noqa: S103  # nosec B103
        argv = [
            self.policy.python,
            "-m",
            self.policy.child_module,
            "--in",
            str(job_in),
            "--work",
            str(work),
            "--memory-mb",
            str(self.policy.child_memory_mb),
            "--cpu-s",
            str(min(self.policy.child_cpu_s, timeout + 5)),
            "--fsize-mb",
            str(self.policy.child_fsize_mb),
            "--nofile",
            str(self.policy.child_nofile),
        ]
        log.info("sandbox_job_started", job=name, parser=request.parser, timeout_s=timeout)
        stderr_path = work / "child.stderr"
        try:
            with stderr_path.open("wb") as err:
                proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell  # nosec B603
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=err,
                    cwd=str(work),
                    env={**child_env(work), **dict(self.policy.extra_env)},
                    close_fds=True,
                    shell=False,
                    start_new_session=sys.platform != "win32",
                    # uid split: real, effective and saved ids all become the child's, which
                    # clears every capability before the child runs.
                    user=self.policy.child_uid if split else None,
                    group=self.policy.gid if split else None,
                    extra_groups=[] if split else None,
                    umask=0o077 if split else -1,
                )
        except OSError:
            self._remove_work(work)
            return finish("failed_start", None)
        if proc.stdout is None:  # cannot happen with stdout=PIPE
            self._kill(proc)
            self._remove_work(work)
            return finish("failed_start", None)
        reader = threading.Thread(target=pump.pump, args=(proc.stdout,), daemon=True)
        reader.start()
        reason: str | None = None
        while True:
            try:
                proc.wait(timeout=self.policy.poll_s)
                break
            except subprocess.TimeoutExpired:
                pass
            self.heartbeat()
            if time.monotonic() - started > timeout:
                reason = "timeout"
            elif not job_in.is_dir():
                reason = "abandoned"
            elif (job_in / CANCEL_FILE).exists():
                reason = "cancelled"
            elif pump.violation is not None:
                reason = pump.violation
            if reason is not None:
                break
        self._kill(proc)
        self.sweep()  # nothing the child started survives (and holds the pipe open)
        reader.join(timeout=10)
        with contextlib.suppress(OSError):
            proc.stdout.close()
        returncode = proc.returncode
        if reason is None:
            if pump.violation is not None:
                reason = pump.violation
            elif returncode == 0 and pump.result_seen:
                reason = "ok"
            elif returncode is not None and returncode < 0:
                reason = "killed"
            else:
                reason = "child_error"
        self._log_stderr(name, stderr_path)
        self._remove_work(work)
        if reason == "abandoned":
            reason = "cancelled"
        return finish(reason, returncode)

    @staticmethod
    def _log_stderr(name: str, path: Path) -> None:
        """Log only the size of the child's stderr and an exception class name, if any."""
        try:
            size = path.stat().st_size
            with path.open("rb") as fh:
                fh.seek(max(size - 4096, 0))
                tail = fh.read(4096)
        except OSError:
            return
        if not size:
            return
        last = tail.strip().splitlines()[-1] if tail.strip() else b""
        match = _EXC_NAME.match(last)
        log.warning(
            "sandbox_child_stderr",
            job=name,
            stderr_bytes=size,
            exception=match.group(1).decode("ascii") if match else None,
        )


# ---------------------------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    number = int(value)
    if number < 1:
        raise ValueError(f"{name} must be positive")
    return number


def policy_from_env() -> SandboxPolicy:
    return SandboxPolicy(
        child_memory_mb=_env_int("SANDBOX_CHILD_MEMORY_MB", 2048),
        child_cpu_s=_env_int("SANDBOX_CHILD_CPU_S", 3600),
        max_run_s=_env_int("SANDBOX_MAX_RUN_S", 3600),
        max_output_bytes=_env_int("SANDBOX_MAX_OUTPUT_MB", 4096) * MIB,
        max_line_bytes=min(_env_int("SANDBOX_MAX_LINE_KB", 4096) * 1024, MAX_LINE_BYTES),
        child_fsize_mb=_env_int("SANDBOX_CHILD_FSIZE_MB", 4096),
    )


def uid_split_from_env() -> tuple[int, int, int] | None:
    """``(server fs uid, child uid, shared gid)`` from the environment: all set, none root."""
    names = ("SANDBOX_SERVER_UID", "SANDBOX_CHILD_UID", "SANDBOX_GID")
    if not all(os.environ.get(n, "").strip() for n in names):
        return None
    fs_uid, child_uid, gid = (_env_int(n, 0) for n in names)
    if fs_uid == child_uid:
        raise ValueError("SANDBOX_CHILD_UID must differ from SANDBOX_SERVER_UID")
    return fs_uid, child_uid, gid


def health(work_dir: Path) -> int:
    try:
        age = time.time() - (work_dir / HEARTBEAT_FILE).stat().st_mtime
    except OSError:
        return 1
    return 0 if age < HEALTH_MAX_AGE_S else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.sandbox.server")
    parser.add_argument("--in", dest="in_dir", default=os.environ.get("SANDBOX_IN_DIR"))
    parser.add_argument("--out", dest="out_dir", default=os.environ.get("SANDBOX_OUT_DIR"))
    parser.add_argument("--work", dest="work_dir", default=os.environ.get("SANDBOX_WORK_DIR"))
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args(argv)
    if not (args.in_dir and args.out_dir and args.work_dir):
        print("SANDBOX_IN_DIR, SANDBOX_OUT_DIR and SANDBOX_WORK_DIR are required", file=sys.stderr)  # noqa: T201
        return 2
    work_dir = Path(args.work_dir)
    if args.health:
        return health(work_dir)

    from app.core.logging import setup_logging

    setup_logging(os.environ.get("LOG_LEVEL", "INFO").upper(), True)
    policy = policy_from_env()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # The container starts as root with only SETUID, SETGID, KILL and DAC_OVERRIDE: the
        # server starts each child as another uid and keeps the right to kill it, while a
        # compromised child cannot signal (stop) the server or touch its files.
        try:
            split = uid_split_from_env()
        except ValueError:
            split = None
        if split is None:
            log.error("sandbox_root_needs_uid_split")
            return 2
        fs_uid, child_uid, gid = split
        if sys.platform != "win32":  # always true here (geteuid exists); for type checkers
            os.setgroups([])
        os.umask(0o077)
        set_fs_ids(fs_uid, gid)
        policy = replace(policy, child_uid=child_uid, fs_uid=fs_uid, gid=gid)
    elif os.environ.get("SANDBOX_ALLOW_SAME_UID") != "1":
        # Without the split a parser could stop the server and outlive its job.
        log.error("sandbox_needs_uid_split")
        return 2
    if sys.platform.startswith("linux"):
        try:
            set_subreaper()
        except OSError:
            log.error("sandbox_no_subreaper")
            return 2
    log.info(
        "sandbox_started",
        uid_split=policy.uid_split,
        memory_mb=policy.child_memory_mb,
        max_run_s=policy.max_run_s,
        max_output_mb=policy.max_output_bytes // MIB,
    )
    SandboxServer(Path(args.in_dir), Path(args.out_dir), work_dir, policy).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
