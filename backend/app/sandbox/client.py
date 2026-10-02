"""Worker side of the parser sandbox: the slot lock, the request, the wait and the output.

``hold_slot`` gives one worker process exclusive use of the spool. While it is held:

* stale job directories from a crashed holder are wiped (only names matching ``job-<hex>``);
* the job's evidence copy, request and ``ready`` marker go to ``<in>/<job dir>/``;
* on exit (success, error, cancel or a Celery time limit) a cancel marker is written and both
  spool directories are removed before the lock is released, so the sandbox never sees two jobs'
  evidence and a later job never starts while this one's output still exists.

The lock is ``fcntl.flock`` (``msvcrt.locking`` on Windows test hosts) on a file in the
worker-private scratch volume; the kernel releases it if the worker dies.

``SandboxClient.run`` waits for the sandbox to claim the job and to write ``exit.json``, calling
``tick`` (the job heartbeat, which also notices a cancel) meanwhile. ``SandboxOutput`` checks the
output against ``exit.json`` (size and SHA-256) before anything is decoded, then yields events
and the result; every line is untrusted.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from app.parsers.base import Event
from app.sandbox.protocol import (
    CANCEL_FILE,
    EVENTS_FILE,
    EXIT_FILE,
    JOB_DIR,
    MAX_EXIT_BYTES,
    MAX_LINE_BYTES,
    PROGRESS_FILE,
    READY_FILE,
    REQUEST_FILE,
    ChildResult,
    ExitInfo,
    ProtocolError,
    SandboxRequest,
    decode_event,
    decode_progress,
    decode_result,
)
from app.sandbox.server import remove_tree

LOCK_FILE = "sandbox-slot.lock"
EXIT_GRACE_S = 120


class SandboxUnavailableError(Exception):
    """The sandbox did not claim or finish the job in time (transient: the job is retried)."""


@dataclass(frozen=True)
class SlotDirs:
    name: str
    in_dir: Path
    out_dir: Path


def _try_lock(fd: int) -> bool:
    if sys.platform == "win32":
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        with contextlib.suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    with contextlib.suppress(OSError):
        fcntl.flock(fd, fcntl.LOCK_UN)


def _wipe(root: Path, keep: str | None = None) -> None:
    try:
        entries = list(root.iterdir())
    except OSError:
        return
    for entry in entries:
        if JOB_DIR.fullmatch(entry.name) and entry.name != keep:
            remove_tree(entry)


@contextlib.contextmanager
def hold_slot(
    lock_dir: Path,
    in_root: Path,
    out_root: Path,
    *,
    tick: Callable[[], None],
    poll_s: float = 1.0,
) -> Iterator[SlotDirs]:
    """Exclusive use of the spool; ``tick`` runs while another worker holds it."""
    lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(lock_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        while not _try_lock(fd):
            tick()
            time.sleep(poll_s)
        try:
            _wipe(in_root)
            _wipe(out_root)
            name = f"job-{uuid.uuid4().hex}"
            dirs = SlotDirs(name, in_root / name, out_root / name)
            # Group-readable: the sandbox child runs as another uid in this group (read-only
            # mount there); the server and this worker share the owner uid.
            with contextlib.suppress(OSError):
                os.chmod(in_root, 0o750)  # noqa: S103  # nosec B103 - group read, no others
            dirs.in_dir.mkdir(mode=0o750)
            os.chmod(dirs.in_dir, 0o750)  # noqa: S103  # nosec B103 - umask independent
            try:
                yield dirs
            finally:
                with contextlib.suppress(OSError):
                    (dirs.in_dir / CANCEL_FILE).touch()
                remove_tree(dirs.in_dir)
                remove_tree(dirs.out_dir)
        finally:
            _unlock(fd)
    finally:
        os.close(fd)


def _write_new(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o640)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _read_small(path: Path, limit: int) -> bytes:
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ProtocolError(f"{path.name} too large")
    return data


@dataclass
class BadLine:
    """A line of sandbox output that did not decode (counted as an error by the worker)."""

    number: int
    reason: str


class SandboxOutput:
    def __init__(self, out_dir: Path, exit_info: ExitInfo) -> None:
        self.out_dir = out_dir
        self.exit = exit_info
        self.result: ChildResult | None = None

    @property
    def events_path(self) -> Path:
        return self.out_dir / EVENTS_FILE

    def verify(self) -> None:
        """The output file is exactly what the server recorded (size and SHA-256)."""
        path = self.events_path
        if not path.is_file():
            if self.exit.output_bytes == 0:
                return
            raise ProtocolError("sandbox output is missing")
        if path.stat().st_size != self.exit.output_bytes:
            raise ProtocolError("sandbox output size differs from its exit record")
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        if self.exit.output_bytes and digest.hexdigest() != self.exit.sha256:
            raise ProtocolError("sandbox output hash differs from its exit record")

    def items(self) -> Iterator[Event | BadLine]:
        """Decoded events (or ``BadLine``); sets ``result`` from the final ``R`` line."""
        if not self.events_path.is_file():
            return
        with self.events_path.open("rb") as fh:
            number = 0
            while True:
                line = fh.readline(MAX_LINE_BYTES + 1)
                if not line:
                    return
                number += 1
                if self.result is not None:
                    raise ProtocolError("sandbox output continues after the result")
                if line.startswith(b"R"):
                    try:
                        self.result = decode_result(line.rstrip(b"\n"))
                    except ProtocolError as exc:
                        yield BadLine(number, f"bad result: {exc}")
                    continue
                try:
                    yield decode_event(line.rstrip(b"\n"))
                except ProtocolError as exc:
                    yield BadLine(number, str(exc))


class SandboxClient:
    def __init__(self, *, start_timeout_s: float, poll_s: float = 0.5) -> None:
        self.start_timeout_s = start_timeout_s
        self.poll_s = poll_s

    def progress(self, slot: SlotDirs) -> float:
        try:
            value = decode_progress(_read_small(slot.out_dir / PROGRESS_FILE, 32))
        except (OSError, ProtocolError):
            return 0.0
        return value or 0.0

    def run(
        self, slot: SlotDirs, request: SandboxRequest, *, tick: Callable[[float], None]
    ) -> SandboxOutput:
        """Hand the job to the sandbox and wait for its exit record."""
        _write_new(slot.in_dir / REQUEST_FILE, request.encode())
        _write_new(slot.in_dir / READY_FILE, b"1")
        deadline = time.monotonic() + self.start_timeout_s
        while not slot.out_dir.is_dir():
            if time.monotonic() > deadline:
                raise SandboxUnavailableError("the parser sandbox did not pick up the job")
            tick(0.0)
            time.sleep(self.poll_s)
        deadline = time.monotonic() + request.timeout_s + EXIT_GRACE_S
        exit_path = slot.out_dir / EXIT_FILE
        while not exit_path.is_file():
            if time.monotonic() > deadline:
                raise SandboxUnavailableError("the parser sandbox did not finish the job")
            if not slot.out_dir.is_dir():
                raise SandboxUnavailableError("the parser sandbox dropped the job")
            tick(self.progress(slot))
            time.sleep(self.poll_s)
        return SandboxOutput(slot.out_dir, ExitInfo.decode(_read_small(exit_path, MAX_EXIT_BYTES)))
