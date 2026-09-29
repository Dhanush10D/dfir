"""External forensic engines (Sleuth Kit, Volatility 3, Zeek): one hardened way to run them.

Rules (spec decision 9):

* the binary is looked up by a fixed name on ``ToolConfig.search_path`` (else ``PATH``); a missing
  engine raises ``ToolMissingError`` (a ``ParserInputError``: the job fails with a clear message);
* argv is a fixed list built by the parser, never a shell string (``shell=False``); evidence
  content never becomes an argument except as the scratch path of the evidence copy;
* the child gets a clean environment (no database/object-store credentials), stdin closed, its own
  session/process group, and its working directory inside the job's scratch ``work_dir``;
* stdout/stderr go to files in scratch; their size (plus any ``watch`` paths the engine writes to)
  is polled against ``max_output_bytes`` and the wall clock against ``timeout_s``; ``heartbeat``
  (the job's progress callback) runs on every poll so cancellation stops the engine promptly;
* on timeout, output overflow or cancellation the whole process group is killed.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess  # nosec B404 - fixed argv lists, shell=False, clean env (see module docstring)
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from app.parsers.base import ParserInputError, ToolConfig, snippet

POLL_S = 0.5
STDERR_TAIL = 4096
MAX_WATCH_ENTRIES = 10_000


class ToolMissingError(ParserInputError):
    """The engine is not installed in this worker image."""


class ToolFailedError(ParserInputError):
    """The engine ran but could not process the input (non-zero exit)."""


class ToolTimeoutError(Exception):
    pass


class ToolOutputLimitError(Exception):
    pass


@dataclass(frozen=True)
class ToolResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: Path
    stderr_tail: str
    duration_s: float
    output_bytes: int


def find_tool(name: str, cfg: ToolConfig, *, optional_note: str = "") -> str:
    """Absolute path of engine ``name`` or ``ToolMissingError``."""
    found = shutil.which(name, path=cfg.search_path) if cfg.search_path else shutil.which(name)
    if not found:
        note = f" ({optional_note})" if optional_note else ""
        raise ToolMissingError(f"{name!r} is not installed in this worker image{note}")
    return str(Path(found).resolve())


def clean_env(cwd: Path, cfg: ToolConfig) -> dict[str, str]:
    env = {
        "PATH": cfg.search_path or os.environ.get("PATH", ""),
        "HOME": str(cwd),
        "TMPDIR": str(cwd),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    if sys.platform == "win32":  # CreateProcess needs these for .bat/.exe test doubles
        for key in ("SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
            if key in os.environ:
                env[key] = os.environ[key]
    return env


def _size(paths: Iterable[Path]) -> int:
    total = 0
    seen = 0
    for path in paths:
        try:
            if path.is_dir():
                for entry in path.rglob("*"):
                    seen += 1
                    if seen > MAX_WATCH_ENTRIES:
                        return 1 << 62  # an engine spraying files is over any limit
                    if entry.is_file() and not entry.is_symlink():
                        total += entry.stat().st_size
            elif path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _kill(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=10)


def _tail(path: Path) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            fh.seek(max(size - STDERR_TAIL, 0))
            data = fh.read(STDERR_TAIL)
    except OSError:
        return ""
    text = data.decode("utf-8", "replace").strip()
    return snippet(text[-1000:]) if text else ""


def run_tool(
    argv: Sequence[str],
    *,
    cwd: Path,
    stdout: Path,
    cfg: ToolConfig,
    heartbeat: Callable[[], None],
    watch: Sequence[Path] = (),
    timeout_s: int | None = None,
) -> ToolResult:
    """Run ``argv`` (argv[0] from ``find_tool``) and wait, enforcing time and output limits."""
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("argv[0] must be an absolute path from find_tool()")
    cwd.mkdir(mode=0o700, parents=True, exist_ok=True)
    stderr = stdout.with_name(stdout.name + ".stderr")
    limit = cfg.max_output_bytes
    deadline_s = timeout_s if timeout_s is not None else cfg.timeout_s
    started = time.monotonic()
    kwargs: dict[str, object] = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    with stdout.open("xb") as out, stderr.open("xb") as err:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell  # nosec B603
            list(argv),
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=clean_env(cwd, cfg),
            close_fds=True,
            shell=False,
            **kwargs,  # type: ignore[call-overload]
        )
        try:
            while True:
                try:
                    proc.wait(timeout=POLL_S)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() - started > deadline_s:
                    _kill(proc)
                    raise ToolTimeoutError(f"{Path(argv[0]).name} exceeded {deadline_s} s")
                used = _size([stdout, stderr, *watch])
                if used > limit:
                    _kill(proc)
                    raise ToolOutputLimitError(
                        f"{Path(argv[0]).name} output exceeded {limit // (1024 * 1024)} MiB"
                    )
                heartbeat()
        except BaseException:
            _kill(proc)
            raise
    used = _size([stdout, stderr, *watch])
    if used > limit:
        raise ToolOutputLimitError(
            f"{Path(argv[0]).name} output exceeded {limit // (1024 * 1024)} MiB"
        )
    return ToolResult(
        argv=tuple(argv),
        returncode=int(proc.returncode),
        stdout=stdout,
        stderr_tail=_tail(stderr),
        duration_s=round(time.monotonic() - started, 3),
        output_bytes=used,
    )


def image_tool_versions(names: Iterable[str]) -> dict[str, str]:
    """Versions recorded at image build time in ``DFIR_TOOL_VERSIONS`` (``name version`` lines)."""
    path = os.environ.get("DFIR_TOOL_VERSIONS")
    wanted = set(names)
    found: dict[str, str] = {}
    if not path:
        return found
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh.read(64 * 1024).splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0] in wanted:
                    found[parts[0]] = parts[1][:128]
    except OSError:
        return found
    return found
