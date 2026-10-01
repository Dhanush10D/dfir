"""Parser child: ``python -m app.sandbox.child --in DIR --work DIR [limits]``.

Started by the sandbox server for exactly one job, inside the ``parser-sandbox`` container:

1. it lowers its own resource limits (address space, CPU seconds, file size, open files, no core
   dumps) before it reads any evidence; soft and hard limits are set together and cannot be
   raised again (the container has no ``CAP_SYS_RESOURCE``);
2. it reads the request, runs the parser on the read-only evidence copy and writes cleaned events,
   progress and the final result to stdout (``protocol``); external engines write only below the
   job's work directory (``HOME``/``TMPDIR`` point there);
3. it has no network, no database and no object-store access: none exists in the container, and
   its environment holds no credentials.

Exceptions are reported as data (``input_error`` with the parser's message, ``crash`` with the
exception type only), never as a traceback that could carry evidence content.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import BinaryIO

from app.parsers.base import ParseContext, ParserInputError, ParseStats
from app.parsers.registry import UnknownParserError, get_parser
from app.sandbox.protocol import (
    EVIDENCE_FILE,
    MAX_REQUEST_BYTES,
    REQUEST_FILE,
    ProtocolError,
    ResultStatus,
    SandboxRequest,
    encode_event,
    encode_progress,
    encode_result,
)

MIB = 1024 * 1024
PROGRESS_EVERY_S = 0.5


def set_limits(*, memory_mb: int, cpu_s: int, fsize_mb: int, nofile: int) -> None:
    """Lower soft and hard limits of this process (POSIX only; a no-op on Windows test hosts)."""
    if sys.platform == "win32":
        return
    import resource

    wanted = [
        (resource.RLIMIT_AS, memory_mb * MIB),
        (resource.RLIMIT_CPU, cpu_s),
        (resource.RLIMIT_FSIZE, fsize_mb * MIB),
        (resource.RLIMIT_NOFILE, nofile),
        (resource.RLIMIT_CORE, 0),
    ]
    for limit, value in wanted:
        _, hard = resource.getrlimit(limit)
        if hard != resource.RLIM_INFINITY:
            value = min(value, hard)
        resource.setrlimit(limit, (value, value))


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ProtocolError(f"{path.name} is larger than {limit} bytes")
    return data


class _Progress:
    """Writes ``P`` lines at most every PROGRESS_EVERY_S."""

    def __init__(self, out: BinaryIO) -> None:
        self.out = out
        self.last = 0.0

    def __call__(self, fraction: float) -> None:
        now = time.monotonic()
        if now - self.last < PROGRESS_EVERY_S:
            return
        self.last = now
        self.out.write(encode_progress(fraction))
        self.out.flush()


def run(in_dir: Path, work_dir: Path, out: BinaryIO) -> ResultStatus:
    stats = ParseStats()
    yielded = 0
    status: ResultStatus = "ok"
    message: str | None = None
    error_type: str | None = None
    try:
        request = SandboxRequest.decode(read_bounded(in_dir / REQUEST_FILE, MAX_REQUEST_BYTES))
        parser = get_parser(request.parser)
        tmp = work_dir / "tmp"
        tmp.mkdir(mode=0o700, exist_ok=True)
        ctx = ParseContext(
            path=in_dir / EVIDENCE_FILE,
            evidence_id=str(request.evidence_id),
            case_id=str(request.case_id),
            source_file=request.source_file,
            host_hint=request.host_hint,
            timezone=request.timezone,
            year=request.year,
            reference_time=request.reference_time,
            reference_source=request.reference_source,
            params=request.params,
            stats=stats,
            limits=request.limits.to_limits(),
            tools=request.tools.to_tools(),
            work_dir=tmp,
            progress=_Progress(out),
        )
        for event in parser.parse(ctx):
            out.write(encode_event(event))
            yielded += 1
    except UnknownParserError:
        status, message = "input_error", "unknown parser"
    except ParserInputError as exc:
        status, message = "input_error", str(exc)
    except Exception as exc:  # noqa: BLE001 - reported as data; the type only (no evidence text)
        status, error_type = "crash", type(exc).__name__
    out.write(encode_result(status, stats, yielded, message=message, error_type=error_type))
    out.flush()
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.sandbox.child")
    parser.add_argument("--in", dest="in_dir", required=True, type=Path)
    parser.add_argument("--work", dest="work_dir", required=True, type=Path)
    parser.add_argument("--memory-mb", type=int, default=2048)
    parser.add_argument("--cpu-s", type=int, default=3600)
    parser.add_argument("--fsize-mb", type=int, default=4096)
    parser.add_argument("--nofile", type=int, default=1024)
    args = parser.parse_args(argv)
    set_limits(
        memory_mb=args.memory_mb, cpu_s=args.cpu_s, fsize_mb=args.fsize_mb, nofile=args.nofile
    )
    run(args.in_dir, args.work_dir, sys.stdout.buffer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
