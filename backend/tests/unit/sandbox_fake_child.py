"""A misbehaving stand-in for ``app.sandbox.child`` (sandbox server tests only).

The mode comes from the request's ``params["mode"]``; argv matches the real child.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from app.parsers.base import Event, ParseStats
from app.sandbox.protocol import (
    REQUEST_FILE,
    SandboxRequest,
    encode_event,
    encode_progress,
    encode_result,
)

SLEEPER = [sys.executable, "-c", "import time; time.sleep(120)"]


def _event(i: int) -> bytes:
    return encode_event(
        Event(
            ts=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
            source_type="fake",
            message=f"event {i}",
            record_key=f"line:{i}",
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_dir", type=Path)
    parser.add_argument("--work", dest="work_dir", type=Path)
    parser.add_argument("--memory-mb")
    parser.add_argument("--cpu-s")
    parser.add_argument("--fsize-mb")
    parser.add_argument("--nofile")
    args = parser.parse_args()
    request = SandboxRequest.decode((args.in_dir / REQUEST_FILE).read_bytes())
    mode = os.environ.get("FAKE_CHILD_MODE") or request.params.get("mode", "ok")
    out = sys.stdout.buffer
    stats = ParseStats(records_read=3)
    if mode == "ok":
        for i in range(3):
            out.write(_event(i))
        out.write(encode_progress(0.5))
        out.write(encode_result("ok", stats, 3))
    elif mode == "env":
        leaked = sorted(k for k in os.environ if "SECRET" in k or k.startswith("DATABASE"))
        out.write(encode_result("input_error", ParseStats(), 0, message=",".join(leaked) or "-"))
    elif mode == "write_evidence":
        try:
            (args.in_dir / "evil").write_bytes(b"x")
            message = "wrote"
        except OSError:
            message = "refused"
        out.write(encode_result("input_error", ParseStats(), 0, message=message))
    elif mode == "crash":
        out.write(_event(0))
        out.flush()
        return 3
    elif mode == "sleep":
        out.write(_event(0))
        out.flush()
        time.sleep(120)
    elif mode == "sleep_tree":
        subprocess.Popen(SLEEPER, stdout=subprocess.DEVNULL)
        time.sleep(120)
    elif mode == "orphan":  # a grandchild keeps stdout open after the child exits
        subprocess.Popen(SLEEPER, start_new_session=True)
        out.write(encode_result("ok", ParseStats(), 0))
    elif mode == "flood":
        line = _event(1)
        while True:
            out.write(line)
    elif mode == "garbage":
        out.write(b"Zhello\n")
        out.flush()
        time.sleep(30)
    elif mode == "long_line":
        out.write(b"E" + b"x" * (int(request.params.get("size", 2_000_000))))
        out.flush()
        time.sleep(30)
    elif mode == "after_result":
        out.write(encode_result("ok", ParseStats(), 0))
        out.write(_event(1))
    elif mode == "kill_self":
        out.write(_event(0))
        out.flush()
        import signal

        os.kill(os.getpid(), signal.SIGKILL)
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
