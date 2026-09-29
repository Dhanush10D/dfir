"""Linux wtmp / btmp / utmp login records (guide 10.3 ``wtmp``).

glibc x86-64 ``struct utmp`` (384 bytes, little endian). One record per 384-byte entry:
``USER_PROCESS`` -> logon (``btmp``: failed logon), ``DEAD_PROCESS`` -> logoff, ``BOOT_TIME`` ->
boot, ``RUN_LVL`` -> runlevel change / shutdown, ``NEW_TIME``/``OLD_TIME`` -> clock change;
``EMPTY`` and other types are skipped. A trailing partial entry is one error. Times are Unix
seconds + microseconds (UTC).
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import Event, ParseContext, ParserInputError, record_cap_reached
from app.parsers.registry import register
from app.parsers.timeconv import TimestampError, unix_seconds

RECORD = struct.Struct("<h2xi32s4s32s256shhiii16s20s")
SIZE = RECORD.size  # 384
READ_CHUNK = SIZE * 1024
TYPES = {
    1: ("runlevel", "system", "runlevel_change"),
    2: ("boot", "host", "boot"),
    3: ("clock_new", "host", "clock_change"),
    4: ("clock_old", "host", "clock_change"),
    5: ("init_process", "process", "process_start"),
    6: ("login_process", "authentication", "login_prompt"),
    7: ("user_process", "authentication", "logon"),
    8: ("dead_process", "authentication", "logoff"),
}
NAMES = ("wtmp", "btmp", "utmp")


def _s(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _addr(raw: bytes) -> str | None:
    words = struct.unpack("<4I", raw)
    if not any(words):
        return None
    if not any(words[1:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    return str(ipaddress.IPv6Address(raw))


def _kind(filename: str) -> str | None:
    name = filename.rsplit("/", 1)[-1].lower()
    for kind in NAMES:
        if name.startswith(kind):
            return kind
    return None


@register
class WtmpParser:
    name = "wtmp"
    version = "1.0.0"
    description = "Linux wtmp/btmp/utmp login records (glibc x86-64 layout)"
    source_types = NAMES

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if _kind(filename) is None or len(head) < SIZE:
            return 0.0
        if len(head) < 8192 and len(head) % SIZE:
            return 0.0
        ut_type = struct.unpack_from("<h", head, 0)[0]
        return 0.9 if 0 <= ut_type <= 9 else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        kind = _kind(ctx.source_file) or "wtmp"
        total = max(ctx.path.stat().st_size, 1)
        stats.assumptions.update(
            {"timezone": "UTC (Unix time)", "layout": "glibc x86-64", "kind": kind}
        )
        index = 0
        with ctx.path.open("rb") as fh:
            while True:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                stats.bytes_read += len(chunk)
                for off in range(0, len(chunk), SIZE):
                    if record_cap_reached(ctx):
                        return
                    stats.read()
                    record = chunk[off : off + SIZE]
                    location = f"record {index} (byte {index * SIZE})"
                    if len(record) < SIZE:
                        stats.error(location, "truncated_record", f"{len(record)} bytes")
                        continue
                    event = self._event(ctx, kind, index, record, location)
                    index += 1
                    if event is not None:
                        yield event
                ctx.progress(min(fh.tell() / total, 1.0))
        if index == 0 and stats.records_read == 0:
            raise ParserInputError("empty login record file")

    def _event(
        self, ctx: ParseContext, kind: str, index: int, record: bytes, location: str
    ) -> Event | None:
        stats = ctx.stats
        (ut_type, pid, line, ut_id, user, host, _term, _exit, session, sec, usec, addr, _u) = (
            RECORD.unpack(record)
        )
        mapped = TYPES.get(ut_type)
        if mapped is None:
            stats.skip(location, "empty" if ut_type == 0 else f"type_{ut_type}")
            return None
        if not 0 <= usec < 1_000_000:
            stats.error(location, "bad_timestamp", f"usec {usec}")
            return None
        try:
            converted = unix_seconds(sec + usec / 1_000_000 if usec else sec, tag="unix")
        except TimestampError as exc:
            stats.error(location, "bad_timestamp", str(exc))
            return None
        if converted is None:
            stats.skip(location, "no_timestamp")
            return None
        code, category, action = mapped
        user_s, line_s, host_s = _s(user), _s(line), _s(host)
        try:
            src_ip = _addr(addr)
        except ValueError:
            src_ip = None
        outcome = (
            "failure" if kind == "btmp" and ut_type == 7 else ("success" if ut_type == 7 else None)
        )
        if ut_type == 1 and user_s == "shutdown":
            code, action = "shutdown", "shutdown"
        if kind == "btmp" and ut_type == 7:
            message = f"Failed login for {user_s} on {line_s} from {host_s or src_ip or 'local'}"
        elif ut_type == 7:
            message = f"Login {user_s} on {line_s} from {host_s or src_ip or 'local'}"
        elif ut_type == 8:
            message = f"Logout on {line_s}"
        elif ut_type == 2:
            message = f"System boot ({host_s})" if host_s else "System boot"
        elif code == "shutdown":
            message = f"System shutdown ({host_s})" if host_s else "System shutdown"
        elif ut_type == 1:
            message = f"Runlevel change {user_s} ({line_s})"
        else:
            message = f"{code} {user_s} {line_s}".strip()
        raw: dict[str, Any] = {
            "type": ut_type,
            "pid": pid,
            "line": line_s,
            "id": _s(ut_id),
            "user": user_s,
            "host": host_s,
            "session": session,
            "addr": src_ip,
        }
        return Event(
            ts=converted.ts,
            ts_original=converted.original,
            source_type=kind,
            message=message,
            record_key=f"rec:{index}",
            source_record_id=str(index),
            source_file=ctx.source_file,
            host=ctx.host_hint,
            user=user_s or None if ut_type in (6, 7) else None,
            event_code=code,
            event_category=category,
            action=action,
            outcome=outcome,
            pid=pid if pid > 0 else None,
            src_ip=src_ip,
            raw=raw,
        )
