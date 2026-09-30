"""systemd journal exports (``journalctl -o json``, one JSON object per line), as collected by the
Phase 5 Linux collector (guide 10.3 ``linux_auth`` journal input).

One record per line. ``__REALTIME_TIMESTAMP`` (microseconds since the Unix epoch, UTC) is the
time; ``MESSAGE`` may be a string or a byte array (decoded as UTF-8). The message goes through the
``linux_auth`` classifier, so sshd/sudo/useradd lines get the same event codes as auth.log. Lines
are bounded by ``max_line_bytes``; a line that is not a JSON object or has no usable time is an
error.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import Event, ParseContext, decimal_int, record_cap_reached, snippet
from app.parsers.linux_auth import LinuxAuthParser, _Parsed
from app.parsers.registry import register
from app.parsers.textio import head_text, iter_lines
from app.parsers.timeconv import TimestampError, unix_micros

SOURCE = "journal"
KEEP = (
    "_HOSTNAME",
    "SYSLOG_IDENTIFIER",
    "_COMM",
    "_EXE",
    "_CMDLINE",
    "_PID",
    "_UID",
    "_GID",
    "_SYSTEMD_UNIT",
    "PRIORITY",
    "_TRANSPORT",
    "_BOOT_ID",
    "__CURSOR",
)


def _field(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(b, int) and 0 <= b < 256 for b in value[:65536]):
        return bytes(value[:65536]).decode("utf-8", "replace")
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    return None


def _int(value: str | None) -> int | None:
    number = decimal_int(value, 10)
    return number if number is not None and number < 2**31 else None


@register
class JournalJsonParser:
    name = "journal_json"
    version = "1.0.0"
    description = "systemd journal JSON export (journalctl -o json), auth classification"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        text = head_text(head).lstrip()
        if text.startswith(b"{") and b'"__REALTIME_TIMESTAMP"' in text[:8192]:
            return 0.9
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        auth = LinuxAuthParser()
        stats.assumptions["timezone"] = "UTC (__REALTIME_TIMESTAMP)"
        for line in iter_lines(ctx.path, ctx.limits, stats, ctx.progress):
            if record_cap_reached(ctx):
                return
            stats.read()
            location = f"line {line.number}"
            if line.too_long:
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            if not line.data.strip():
                stats.skip(location, "blank")
                continue
            try:
                obj = json.loads(line.data)
            except (ValueError, RecursionError):
                stats.error(location, "invalid_json", snippet(line.data))
                continue
            if not isinstance(obj, dict):
                stats.error(location, "not_an_object")
                continue
            raw_ts = _field(obj.get("__REALTIME_TIMESTAMP"))
            micros = decimal_int(raw_ts, 20)
            if micros is None:
                reason = "no __REALTIME_TIMESTAMP" if not raw_ts else snippet(raw_ts)
                stats.error(location, "bad_timestamp", reason)
                continue
            try:
                converted = unix_micros(micros)
            except TimestampError as exc:
                stats.error(location, "bad_timestamp", str(exc))
                continue
            if converted is None:
                stats.error(location, "bad_timestamp", "no __REALTIME_TIMESTAMP")
                continue
            fields = {k: _field(obj.get(k)) for k in KEEP}
            message = _field(obj.get("MESSAGE")) or ""
            program = fields["SYSLOG_IDENTIFIER"] or fields["_COMM"]
            parsed = _Parsed(
                converted.ts,
                converted.original,
                fields["_HOSTNAME"],
                program,
                _int(fields["_PID"]),
                message,
                "journal_json",
                {},
            )
            event = auth._event(ctx, line.number, line.offset, message, parsed)
            event.source_type = SOURCE
            event.raw.pop("line", None)
            event.raw["journal"] = {k: v for k, v in fields.items() if v is not None}
            event.cmdline = event.cmdline or fields["_CMDLINE"]
            event.file_path = fields["_EXE"]
            if event.event_code is None:
                event.event_code = "journal_entry"
            yield event
