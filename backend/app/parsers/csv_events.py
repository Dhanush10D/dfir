"""Generic CSV/TSV exports (SIEM searches, EDR and firewall exports, spreadsheets) with a header.

The first line is the header; the delimiter is the most frequent of tab, ``;`` and ``,`` in it.
The time column is the first header named like a timestamp (``timestamp``, ``@timestamp``,
``_time``, ``TimeCreated``, ``UtcTime``, ``datetime``, ``date``, ``time``, ...). Each other line is
one event; well-known column names are mapped to the normalized fields (``host``, ``user``,
``src_ip``, ``dst_ip``, ports, ``event_code``, ``action``, ``process_name``, ``cmdline``,
``file_path``, ``protocol``, ``message``) and every column is kept in ``raw.csv``.

Times: ISO 8601 with an offset or ``Z`` is exact; ISO 8601 without one (``2026-09-14 02:10:03``)
is read in the job's ``timezone`` parameter (IANA, default UTC, recorded as an assumption); a
10- or 13-digit number is Unix seconds or milliseconds. A row whose time cannot be read, or with
the wrong number of columns, is an error. One CSV record per line (quoted line breaks are not
supported).
"""

from __future__ import annotations

import csv
import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.parsers.base import (
    Event,
    ParseContext,
    ParserInputError,
    decimal_int,
    record_cap_reached,
    snippet,
)
from app.parsers.linux_auth import _local_to_utc
from app.parsers.registry import register
from app.parsers.textio import head_text, iter_lines
from app.parsers.timeconv import TimestampError, unix_micros, unix_seconds

SOURCE = "csv"
MAX_COLUMNS = 256
MAX_CELL = 8192
DELIMITERS = ("\t", ";", ",")

TIME_COLUMNS = (
    "timestamp", "@timestamp", "_time", "time_created", "timecreated", "utctime", "utc_time",
    "event_time", "eventtime", "time_generated", "timegenerated", "datetime", "date_time",
    "created", "created_at", "logged", "time", "date",
)  # fmt: skip
FIELD_COLUMNS: dict[str, tuple[str, ...]] = {
    "host": ("host", "hostname", "computer", "computername", "computer_name", "device",
             "devicename", "device_name", "machine", "machinename", "workstation"),
    "user": ("user", "username", "user_name", "account", "accountname", "account_name",
             "targetusername", "subjectusername", "login", "principal"),
    "src_ip": ("src_ip", "srcip", "source_ip", "sourceip", "sourceaddress", "source_address",
               "src", "client_ip", "clientip", "c_ip", "remote_ip", "remoteip", "ipaddress",
               "ip_address", "ip"),
    "dst_ip": ("dst_ip", "dstip", "dest_ip", "destip", "destination_ip", "destinationip",
               "destaddress", "destination_address", "dst", "server_ip", "s_ip"),
    "src_port": ("src_port", "srcport", "source_port", "sourceport", "sport"),
    "dst_port": ("dst_port", "dstport", "dest_port", "destport", "destination_port",
                 "destinationport", "dport", "port"),
    "event_code": ("event_id", "eventid", "event_code", "eventcode", "event_type", "eventtype",
                   "status", "status_code"),
    "action": ("action", "activity", "operation", "event_action"),
    "process_name": ("process_name", "processname", "process", "image", "program", "app"),
    "cmdline": ("commandline", "command_line", "cmdline", "command", "process_command_line"),
    "file_path": ("file_path", "filepath", "path", "file", "filename", "file_name", "url", "uri"),
    "protocol": ("protocol", "proto", "transport"),
    "message": ("message", "msg", "description", "details", "summary", "event", "log"),
}  # fmt: skip
NAIVE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?$")
OFFSET_RE = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")
EPOCH_RE = re.compile(r"^\d{10}(\d{3})?(\.\d{1,6})?$")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9@_]", "_", name.strip().lower()).strip("_")


def _delimiter(header: str) -> str | None:
    counts = {d: header.count(d) for d in DELIMITERS}
    best = max(counts, key=lambda d: counts[d])
    return best if counts[best] >= 1 else None


def _header(line: bytes) -> tuple[list[str], str] | None:
    text = line.decode("utf-8", "replace").lstrip("﻿").rstrip("\r")
    delim = _delimiter(text)
    if delim is None:
        return None
    try:
        cols = next(csv.reader([text], delimiter=delim))
    except (csv.Error, StopIteration):
        return None
    if not 2 <= len(cols) <= MAX_COLUMNS:
        return None
    return cols, delim


def _time_index(columns: list[str]) -> int | None:
    names = [_norm(c) for c in columns]
    for wanted in TIME_COLUMNS:
        if wanted in names:
            return names.index(wanted)
    return None


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    number = decimal_int(value, 5)
    return number if number is not None and number < 65536 else None


def parse_time(value: str, tz: ZoneInfo, ctx: ParseContext, location: str) -> datetime:
    text = value.strip().strip('"')
    if EPOCH_RE.match(text):
        whole = text.split(".")[0]
        converted = unix_micros(int(whole) * 1000) if len(whole) == 13 else unix_seconds(int(whole))
        if converted is None:
            raise TimestampError("zero epoch")
        return converted.ts
    if OFFSET_RE.search(text):
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise TimestampError(f"no offset in {text[:40]!r}")
        return parsed.astimezone(UTC)
    if NAIVE_RE.match(text):
        ctx.stats.assumptions["timezone"] = f"{ctx.timezone} (times without an offset)"
        return _local_to_utc(datetime.fromisoformat(text), tz, ctx.stats, location)
    raise TimestampError(f"unsupported time format {text[:40]!r}")


@register
class CsvEventsParser:
    name = "csv_events"
    version = "1.0.0"
    description = "CSV/TSV exports with a header row and a timestamp column"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        lines = head_text(head).splitlines()
        if len(lines) < 2:
            return 0.0
        found = _header(lines[0])
        if found is None or _time_index(found[0]) is None:
            return 0.0
        return 0.75 if filename.lower().endswith((".csv", ".tsv")) else 0.6

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        try:
            tz = ZoneInfo(ctx.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ParserInputError(f"unknown timezone {ctx.timezone!r}") from exc
        columns: list[str] = []
        delim = ","
        time_at = 0
        mapping: dict[str, int] = {}
        for line in iter_lines(ctx.path, ctx.limits, stats, ctx.progress):
            if record_cap_reached(ctx):
                return
            stats.read()
            location = f"line {line.number}"
            if line.too_long:
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            if not columns:
                found = _header(line.data)
                if found is None or _time_index(found[0]) is None:
                    raise ParserInputError("no header row with a timestamp column")
                columns, delim = found
                time_at = _time_index(columns) or 0
                names = [_norm(c) for c in columns]
                for field, aliases in FIELD_COLUMNS.items():
                    for alias in aliases:
                        if alias in names and names.index(alias) != time_at:
                            mapping[field] = names.index(alias)
                            break
                stats.assumptions["time_column"] = columns[time_at]
                stats.skip(location, "header")
                continue
            text = line.data.decode("utf-8", "replace").rstrip("\r")
            if not text.strip():
                stats.skip(location, "blank")
                continue
            try:
                values = next(csv.reader([text], delimiter=delim))
            except (csv.Error, StopIteration):
                stats.error(location, "invalid_csv", snippet(line.data))
                continue
            if len(values) != len(columns):
                stats.error(
                    location, "column_count", f"{len(values)} values, {len(columns)} columns"
                )
                continue
            try:
                ts = parse_time(values[time_at], tz, ctx, location)
            except (TimestampError, ValueError, OverflowError) as exc:
                stats.error(location, "bad_timestamp", str(exc)[:200])
                continue
            yield self._event(ctx, line.number, ts, columns, values, mapping, values[time_at])

    @staticmethod
    def _event(
        ctx: ParseContext,
        number: int,
        ts: datetime,
        columns: list[str],
        values: list[str],
        mapping: dict[str, int],
        original: str,
    ) -> Event:
        def get(field: str) -> str | None:
            at = mapping.get(field)
            value = values[at].strip()[:MAX_CELL] if at is not None else ""
            return value or None

        row = {c: v[:MAX_CELL] for c, v in zip(columns, values, strict=True) if v.strip()}
        message = get("message") or ", ".join(f"{k}={v}" for k, v in list(row.items())[:6])
        return Event(
            ts=ts,
            source_type=SOURCE,
            message=message[:2000],
            record_key=f"line:{number}",
            host=get("host") or ctx.host_hint,
            user=get("user"),
            event_code=get("event_code"),
            action=get("action"),
            process_name=get("process_name"),
            cmdline=get("cmdline"),
            file_path=get("file_path"),
            src_ip=_ip(get("src_ip")),
            dst_ip=_ip(get("dst_ip")),
            src_port=_port(get("src_port")),
            dst_port=_port(get("dst_port")),
            protocol=(get("protocol") or "").lower() or None,
            source_file=ctx.source_file,
            source_record_id=str(number),
            ts_original=original[:100],
            raw={"csv": row, "line_no": number},
        )
