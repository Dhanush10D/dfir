"""W3C extended log files: Windows Firewall (``pfirewall.log``) and IIS web logs, plain or gzip.

The ``#Fields:`` directive names the space-separated columns of the lines that follow (it may
change mid-file; every ``#`` line is a skipped record). The ``#Software:`` directive (or the
columns) decides the flavour:

* **Windows Firewall** (``action protocol src-ip dst-ip src-port dst-port ...``): one connection
  per line; ``event_code`` is ``fw_allow`` / ``fw_drop`` / ...; source type ``firewall``. The
  firewall writes **local time**: the job's ``timezone`` parameter (IANA, default UTC) is applied
  and recorded as an assumption.
* **IIS** (``cs-method cs-uri-stem sc-status c-ip ...``): one request per line, mapped like
  ``web_access`` (status -> ``event_code``, client -> ``src_ip``); source type ``iis``. IIS writes
  UTC (W3C format).
* any other W3C log: source type ``w3c``, every column kept in ``raw.w3c``.

A value of ``-`` is empty. A data line before any ``#Fields:`` or with the wrong number of
columns is an error.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
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

MAX_COLUMNS = 64
FIREWALL_COLUMNS = {"action", "src-ip", "dst-ip"}
IIS_COLUMNS = {"cs-method", "cs-uri-stem"}


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value: str | None) -> int | None:
    number = decimal_int(value, 5)
    return number if number is not None and number < 65536 else None


def _flavour(software: str, columns: list[str]) -> str:
    names = set(columns)
    if "firewall" in software.lower() or names >= FIREWALL_COLUMNS:
        return "firewall"
    if "internet information services" in software.lower() or names >= IIS_COLUMNS:
        return "iis"
    return "w3c"


@register
class W3cParser:
    name = "w3c"
    version = "1.0.0"
    description = "W3C extended logs: Windows Firewall (pfirewall.log) and IIS"
    source_types = ("firewall", "iis", "w3c")

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        text = head_text(head)
        if b"\n#Fields:" in b"\n" + text[:8192] or text.startswith(b"#Fields:"):
            return 0.9
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        try:
            tz = ZoneInfo(ctx.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ParserInputError(f"unknown timezone {ctx.timezone!r}") from exc
        columns: list[str] = []
        software = ""
        for line in iter_lines(ctx.path, ctx.limits, stats, ctx.progress):
            if record_cap_reached(ctx):
                return
            stats.read()
            location = f"line {line.number}"
            if line.too_long:
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            data = line.data.rstrip(b"\r").decode("utf-8", "replace")
            if not data.strip():
                stats.skip(location, "blank")
                continue
            if data.startswith("#"):
                key, _, value = data[1:].partition(":")
                if key == "Fields":
                    columns = value.split()[:MAX_COLUMNS]
                elif key == "Software":
                    software = value.strip()
                stats.skip(location, "directive")
                continue
            if not columns:
                stats.error(location, "no_fields_directive", snippet(line.data))
                continue
            values = data.split()
            if len(values) != len(columns):
                stats.error(
                    location, "column_count", f"{len(values)} values, {len(columns)} fields"
                )
                continue
            row = {c: (None if v == "-" else v) for c, v in zip(columns, values, strict=True)}
            flavour = _flavour(software, columns)
            date, clock = row.get("date"), row.get("time")
            try:
                naive = datetime.fromisoformat(f"{date}T{clock}")
            except (TypeError, ValueError):
                stats.error(location, "bad_timestamp", f"{date} {clock}")
                continue
            if naive.tzinfo is not None:
                stats.error(location, "bad_timestamp", f"{date} {clock}")
                continue
            if flavour == "firewall":
                ts = _local_to_utc(naive, tz, stats, location)
                stats.assumptions["timezone"] = f"{ctx.timezone} (Windows Firewall logs local time)"
                yield self._firewall(ctx, line.number, ts, f"{date} {clock}", row)
            else:
                ts = naive.replace(tzinfo=UTC)
                stats.assumptions["timezone"] = "UTC (W3C extended log format)"
                yield self._web(ctx, line.number, ts, f"{date} {clock}", row, flavour)

    @staticmethod
    def _firewall(
        ctx: ParseContext, number: int, ts: datetime, original: str, row: dict[str, str | None]
    ) -> Event:
        action = (row.get("action") or "unknown").upper()
        proto = (row.get("protocol") or "").lower() or None
        src, dst = row.get("src-ip"), row.get("dst-ip")
        sport, dport = row.get("src-port"), row.get("dst-port")
        direction = row.get("path")
        return Event(
            ts=ts,
            source_type="firewall",
            message=(
                f"Firewall {action} {proto or '-'} {src or '-'}:{sport or '-'} -> "
                f"{dst or '-'}:{dport or '-'}" + (f" ({direction})" if direction else "")
            ),
            record_key=f"line:{number}",
            host=ctx.host_hint,
            event_code=f"fw_{action.lower()}",
            event_category="network",
            action="connection",
            outcome="success" if action == "ALLOW" else "failure",
            src_ip=_ip(src),
            dst_ip=_ip(dst),
            src_port=_port(sport),
            dst_port=_port(dport),
            protocol=proto,
            pid=decimal_int(row.get("pid"), 10),
            source_file=ctx.source_file,
            source_record_id=str(number),
            ts_original=original,
            raw={"firewall": {k: v for k, v in row.items() if v is not None}, "line_no": number},
        )

    @staticmethod
    def _web(
        ctx: ParseContext,
        number: int,
        ts: datetime,
        original: str,
        row: dict[str, str | None],
        flavour: str,
    ) -> Event:
        method = row.get("cs-method")
        stem, query = row.get("cs-uri-stem"), row.get("cs-uri-query")
        status = row.get("sc-status")
        code = status if status and status.isascii() and status.isdigit() else None
        if flavour == "iis":
            message = f"{method or 'Request'} {unquote(stem or '')[:300]} -> {status or '-'}"
        else:
            message = " ".join(f"{k}={v}" for k, v in list(row.items())[:8] if v is not None)
        failed = code is not None and int(code) >= 400
        return Event(
            ts=ts,
            source_type=flavour,
            message=message,
            record_key=f"line:{number}",
            host=row.get("s-computername") or row.get("s-sitename") or ctx.host_hint,
            user=row.get("cs-username"),
            event_code=code,
            event_category="web" if flavour == "iis" else None,
            action=(method or "").lower() or None,
            outcome=("failure" if failed else "success") if code else None,
            file_path=stem,
            src_ip=_ip(row.get("c-ip")),
            dst_ip=_ip(row.get("s-ip")),
            dst_port=_port(row.get("s-port")),
            protocol="http" if flavour == "iis" else None,
            source_file=ctx.source_file,
            source_record_id=str(number),
            ts_original=original,
            raw={
                "w3c": {k: v for k, v in row.items() if v is not None},
                "http": {
                    k: v
                    for k, v in {
                        "method": method,
                        "path": stem,
                        "query": query,
                        "status": int(code) if code else None,
                        "user_agent": (row.get("cs(User-Agent)") or "").replace("+", " ") or None,
                        "referer": row.get("cs(Referer)"),
                    }.items()
                    if v is not None
                },
                "line_no": number,
            },
        )
