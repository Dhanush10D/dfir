"""Web server access logs: Apache/Nginx "combined" and "common" (NCSA) formats, plain or gzip.

One record per line::

    203.0.113.5 - alice [14/Sep/2026:02:10:03 +0000] "GET /login HTTP/1.1" 200 512 "-" "curl/8.0"

The time carries its own UTC offset, so no timezone assumption is needed. The client address
becomes ``src_ip`` (a hostname, when ``HostnameLookups`` was on, stays in ``raw.http.client``), the
authenticated user ``user``, the HTTP status ``event_code`` and the request path ``file_path``;
everything else is kept in ``raw.http``. A request line that is not ``METHOD URL PROTOCOL`` (probes
often send garbage) is kept verbatim with ``method`` empty. Lines that do not match the format are
errors; blank lines are skipped.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from app.parsers.base import Event, ParseContext, record_cap_reached, snippet
from app.parsers.registry import register
from app.parsers.textio import head_text, iter_lines

SOURCE = "web_access"
LINE_RE = re.compile(
    rb"^(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]{20,40})\] "
    rb'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}|-) (?P<size>\d{1,20}|-)'
    rb'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)")?'
)
TS_RE = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
MONTHS = {
    m: i
    for i, m in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}
METHOD_RE = re.compile(r"^[A-Z][A-Z_-]{0,19}$")
NAME_HINTS = ("access.log", "access_log", "ssl_access", "access-")


def parse_time(value: str) -> datetime:
    m = TS_RE.match(value)
    if not m or m.group(2).lower() not in MONTHS:
        raise ValueError(f"not a [dd/Mon/yyyy:HH:MM:SS +zzzz] time: {value[:40]!r}")
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    offset = timedelta(hours=int(oh), minutes=int(om)) * (-1 if sign == "-" else 1)
    local = datetime(
        int(year),
        MONTHS[mon.lower()],
        int(day),
        int(hh),
        int(mm),
        int(ss),
        tzinfo=timezone(offset),
    )
    return local.astimezone(UTC)


def _text(value: bytes | None) -> str | None:
    if value is None:
        return None
    text = value.decode("utf-8", "replace")
    return None if text == "-" else text


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def split_request(request: str) -> tuple[str, str, str]:
    """``METHOD URL PROTOCOL`` -> parts; anything else stays whole in ``url``."""
    parts = request.split(" ")
    if len(parts) == 3 and METHOD_RE.match(parts[0]):
        return parts[0], parts[1], parts[2]
    if len(parts) == 2 and METHOD_RE.match(parts[0]):  # HTTP/0.9 style
        return parts[0], parts[1], ""
    return "", request, ""


@register
class WebAccessParser:
    name = "web_access"
    version = "1.0.0"
    description = "Apache/Nginx access logs (combined and common formats)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        lines = [ln for ln in head_text(head).splitlines()[:20] if ln.strip()]
        if lines and not head_text(head).endswith((b"\n", b"\r")) and len(lines) > 1:
            lines = lines[:-1]  # the last line of the head may be cut
        if not lines:
            return 0.0
        hits = sum(1 for ln in lines if LINE_RE.match(ln))
        if hits == 0 or hits / len(lines) < 0.6:
            return 0.0
        return 0.9 if any(h in filename.lower() for h in NAME_HINTS) else 0.85

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        stats.assumptions["timezone"] = "from each line's UTC offset"
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
            m = LINE_RE.match(line.data.rstrip(b"\r"))
            if not m:
                stats.error(location, "not_access_log_format", snippet(line.data))
                continue
            ts_text = m.group("ts").decode("ascii", "replace")
            try:
                ts = parse_time(ts_text)
            except (ValueError, OverflowError) as exc:
                stats.error(location, "bad_timestamp", str(exc))
                continue
            client = m.group("client").decode("utf-8", "replace")
            request = (_text(m.group("request")) or "").replace('\\"', '"')
            method, url, protocol = split_request(request)
            path, _, query = url.partition("?")
            status = _text(m.group("status"))
            size = _text(m.group("size"))
            user = _text(m.group("user"))
            failed = status is not None and int(status) >= 400
            http = {
                "client": client,
                "method": method or None,
                "url": url or None,
                "path": path or None,
                "query": query or None,
                "protocol": protocol or None,
                "status": int(status) if status else None,
                "bytes": int(size) if size else None,
                "referer": _text(m.group("referer")),
                "user_agent": _text(m.group("agent")),
            }
            shown = unquote(url)[:300] if url else "(empty request)"
            yield Event(
                ts=ts,
                source_type=SOURCE,
                message=f"{method or 'Request'} {shown} -> {status or '-'}",
                record_key=f"line:{line.number}",
                host=ctx.host_hint,
                user=user,
                event_code=status,
                event_category="web",
                action=(method or "request").lower(),
                outcome="failure" if failed else "success",
                file_path=path or None,
                src_ip=_ip(client),
                protocol="http",
                source_file=ctx.source_file,
                source_record_id=str(line.number),
                ts_original=ts_text,
                raw={
                    "http": {k: v for k, v in http.items() if v is not None},
                    "line_no": line.number,
                },
            )
