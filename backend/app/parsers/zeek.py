"""Zeek wrapper for packet captures (guide 10.3 ``pcap``; optional engine, spec decision 6).

Zeek is NOT in the default worker image. ``find_tool("zeek")`` fails the job with
``'zeek' is not installed in this worker image (optional engine ...)`` unless an operator adds it
(``TOOL_SEARCH_PATH`` or a derived image). When present it runs as
``zeek -C -r <capture> LogAscii::use_json=T`` inside the job work dir (clean env, timeout, output
cap on the whole log directory), then conn/dns/http/ssl/notice logs are read line by line: one
record per JSON line, ``ts`` = Unix epoch seconds (UTC). Explicit request only.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import Event, ParseContext, record_cap_reached, require_work_dir, snippet
from app.parsers.registry import register
from app.parsers.textio import iter_lines
from app.parsers.timeconv import TimestampError, unix_seconds
from app.parsers.tools import ToolFailedError, find_tool, image_tool_versions, run_tool

SOURCE = "zeek"
LOGS = ("conn", "dns", "http", "ssl", "notice")


def _str(value: Any, limit: int = 1024) -> str | None:
    if isinstance(value, str) and value and value != "-":
        return value[:limit]
    if isinstance(value, list):
        return ", ".join(str(v)[:255] for v in value[:16]) or None
    return None


def _port(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535
        else None
    )


def _fields(log: str, rec: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    net = {
        "src_ip": _str(rec.get("id.orig_h")),
        "src_port": _port(rec.get("id.orig_p")),
        "dst_ip": _str(rec.get("id.resp_h")),
        "dst_port": _port(rec.get("id.resp_p")),
        "protocol": _str(rec.get("proto")),
    }
    flow = f"{net['src_ip']}:{net['src_port']} -> {net['dst_ip']}:{net['dst_port']}"
    if log == "conn":
        message = (
            f"{net['protocol'] or 'conn'} {flow} service={_str(rec.get('service')) or '-'} "
            f"state={_str(rec.get('conn_state')) or '-'}"
        )
        return message, {**net, "action": "connection"}
    if log == "dns":
        return f"DNS {_str(rec.get('query'))} -> {_str(rec.get('answers')) or '-'}", {
            **net,
            "action": "dns_query",
        }
    if log == "http":
        host = _str(rec.get("host"))
        return f"HTTP {_str(rec.get('method'))} http://{host}{_str(rec.get('uri'), 4096) or ''}", {
            **net,
            "action": "http_request",
        }
    if log == "ssl":
        return f"TLS {flow} server_name={_str(rec.get('server_name')) or '-'}", {
            **net,
            "action": "tls_session",
        }
    return f"Zeek notice {_str(rec.get('note'))}: {_str(rec.get('msg'))}", {
        **net,
        "action": "notice",
    }


@register
class ZeekParser:
    name = "zeek"
    version = "1.0.0"
    description = "Packet captures via Zeek (optional engine; explicit request only)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return image_tool_versions(["zeek"])

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 0.0  # optional engine; the pcap parser is the default

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        zeek = find_tool("zeek", ctx.tools, optional_note="optional engine, see docs/parsers.md")
        work = require_work_dir(ctx)
        logs = work / "zeek"
        logs.mkdir(mode=0o700, exist_ok=True)
        result = run_tool(
            [zeek, "-C", "-r", str(ctx.path), "LogAscii::use_json=T"],
            cwd=logs,
            stdout=work / "zeek.stdout",
            cfg=ctx.tools,
            heartbeat=lambda: ctx.progress(0.1),
            watch=[logs],
        )
        if result.returncode != 0:
            raise ToolFailedError(f"zeek failed (exit {result.returncode}): {result.stderr_tail}")
        stats.assumptions.update({"timezone": "UTC (Zeek epoch)", "logs": []})
        for log in LOGS:
            path = logs / f"{log}.log"
            if not path.is_file() or path.is_symlink():
                continue
            stats.assumptions["logs"].append(log)
            for line in iter_lines(path, ctx.limits, stats, lambda _f: None):
                if record_cap_reached(ctx):
                    return
                if not line.data.strip() or line.data.startswith(b"#"):
                    continue
                stats.read()
                location = f"{log}.log line {line.number}"
                if line.too_long:
                    stats.error(location, "line_too_long", f"{line.length} bytes")
                    continue
                try:
                    rec = json.loads(line.data)
                except (ValueError, RecursionError):
                    stats.error(location, "invalid_json", snippet(line.data))
                    continue
                if not isinstance(rec, dict):
                    stats.error(location, "not_an_object")
                    continue
                try:
                    converted = unix_seconds(rec.get("ts"), tag="zeek_ts")
                except TimestampError as exc:
                    stats.error(location, "bad_timestamp", str(exc))
                    continue
                if converted is None:
                    stats.skip(location, "no_timestamp")
                    continue
                message, fields = _fields(log, rec)
                yield Event(
                    ts=converted.ts,
                    ts_original=converted.original,
                    source_type=SOURCE,
                    message=message,
                    record_key=f"{log}:{line.number}",
                    source_record_id=_str(rec.get("uid"), 64) or f"{log}:{line.number}",
                    source_file=ctx.source_file,
                    host=ctx.host_hint,
                    event_code=f"zeek_{log}",
                    event_category="network",
                    raw={"log": log, **rec},
                    **fields,
                )
        ctx.progress(1.0)
