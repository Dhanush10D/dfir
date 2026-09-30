"""Volatility 3 wrapper for memory images (guide 10.3 ``volatility``, spec decision 7).

``vol`` (its own venv in the worker image; never imported: Volatility Software License) runs once
per allowlisted plugin with the JSON renderer, ``--offline`` (no symbol downloads), a cache inside
the job work dir and ``-s VOLATILITY_SYMBOLS_DIR`` when configured, through ``tools.run_tool``
(clean env, timeout, output cap). The JSON tree is flattened (depth <= ``max_depth``); every row
is one record and one ``memory`` event:

* ``pslist``/``psscan``/``pstree``: ``CreateTime`` -> process events (pid, ppid, name);
* ``netscan``/``netstat``/``sockstat``: ``Created`` when present -> connection events;
* ``info``: one event per row (the ``SystemTime`` row carries the capture time);
* others (``cmdline``, ``dlllist``, ``svcscan``, ``malfind``, ``bash``, ``lsmod``): the first
  timestamp column, else the evidence reference time (``raw.ts_source``, tag ``time_inferred``).

A plugin that fails (e.g. no matching symbols) is a warning with Volatility's message and the run
is ``partial``; if every plugin fails the job fails with that message. ``TOOL_TIMEOUT_S`` is the
budget for all plugins together (each run gets what is left; plugins after it runs out are
skipped as failures), and the shared symbol cache counts toward ``TOOL_MAX_OUTPUT_MB``.
"""

from __future__ import annotations

import functools
import json
import math
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import (
    Event,
    ParseContext,
    ParserInputError,
    record_cap_reached,
    reference_ts,
    require_work_dir,
)
from app.parsers.registry import register
from app.parsers.timeconv import Converted, TimestampError, iso_utc
from app.parsers.tools import (
    ToolFailedError,
    ToolOutputLimitError,
    ToolTimeoutError,
    find_tool,
    image_tool_versions,
    run_tool,
)

SOURCE = "memory"
# Allowlisted plugins per OS (job parameter ``plugins``); anything else is rejected with 422.
VOLATILITY_PLUGINS: dict[str, frozenset[str]] = {
    "windows": frozenset(
        {
            "info",
            "pslist",
            "psscan",
            "pstree",
            "cmdline",
            "netscan",
            "netstat",
            "dlllist",
            "svcscan",
            "malfind",
        }
    ),
    "linux": frozenset({"pslist", "pstree", "bash", "lsmod", "sockstat", "malfind"}),
}
DEFAULT_PLUGINS: dict[str, tuple[str, ...]] = {
    "windows": ("info", "pslist", "cmdline", "netscan"),
    "linux": ("pslist", "bash"),
}
TIME_COLUMNS = ("CreateTime", "Created", "SystemTime", "CommandTime", "Start Time", "StartTime")
LIME_MAGIC = b"EMiL"
MAX_JSON_BYTES = 256 * 1024 * 1024  # parsed in memory: bounded separately
MEMORY_NAMES = (".mem", ".vmem", ".lime", ".raw", ".dmp", ".avml")


def flatten(rows: Any, depth: int, max_depth: int) -> Iterator[dict[str, Any]]:
    if depth > max_depth or not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        children = row.get("__children")
        yield {k: v for k, v in row.items() if k != "__children"}
        if children:
            yield from flatten(children, depth + 1, max_depth)


def _int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**31:
        return value
    return None


def _str(value: Any) -> str | None:
    return value[:4096] if isinstance(value, str) and value and value != "N/A" else None


def _time(row: dict[str, Any]) -> tuple[Converted | None, str | None]:
    for column in TIME_COLUMNS:
        value = row.get(column)
        if isinstance(value, str) and value:
            try:
                return iso_utc(value), column
            except TimestampError:
                continue
    if row.get("Variable") == "SystemTime" and isinstance(row.get("Value"), str):
        try:
            return iso_utc(row["Value"].replace(" ", "T", 1)), "SystemTime"
        except TimestampError:
            return None, None
    return None, None


def _event(
    ctx: ParseContext,
    plugin: str,
    index: int,
    row: dict[str, Any],
    reference: tuple[Any, str],
) -> Event:
    converted, column = _time(row)
    tags: list[str] = ["memory"]
    raw: dict[str, Any] = {"plugin": plugin, "row": row}
    if converted is None:
        ts, original = reference[0], None
        raw["ts_source"] = reference[1]
        tags.append("time_inferred")
    else:
        ts, original = converted.ts, converted.original
        raw["ts_source"] = column
    short = plugin.split(".", 1)[-1]
    pid = _int(row.get("PID") or row.get("Pid"))
    name = _str(
        row.get("ImageFileName") or row.get("Process") or row.get("Owner") or row.get("COMM")
    )
    fields: dict[str, Any] = {"pid": pid, "process_name": name}
    if short in ("pslist", "psscan", "pstree"):
        fields.update(ppid=_int(row.get("PPID")), event_category="process", action="process_start")
        message = f"Process {name or '?'} (pid {pid}, ppid {row.get('PPID')})"
    elif short in ("netscan", "netstat", "sockstat"):
        fields.update(
            src_ip=_str(row.get("LocalAddr") or row.get("Source Addr")),
            src_port=_int(row.get("LocalPort") or row.get("Source Port")),
            dst_ip=_str(row.get("ForeignAddr") or row.get("Destination Addr")),
            dst_port=_int(row.get("ForeignPort") or row.get("Destination Port")),
            protocol=_str(row.get("Proto") or row.get("Proto Type")),
            event_category="network",
            action="connection",
        )
        message = (
            f"{fields['protocol'] or 'conn'} {fields['src_ip']}:{fields['src_port']} -> "
            f"{fields['dst_ip']}:{fields['dst_port']} {row.get('State') or ''} "
            f"(pid {pid} {name or ''})"
        ).strip()
    elif short in ("cmdline", "bash"):
        cmd = _str(row.get("Args") or row.get("Command"))
        fields.update(cmdline=cmd, event_category="process", action="command")
        message = f"{name or '?'} (pid {pid}): {cmd or ''}"
    elif short == "info":
        message = f"Memory image info: {row.get('Variable')} = {str(row.get('Value'))[:200]}"
        fields.update(event_category="host", action="image_info")
    else:
        fields.update(event_category="memory", action=short)
        message = f"{plugin}: " + ", ".join(
            f"{k}={str(v)[:80]}" for k, v in list(row.items())[:6] if v not in (None, "")
        )
    return Event(
        ts=ts,
        ts_original=original,
        source_type=SOURCE,
        message=message,
        record_key=f"{plugin}:{index}",
        source_record_id=f"{plugin}:{index}",
        source_file=ctx.source_file,
        host=ctx.host_hint,
        event_code=plugin,
        tags=tags,
        raw=raw,
        **fields,
    )


@register
class VolatilityParser:
    name = "volatility"
    version = "1.0.0"
    description = "Memory images via Volatility 3 (allowlisted plugins, JSON renderer, offline)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return image_tool_versions(["volatility3"])

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if head[:4] == LIME_MAGIC or head[:6] == b"PAGEDU" or head[:4] in (b"hibr", b"HIBR"):
            return 0.6
        return 0.55 if filename.lower().endswith(MEMORY_NAMES) else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        os_name = str(ctx.params.get("os") or "windows")
        if os_name not in VOLATILITY_PLUGINS:
            raise ParserInputError(f"unsupported os {os_name!r}")
        requested = ctx.params.get("plugins") or DEFAULT_PLUGINS[os_name]
        plugins = [p for p in requested if isinstance(p, str) and p in VOLATILITY_PLUGINS[os_name]]
        if not plugins:
            raise ParserInputError("no allowlisted Volatility plugins requested")
        vol = find_tool("vol", ctx.tools, optional_note="Volatility 3, see docs/parsers.md")
        work = require_work_dir(ctx)
        reference = reference_ts(ctx)
        cache = work / "volcache"
        cache.mkdir(mode=0o700, exist_ok=True)
        stats.assumptions.update(
            {
                "os": os_name,
                "plugins": plugins,
                "symbols_dir": bool(ctx.tools.volatility_symbols_dir),
                "offline": True,
            }
        )
        failures: list[str] = []
        succeeded = 0
        started = time.monotonic()
        for n, plugin_short in enumerate(plugins):
            plugin = f"{os_name}.{plugin_short}"
            remaining = math.ceil(ctx.tools.timeout_s - (time.monotonic() - started))
            if remaining <= 0:
                failures.append(f"{plugin}: TOOL_TIMEOUT_S budget used up")
                stats.warn("plugin_skipped_timeout", plugin)
                continue
            argv = [vol, "-q", "-r", "json", "--offline", "--cache-path", str(cache)]
            if ctx.tools.volatility_symbols_dir:
                argv += ["-s", ctx.tools.volatility_symbols_dir]
            argv += ["-f", str(ctx.path), plugin]
            out = work / f"vol-{n:02d}.json"
            try:
                result = run_tool(
                    argv,
                    cwd=work,
                    stdout=out,
                    cfg=ctx.tools,
                    heartbeat=functools.partial(ctx.progress, n / len(plugins)),
                    watch=[cache],
                    timeout_s=remaining,
                )
            except (ToolTimeoutError, ToolOutputLimitError) as exc:
                failures.append(f"{plugin}: {exc}")
                stats.warn("plugin_failed", plugin, str(exc))
                continue
            if result.returncode != 0:
                failures.append(f"{plugin}: exit {result.returncode} {result.stderr_tail}")
                stats.warn(
                    "plugin_failed", plugin, f"exit {result.returncode}: {result.stderr_tail}"
                )
                continue
            if out.stat().st_size > MAX_JSON_BYTES:
                failures.append(f"{plugin}: output too large to load")
                stats.warn("plugin_output_too_large", plugin)
                continue
            try:
                with out.open("rb") as fh:
                    data = json.load(fh)
            except (ValueError, RecursionError) as exc:
                failures.append(f"{plugin}: invalid JSON output")
                stats.warn("plugin_output_invalid", plugin, type(exc).__name__)
                continue
            succeeded += 1
            for index, row in enumerate(flatten(data, 0, ctx.limits.max_depth)):
                if record_cap_reached(ctx):
                    return
                stats.read()
                yield _event(ctx, plugin, index, row, reference)
        stats.assumptions["plugins_failed"] = failures[:20]
        if succeeded == 0:
            raise ToolFailedError(
                "Volatility could not analyse the image: " + "; ".join(failures)[:900]
            )
        if failures:
            stats.assumptions["incomplete"] = "plugin_failed"
        ctx.progress(1.0)
