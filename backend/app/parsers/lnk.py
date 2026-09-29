"""Windows shortcut (``.lnk``) files -> target file timestamps (guide 10.3, spec decision 4).

The three target FILETIMEs (created, modified, accessed; UTC) are read directly from the 76-byte
header: one record each, a zero time is skipped. Link info (local path, volume serial/label,
network share), string data (arguments, working directory, description) and the distributed link
tracker block (machine id, droids) come from LnkParse3 1.6.0 (MIT) and go into ``raw`` of every
event. A library failure on those structures is a warning (the header times are still used);
files over 16 MiB or with a bad header are refused.
"""

from __future__ import annotations

import importlib.metadata
import struct
import warnings
from collections.abc import Iterator
from pathlib import Path, PureWindowsPath
from typing import Any

import LnkParse3

from app.parsers.base import Event, ParseContext, ParserInputError
from app.parsers.registry import register
from app.parsers.timeconv import TimestampError, filetime

SOURCE = "lnk"
MAX_BYTES = 16 * 1024 * 1024
HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
TIMES = (("target_created", 28), ("target_modified", 44), ("target_accessed", 36))
STRING_KEYS = (
    "description",
    "relative_path",
    "working_directory",
    "command_line_arguments",
    "icon_location",
)


def _text(value: Any, limit: int = 4096) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    return text[:limit] or None


def link_details(data: bytes) -> tuple[dict[str, Any], str | None]:
    """(details, error) from LnkParse3; never raises."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            parsed = LnkParse3.lnk_file(indata=data).get_json()
    except Exception as exc:  # noqa: BLE001 - hostile input; any library failure is one warning
        return {}, f"{type(exc).__name__}: {str(exc)[:200]}"
    info = parsed.get("link_info") or {}
    location = info.get("location_info") or {}
    strings = parsed.get("data") or {}
    extra = parsed.get("extra") or {}
    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
    base = info.get("local_base_path_unicode") or info.get("local_base_path")
    suffix = info.get("common_path_suffix_unicode") or info.get("common_path_suffix")
    net = location.get("net_name_unicode") or location.get("net_name")
    target = base
    if base and suffix:
        target = base.rstrip("\\") + "\\" + suffix
    elif net and suffix:
        target = net.rstrip("\\") + "\\" + suffix
    details: dict[str, Any] = {
        "target_path": _text(target),
        "local_base_path": _text(base),
        "network_share": _text(net),
        "drive_type": _text(location.get("drive_type"), 64),
        "drive_serial_number": _text(location.get("drive_serial_number"), 64),
        "volume_label": _text(location.get("volume_label_unicode") or location.get("volume_label")),
        "link_flags": [str(f)[:64] for f in (parsed.get("header") or {}).get("link_flags", [])][
            :32
        ],
        "machine_id": _text(tracker.get("machine_identifier"), 64),
        "droid_volume": _text(tracker.get("droid_volume_identifier"), 64),
        "droid_file": _text(tracker.get("droid_file_identifier"), 64),
        "birth_droid_file": _text(tracker.get("birth_droid_file_identifier"), 64),
    }
    for key in STRING_KEYS:
        details[key] = _text(strings.get(key))
    return {k: v for k, v in details.items() if v not in (None, [], "")}, None


@register
class LnkParser:
    name = "lnk"
    version = "1.0.0"
    description = "Windows shortcut files (.lnk): target times, paths, volume and tracker data"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"LnkParse3": importlib.metadata.version("LnkParse3")}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 0.95 if head[:20] == HEADER else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        size = ctx.path.stat().st_size
        if size > MAX_BYTES:
            raise ParserInputError(f"LNK file of {size} bytes over the 16 MiB limit")
        data = ctx.path.read_bytes()
        stats.bytes_read = len(data)
        if data[:20] != HEADER or len(data) < 76:
            raise ParserInputError("not a Windows shortcut (bad header)")
        details, error = link_details(data)
        if error:
            stats.warn("lnk_structure_unreadable", "link info/string data", error)
        target = details.get("target_path") or details.get("relative_path")
        file_size = struct.unpack_from("<I", data, 52)[0]
        stats.assumptions["timezone"] = "UTC (FILETIME)"
        name = PureWindowsPath(target).name if target else None
        for code, offset in TIMES:
            stats.read()
            try:
                converted = filetime(struct.unpack_from("<Q", data, offset)[0])
            except TimestampError as exc:
                stats.error(code, "bad_timestamp", str(exc))
                continue
            if converted is None:
                stats.skip(code, "not_set")
                continue
            label = code.removeprefix("target_")
            yield Event(
                ts=converted.ts,
                ts_original=converted.original,
                source_type=SOURCE,
                message=f"Shortcut target {label}: {target or '(unknown target)'}",
                record_key=code,
                source_record_id=code,
                source_file=ctx.source_file,
                host=ctx.host_hint,
                event_code=code,
                event_category="file",
                action=f"file_{label}",
                file_path=target,
                process_name=name,
                cmdline=details.get("command_line_arguments"),
                raw={**details, "target_file_size": file_size, "timestamp": label},
            )
        ctx.progress(1.0)
