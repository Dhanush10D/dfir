"""Windows Prefetch (``.pf``) -> program execution events (guide 10.3).

Formats: version 17 (XP/2003), 23 (Vista/7), 26 (8.x), 30/31 (10/11, two file-information
layouts) and the Win10+ ``MAM`` container (LZXPRESS Huffman, own bounded decoder in
``xpress.py``). Inputs are capped at 16 MiB compressed and decompressed.

One record per last-run slot (1 slot before version 26, 8 after): a set slot is a
``prefetch_run`` event (UTC FILETIME), an empty slot is skipped. Each event carries the executable
name, prefetch hash, run count, volumes (device path, serial, creation time) and up to 256 loaded
file names. A truncated or inconsistent section is a warning; the run times in the fixed header
are still used.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from app.parsers.base import Event, ParseContext, ParserInputError
from app.parsers.registry import register
from app.parsers.timeconv import TimestampError, filetime
from app.parsers.xpress import XpressError, decompress_huffman

SOURCE = "prefetch"
MAX_BYTES = 16 * 1024 * 1024
VERSIONS = {17, 23, 26, 30, 31}
MAX_FILES = 256
MAX_VOLUMES = 32


def _u32(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", buf, off)[0])


def _u64(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<Q", buf, off)[0])


def unpack_mam(data: bytes) -> tuple[bytes, dict[str, Any]]:
    """Decompress a ``MAM`` container; raises ``ParserInputError`` when unusable."""
    if len(data) < 8 or data[:3] != b"MAM":
        raise ParserInputError("not a MAM container")
    flags = data[3]
    algorithm = flags & 0x0F
    if algorithm != 4:
        raise ParserInputError(f"unsupported MAM compression algorithm {algorithm}")
    size = _u32(data, 4)
    if size > MAX_BYTES:
        raise ParserInputError(f"declared decompressed size {size} over the 16 MiB limit")
    offset = 8
    crc = None
    if flags & 0xF0:
        if len(data) < 12:
            raise ParserInputError("MAM header truncated")
        crc = _u32(data, 8)
        offset = 12
    try:
        out = decompress_huffman(data[offset:], size)
    except XpressError as exc:
        raise ParserInputError(f"MAM decompression failed: {exc}") from exc
    info: dict[str, Any] = {"container": "MAM", "compressed_bytes": len(data), "size": size}
    if crc is not None:
        # Checksum over the header with the CRC field zeroed plus the payload (MS-XCA style).
        check = zlib.crc32(data[:8] + b"\x00\x00\x00\x00" + data[12:]) & 0xFFFFFFFF
        info["crc_ok"] = check == crc
    return out, info


def _info_layout(version: int, info_size: int) -> tuple[int, int, int]:
    """(offset of the first last-run time, number of slots, offset of the run count) relative to
    the file-information section (84)."""
    if version == 17:
        return 36, 1, 60
    if version == 23:
        return 44, 1, 68
    if version == 26:
        return 44, 8, 124
    if info_size == 216:  # version 30 variant 2 / 31
        return 44, 8, 116
    return 44, 8, 124


def _strings(data: bytes, offset: int, size: int) -> list[str]:
    if offset <= 0 or size <= 0 or offset + size > len(data):
        return []
    text = data[offset : offset + size].decode("utf-16-le", "replace")
    return [s for s in text.split("\x00") if s][:MAX_FILES]


def _volumes(
    data: bytes, version: int, offset: int, count: int, stats: Any
) -> list[dict[str, Any]]:
    entry_size = 40 if version == 17 else 104
    out: list[dict[str, Any]] = []
    if offset <= 0 or count <= 0:
        return out
    for i in range(min(count, MAX_VOLUMES)):
        base = offset + i * entry_size
        if base + 20 > len(data):
            stats.warn("volume_entry_truncated", f"volume {i}")
            break
        path_off, path_chars = _u32(data, base), _u32(data, base + 4)
        created_raw, serial = _u64(data, base + 8), _u32(data, base + 16)
        start = offset + path_off
        path = None
        if 0 < path_chars < 1024 and start + path_chars * 2 <= len(data):
            path = data[start : start + path_chars * 2].decode("utf-16-le", "replace")
        try:
            created = filetime(created_raw)
        except TimestampError:
            created = None
        out.append(
            {
                "device_path": path,
                "serial": f"{serial:08X}",
                "created": created.ts.isoformat() if created else None,
            }
        )
    return out


@register
class PrefetchParser:
    name = "prefetch"
    version = "1.0.0"
    description = "Windows Prefetch (.pf, versions 17-31, MAM/LZXPRESS Huffman)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"xpress": "dfirbench-xpress 1.0"}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if head[4:8] == b"SCCA" and len(head) >= 8 and _u32(head, 0) in VERSIONS:
            return 0.95
        if head[:3] == b"MAM" and len(head) >= 4 and head[3] & 0x0F == 4:
            return 0.95 if filename.lower().endswith(".pf") else 0.7
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        size = ctx.path.stat().st_size
        if size > MAX_BYTES:
            raise ParserInputError(f"prefetch file of {size} bytes over the 16 MiB limit")
        data = ctx.path.read_bytes()
        stats.bytes_read = len(data)
        container: dict[str, Any] = {"container": "none"}
        if data[:3] == b"MAM":
            data, container = unpack_mam(data)
            if container.get("crc_ok") is False:
                stats.warn("mam_crc_mismatch", "MAM header")
        if len(data) < 84 + 68 or data[4:8] != b"SCCA":
            raise ParserInputError("not a Prefetch file (no SCCA signature)")
        version = _u32(data, 0)
        if version not in VERSIONS:
            raise ParserInputError(f"unsupported Prefetch version {version}")
        declared = _u32(data, 12)
        if declared != len(data):
            stats.warn("size_mismatch", "header", f"declared {declared}, actual {len(data)}")
        exe = data[16:76].decode("utf-16-le", "replace").split("\x00", 1)[0]
        pf_hash = f"{_u32(data, 76):08X}"
        info = 84
        metrics_offset = _u32(data, info)
        info_size = metrics_offset - info if metrics_offset > info else 0
        first_time, slots, count_at = _info_layout(version, info_size)
        if info + count_at + 4 > len(data):
            raise ParserInputError("Prefetch file information section truncated")
        run_count = _u32(data, info + count_at)
        files = _strings(data, _u32(data, info + 16), _u32(data, info + 20))
        volumes = _volumes(data, version, _u32(data, info + 24), _u32(data, info + 28), stats)
        stats.assumptions.update(
            {
                "timezone": "UTC (FILETIME)",
                "format_version": version,
                "info_size": info_size,
                **container,
            }
        )
        common: dict[str, Any] = {
            "executable": exe,
            "prefetch_hash": pf_hash,
            "run_count": run_count,
            "format_version": version,
            "volumes": volumes,
            "loaded_files": files,
            "loaded_files_truncated": len(files) >= MAX_FILES,
        }
        path_hint = next((f for f in files if f.upper().endswith("\\" + exe.upper())), None)
        for slot in range(slots):
            stats.read()
            location = f"last run slot {slot}"
            try:
                converted = filetime(_u64(data, info + first_time + slot * 8))
            except (TimestampError, struct.error) as exc:
                stats.error(location, "bad_timestamp", str(exc))
                continue
            if converted is None:
                stats.skip(location, "empty_slot")
                continue
            yield Event(
                ts=converted.ts,
                ts_original=converted.original,
                source_type=SOURCE,
                message=f"Prefetch: {exe} executed (run {slot + 1} of the last {slots}, "
                f"count {run_count})",
                record_key=f"run:{slot}",
                source_record_id=f"{pf_hash}:{slot}",
                source_file=ctx.source_file,
                host=ctx.host_hint,
                event_code="prefetch_run",
                event_category="process",
                action="process_start",
                process_name=exe,
                file_path=path_hint,
                tags=["execution"],
                raw={**common, "slot": slot},
            )
        ctx.progress(1.0)
