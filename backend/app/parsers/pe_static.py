"""Static PE triage (guide 10.3 ``pe_static``, 11.4) with pefile 2024.8.26 (MIT).

One record, one event per file: hashes (MD5/SHA-1/SHA-256), machine, subsystem, DLL flag, compile
time, sections with entropy, imports (bounded) + imphash, exports count, Authenticode directory
presence (not validated), overlay, and indicators as tags (``packed``, ``suspicious_imports``,
``signed``, ``compile_time_suspect``).

``ts`` is the PE ``TimeDateStamp`` (Unix seconds, UTC) when it is plausible (1990 until one day
after the evidence reference time); otherwise the reference time is used
(``raw.ts_source = "reference:..."``, tag ``time_inferred``). pefile maps the file (no full read
into Python memory); files above ``max_structured_bytes`` are refused.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pefile

from app.parsers.base import Event, ParseContext, ParserInputError, reference_ts
from app.parsers.registry import register
from app.parsers.timeconv import TimestampError, unix_seconds

SOURCE = "pe"
MAX_IMPORTS = 2000
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".mpress1", ".themida"}
SUSPICIOUS_APIS = {
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "zwunmapviewofsection",
    "queueuserapc",
    "setwindowshookexa",
    "setwindowshookexw",
    "getasynckeystate",
    "urldownloadtofilea",
    "urldownloadtofilew",
    "winexec",
    "isdebuggerpresent",
    "adjusttokenprivileges",
    "minidumpwritedump",
    "cryptencrypt",
    "internetopena",
    "internetopenw",
}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "arm", 0xAA64: "arm64", 0x200: "ia64"}
EARLIEST = datetime(1990, 1, 1, tzinfo=UTC)


def _hashes(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = (
        hashlib.md5(usedforsecurity=False),
        hashlib.sha1(usedforsecurity=False),
        hashlib.sha256(),
    )
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _name(raw: bytes | None) -> str:
    return (raw or b"").split(b"\x00", 1)[0].decode("latin-1")[:128]


@register
class PeStaticParser:
    name = "pe_static"
    version = "1.0.0"
    description = "Static PE triage: hashes, sections/entropy, imports/imphash, signature, overlay"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"pefile": importlib.metadata.version("pefile")}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if head[:2] != b"MZ" or len(head) < 64:
            return 0.0
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        if e_lfanew + 4 <= len(head) and head[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            return 0.7
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        size = ctx.path.stat().st_size
        if size > ctx.limits.max_structured_bytes:
            raise ParserInputError(f"PE file of {size} bytes over the structured-input limit")
        stats.bytes_read = size
        stats.read()
        try:
            pe = pefile.PE(name=str(ctx.path), fast_load=True)
        except pefile.PEFormatError as exc:
            raise ParserInputError(f"not a valid PE file: {str(exc)[:200]}") from exc
        except (struct.error, ValueError, IndexError, AttributeError) as exc:
            raise ParserInputError(f"unreadable PE headers: {type(exc).__name__}") from exc
        try:
            yield from self._summary(ctx, pe, size)
        finally:
            pe.close()

    def _summary(self, ctx: ParseContext, pe: pefile.PE, size: int) -> Iterator[Event]:
        stats = ctx.stats
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                ]
            )
        except Exception as exc:  # noqa: BLE001 - hostile directories; headers still usable
            stats.warn("data_directories_unreadable", detail=f"{type(exc).__name__}")
        for warning in pe.get_warnings()[:20]:
            stats.warn("pefile_warning", detail=str(warning)[:200])
        hashes = _hashes(ctx.path)
        sections: list[dict[str, Any]] = []
        packed = False
        for section in list(pe.sections)[:96]:
            name = _name(section.Name)
            entropy = round(float(section.get_entropy()), 3)
            if entropy > 7.2 or name.lower() in PACKER_SECTIONS:
                packed = True
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(section.Misc_VirtualSize),
                    "raw_size": int(section.SizeOfRawData),
                    "entropy": entropy,
                    "characteristics": int(section.Characteristics),
                }
            )
        imports: list[str] = []
        suspicious: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:512]:
            dll = _name(entry.dll).lower()
            for imp in entry.imports[:4096]:
                fn = _name(imp.name) if imp.name else f"ord{imp.ordinal}"
                if fn.lower() in SUSPICIOUS_APIS:
                    suspicious.add(fn)
                if len(imports) < MAX_IMPORTS:
                    imports.append(f"{dll}!{fn}")
        try:
            imphash = pe.get_imphash() or None
        except Exception:  # noqa: BLE001 - hostile import table
            imphash = None
        exports = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        export_count = len(exports.symbols) if exports is not None else 0
        security = (
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4
            else None
        )
        signed = bool(security is not None and security.VirtualAddress and security.Size)
        overlay = pe.get_overlay_data_start_offset()
        machine = MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        stamp = int(pe.FILE_HEADER.TimeDateStamp)
        tags: list[str] = []
        if packed:
            tags.append("packed")
        if suspicious:
            tags.append("suspicious_imports")
        if signed:
            tags.append("signed")
        reference, ref_source = reference_ts(ctx)
        raw: dict[str, Any] = {
            **hashes,
            "size": size,
            "machine": machine,
            "dll": is_dll,
            "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
            "compile_time_raw": stamp,
            "sections": sections,
            "imports": imports,
            "imports_truncated": len(imports) >= MAX_IMPORTS,
            "imphash": imphash,
            "suspicious_imports": sorted(suspicious),
            "exports": export_count,
            "authenticode_present": signed,
            "overlay_offset": overlay,
            "overlay_bytes": size - overlay if overlay else 0,
        }
        try:
            compiled = unix_seconds(stamp, tag="pe_timedatestamp")
        except TimestampError:
            compiled = None
        if compiled is not None and EARLIEST <= compiled.ts <= reference + timedelta(days=1):
            ts, ts_original = compiled.ts, compiled.original
            raw["ts_source"] = "pe_timedatestamp"
            raw["compile_time"] = compiled.ts.isoformat()
        else:
            ts, ts_original = reference, None
            raw["ts_source"] = ref_source
            tags += ["compile_time_suspect", "time_inferred"]
        stats.assumptions.update({"timezone": "UTC (TimeDateStamp)", "machine": machine})
        yield Event(
            ts=ts,
            ts_original=ts_original,
            source_type=SOURCE,
            message=f"PE {'DLL' if is_dll else 'executable'} {ctx.source_file} ({machine}, "
            f"{len(sections)} sections, {len(imports)} imports"
            + (", packed" if packed else "")
            + (f", suspicious: {', '.join(sorted(suspicious)[:5])}" if suspicious else "")
            + ")",
            record_key="pe",
            source_record_id=hashes["sha256"],
            source_file=ctx.source_file,
            host=ctx.host_hint,
            event_code="pe_triage",
            event_category="file",
            action="static_analysis",
            file_hash=hashes["sha256"],
            file_path=ctx.source_file,
            tags=tags,
            raw=raw,
        )
        ctx.progress(1.0)
