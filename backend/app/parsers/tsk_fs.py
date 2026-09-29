"""Sleuth Kit file-system timeline for disk images (guide 10.3 ``tsk_fs``, spec decision 8).

``mmls`` lists the partitions (no table: the image is treated as one file system at offset 0);
for each allocated partition (at most ``MAX_PARTITIONS``) ``fls -r -m /pNN`` writes a TSK 3+
body file into the job work dir (``tools.run_tool``: fixed argv, clean env, timeout, output cap).
``-z <zone>`` is passed for the ``timezone`` job parameter (FAT stores local times).

Body file line: ``MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`` (Unix seconds,
UTC). One record per distinct non-zero time of a line, emitted as one event whose ``event_code``
is the MACB string (``m.cb`` style, as ``mactime`` prints it); a line without any time is one
skipped record; an unparseable line is an error. Names marked ``(deleted)`` get the ``deleted``
tag. A partition fls cannot read is a warning; if none can be read the job fails with fls's
message.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from app.parsers.base import (
    Event,
    ParseContext,
    ParserInputError,
    record_cap_reached,
    require_work_dir,
    snippet,
)
from app.parsers.registry import register
from app.parsers.textio import iter_lines
from app.parsers.timeconv import TimestampError, unix_seconds
from app.parsers.tools import (
    ToolFailedError,
    find_tool,
    image_tool_versions,
    run_tool,
)

SOURCE = "filesystem"
MAX_PARTITIONS = 16
MMLS_RE = re.compile(r"^\s*(\d+):\s+(\d+:\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")
E01_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"
IMAGE_NAMES = (".dd", ".raw", ".img", ".e01", ".001", ".vhd", ".iso")


def mmls_partitions(text: str) -> list[tuple[int, str]]:
    """(start sector, description) of the allocated partitions in ``mmls`` output."""
    found: list[tuple[int, str]] = []
    for line in text.splitlines():
        m = MMLS_RE.match(line)
        if m:
            found.append((int(m.group(3)), m.group(6).strip()[:128]))
    return found[:MAX_PARTITIONS]


def looks_like_disk(head: bytes) -> bool:
    if head.startswith(E01_MAGIC):
        return True
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        return True  # MBR / FAT / NTFS boot sector
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        return True
    return len(head) >= 1082 and head[1080:1082] == b"\x53\xef"  # ext2/3/4 superblock magic


@register
class TskFsParser:
    name = "tsk_fs"
    version = "1.0.0"
    description = "Disk images: Sleuth Kit file-system timeline (mmls + fls -r -m), MACB events"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return image_tool_versions(["sleuthkit"])

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        if looks_like_disk(head):
            return 0.6
        return 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        note = "Sleuth Kit, see docs/parsers.md"
        fls = find_tool("fls", ctx.tools, optional_note=note)
        mmls = find_tool("mmls", ctx.tools, optional_note=note)
        work = require_work_dir(ctx)
        tz = str(ctx.params.get("timezone") or "UTC")
        heartbeat = lambda: ctx.progress(0.05)  # noqa: E731
        listing = run_tool(
            [mmls, str(ctx.path)],
            cwd=work,
            stdout=work / "mmls.txt",
            cfg=ctx.tools,
            heartbeat=heartbeat,
        )
        partitions: list[tuple[int, str]] = []
        if listing.returncode == 0:
            partitions = mmls_partitions(
                (work / "mmls.txt").read_bytes()[: 1024 * 1024].decode("utf-8", "replace")
            )
        targets = partitions or [(0, "whole image")]
        stats.assumptions.update(
            {
                "timezone": "UTC (body file epoch)",
                "fls_timezone": tz,
                "partition_table": bool(partitions),
                "partitions": [{"start_sector": s, "description": d} for s, d in targets],
            }
        )
        readable = 0
        errors: list[str] = []
        for slot, (start, _desc) in enumerate(targets):
            prefix = f"/p{slot:02d}" if partitions else "/"
            argv = [fls, "-r", "-m", prefix, "-o", str(start)]
            if tz != "UTC":
                argv += ["-z", tz]
            argv.append(str(ctx.path))
            body = work / f"body-{slot:02d}.txt"
            result = run_tool(argv, cwd=work, stdout=body, cfg=ctx.tools, heartbeat=heartbeat)
            if result.returncode != 0:
                errors.append(f"partition {slot} (sector {start}): {result.stderr_tail}")
                stats.warn("partition_unreadable", f"sector {start}", result.stderr_tail)
                continue
            readable += 1
            yield from self._body(ctx, body, slot)
            if record_cap_reached(ctx):
                return
        if readable == 0:
            raise ToolFailedError("fls could not read a file system: " + "; ".join(errors)[:900])
        if errors:
            stats.assumptions["incomplete"] = "partition_unreadable"
        ctx.progress(1.0)

    def _body(self, ctx: ParseContext, body: Path, slot: int) -> Iterator[Event]:
        stats = ctx.stats
        for line in iter_lines(body, ctx.limits, stats, lambda _f: None):
            location = f"partition {slot} line {line.number}"
            if line.too_long:
                stats.read()
                stats.error(location, "line_too_long", f"{line.length} bytes")
                continue
            text = line.data.decode("utf-8", "replace")
            if not text.strip():
                continue
            parts = text.split("|")
            if len(parts) < 11:
                stats.read()
                stats.error(location, "malformed_body_line", snippet(text))
                continue
            md5 = parts[0]
            name = "|".join(parts[1:-9])
            inode, mode, uid, gid, size, *times = parts[-9:]
            try:
                values = [int(t) for t in times]
            except ValueError:
                stats.read()
                stats.error(location, "bad_timestamp", snippet(text))
                continue
            groups: dict[int, str] = {}
            for letter, value in zip(
                "macb", (values[1], values[0], values[2], values[3]), strict=True
            ):
                if value > 0:
                    groups[value] = groups.get(value, "") + letter
            if not groups:
                stats.read()
                stats.skip(location, "no_times")
                continue
            deleted = "(deleted" in name
            for value, letters in sorted(groups.items()):
                stats.read()
                macb = "".join(c if c in letters else "." for c in "macb")
                try:
                    converted = unix_seconds(value, tag="unix")
                except TimestampError as exc:
                    stats.error(location, "bad_timestamp", str(exc))
                    continue
                if converted is None:  # pragma: no cover - zero filtered above
                    stats.skip(location, "no_times")
                    continue
                yield Event(
                    ts=converted.ts,
                    ts_original=converted.original,
                    source_type=SOURCE,
                    message=f"{macb} {name}",
                    record_key=f"p{slot}:l{line.number}:{macb}",
                    source_record_id=f"p{slot}:{inode}",
                    source_file=ctx.source_file,
                    host=ctx.host_hint,
                    event_code=macb,
                    event_category="file",
                    action="file_timestamp",
                    file_path=name.replace(" (deleted)", "").replace(" (deleted-realloc)", ""),
                    tags=["deleted"] if deleted else [],
                    raw={
                        "partition": slot,
                        "inode": inode,
                        "mode": mode,
                        "uid": uid,
                        "gid": gid,
                        "size": size,
                        "md5": md5 if md5 != "0" else None,
                        "name": name,
                        "atime": values[0],
                        "mtime": values[1],
                        "ctime": values[2],
                        "crtime": values[3],
                    },
                )


__all__ = ["ParserInputError", "TskFsParser", "mmls_partitions"]
