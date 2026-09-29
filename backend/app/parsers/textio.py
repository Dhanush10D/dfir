"""Streaming, bounded line reader for text logs (plain or gzip), shared by line-based parsers.

Memory is bounded by ``CHUNK`` + ``max_line_bytes``: lines longer than the limit are reported as
``too_long`` and their bytes are discarded up to the next newline. Gzip input is decompressed
incrementally with two zip-bomb guards: an absolute cap on decompressed bytes and a
decompressed/compressed ratio cap (checked once the output passes a floor).
"""

from __future__ import annotations

import gzip
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.parsers.base import ParseLimits, ParseStats

CHUNK = 64 * 1024
GZIP_MAGIC = b"\x1f\x8b"


@dataclass(frozen=True)
class Line:
    number: int  # 1-based
    offset: int  # byte offset of the line start in the (decompressed) stream
    data: bytes  # without the line terminator; empty when too_long
    too_long: bool = False
    length: int = 0


def head_text(head: bytes, limit: int = 8192) -> bytes:
    """First bytes of plain or gzip content (bounded), for sniffing."""
    if head.startswith(GZIP_MAGIC):
        try:
            return zlib.decompressobj(wbits=31).decompress(head, limit)
        except zlib.error:
            return b""
    return head[:limit]


class _Guarded:
    """Decompressing reader that enforces the zip-bomb limits."""

    def __init__(self, raw: BinaryIO, limits: ParseLimits) -> None:
        self.raw = raw
        self.gz = gzip.GzipFile(fileobj=raw, mode="rb")
        self.limits = limits
        self.out = 0

    def read(self, n: int) -> bytes:
        data = self.gz.read(n)
        self.out += len(data)
        if self.out > self.limits.max_decompressed_bytes:
            raise DecompressionLimitError("decompressed size limit exceeded")
        if self.out > self.limits.ratio_check_after_bytes:
            consumed = max(self.raw.tell(), 1)
            if self.out / consumed > self.limits.max_decompression_ratio:
                raise DecompressionLimitError("decompression ratio limit exceeded")
        return data


class DecompressionLimitError(Exception):
    pass


def iter_lines(
    path: Path,
    limits: ParseLimits,
    stats: ParseStats,
    progress: Callable[[float], None],
) -> Iterator[Line]:
    """Yield lines; stream-level failures are counted in ``stats`` and end the iteration.

    A decompression limit or a corrupt/truncated gzip stream counts one unreadable unit (read +
    error) and sets ``stats.assumptions['incomplete']`` so the run is reported as partial.
    """
    total = max(path.stat().st_size, 1)
    with path.open("rb") as raw:  # the scratch copy is read-only (0400)
        compressed = raw.read(2) == GZIP_MAGIC
        raw.seek(0)
        stats.assumptions["compression"] = "gzip" if compressed else "none"
        source: _Guarded | BinaryIO = _Guarded(raw, limits) if compressed else raw
        buffer = bytearray()
        number = 0
        offset = 0  # stream offset of buffer[0]
        discarding = False  # inside an over-long line
        discard_start = 0
        discard_len = 0
        max_line = limits.max_line_bytes
        while True:
            try:
                chunk = source.read(CHUNK)
            except DecompressionLimitError as exc:
                _stream_failure(stats, number, offset, "decompression_limit", str(exc))
                return
            except (OSError, EOFError, zlib.error) as exc:
                _stream_failure(stats, number, offset, "decompression_error", type(exc).__name__)
                return
            stats.bytes_read = offset + len(buffer) + len(chunk)
            progress(min(raw.tell() / total, 1.0))
            if not chunk:
                break
            buffer.extend(chunk)
            while True:
                nl = buffer.find(b"\n")
                if nl < 0:
                    if discarding:
                        discard_len += len(buffer)
                        offset += len(buffer)
                        buffer.clear()
                    elif len(buffer) > max_line:
                        discarding = True
                        discard_start = offset
                        discard_len = len(buffer)
                        offset += len(buffer)
                        buffer.clear()
                    break
                if discarding:
                    number += 1
                    yield Line(number, discard_start, b"", True, discard_len + nl)
                    discarding = False
                else:
                    number += 1
                    data = bytes(buffer[:nl])
                    if len(data) > max_line:
                        yield Line(number, offset, b"", True, len(data))
                    else:
                        yield Line(number, offset, data.removesuffix(b"\r"), False, len(data))
                del buffer[: nl + 1]
                offset += nl + 1
        if discarding:
            number += 1
            yield Line(number, discard_start, b"", True, discard_len)
        elif buffer:
            number += 1
            data = bytes(buffer)
            if len(data) > max_line:
                yield Line(number, offset, b"", True, len(data))
            else:
                yield Line(number, offset, data.removesuffix(b"\r"), False, len(data))
        progress(1.0)


def _stream_failure(stats: ParseStats, number: int, offset: int, code: str, detail: str) -> None:
    stats.read()
    stats.error(f"after line {number} (byte {offset})", code, detail)
    stats.assumptions["incomplete"] = code
