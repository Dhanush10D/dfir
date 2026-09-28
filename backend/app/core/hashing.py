"""Streaming hashing helpers (guide 8.2): SHA-256 + MD5 + size in one pass, bounded memory."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol


class Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@dataclass(frozen=True)
class Digests:
    sha256: str
    md5: str  # legacy comparison only (guide 8.1)
    size: int

    def as_dict(self) -> dict[str, str | int]:
        return {"sha256": self.sha256, "md5": self.md5, "size": self.size}


class MultiHasher:
    def __init__(self) -> None:
        self._sha256 = hashlib.sha256()
        self._md5 = hashlib.md5(usedforsecurity=False)
        self.size = 0

    def update(self, chunk: bytes) -> None:
        self._sha256.update(chunk)
        self._md5.update(chunk)
        self.size += len(chunk)

    def digests(self) -> Digests:
        return Digests(self._sha256.hexdigest(), self._md5.hexdigest(), self.size)


class UploadTooLargeError(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"upload exceeds the limit of {limit} bytes")
        self.limit = limit


class HashingReader:
    """File-like wrapper: hashes every byte read from ``source`` and enforces ``max_bytes``.

    It never holds more than the caller's requested ``size`` bytes, so memory stays bounded by the
    consumer's read size (one multipart part for the vault upload).
    """

    def __init__(self, source: Readable, max_bytes: int) -> None:
        self._source = source
        self._max = max_bytes
        self.hasher = MultiHasher()
        self.max_read = 0  # largest single read request seen (tests assert streaming)

    def read(self, size: int = -1, /) -> bytes:
        self.max_read = max(self.max_read, size)
        chunk = self._source.read(size)
        if chunk:
            if self.hasher.size + len(chunk) > self._max:
                raise UploadTooLargeError(self._max)
            self.hasher.update(chunk)
        return chunk


def hash_chunks(chunks: Iterable[bytes]) -> Digests:
    hasher = MultiHasher()
    for chunk in chunks:
        hasher.update(chunk)
    return hasher.digests()
