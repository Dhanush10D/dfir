"""Bounded, read-only reader for Windows registry hive files (regf), used by ``registry_hive`` and
``amcache`` (spec decision 1: regipy loops forever on a crafted big-data segment offset).

The hive is memory-mapped read-only. Every structure is bounds-checked before it is read:

* cells must be allocated (negative size), at least 8 bytes and inside the hive bins;
* list counts (subkeys, values, big-data segments) are bounded by the cell size and by caps;
* ``ri`` index roots may only point at leaf lists (no nesting), so a list walk is finite;
* key recursion is bounded by ``max_depth``; an offset already on the current path is skipped
  (cycles), and every key yielded counts against ``max_keys`` for the whole hive;
* value data is capped (``max_value_bytes``) and big-data (``db``) values are assembled from at
  most ``ceil(size / 16344)`` segments.

Anything malformed raises ``RegfError``; callers count it as a record error and continue.
Names are decoded with ``errors="replace"``; nothing from the hive becomes a file-system path.
"""

from __future__ import annotations

import mmap
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import TracebackType

from app.parsers.timeconv import Converted, TimestampError, filetime

BASE_BLOCK = 4096
REGF_SIG = b"regf"
NONE_OFFSET = 0xFFFFFFFF
KEY_COMP_NAME = 0x0020
VALUE_COMP_NAME = 0x0001
BIG_DATA_SEGMENT = 16344
REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


class RegfError(Exception):
    """Malformed or over-limit hive structure."""


@dataclass(frozen=True)
class HiveLimits:
    max_depth: int = 64
    max_keys: int = 5_000_000
    max_subkeys_per_key: int = 1_000_000
    max_values_per_key: int = 100_000
    max_value_bytes: int = 16 * 1024 * 1024


def _u16(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<H", buf, off)[0])


def _u32(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<I", buf, off)[0])


def _u64(buf: bytes, off: int) -> int:
    return int(struct.unpack_from("<Q", buf, off)[0])


def utf16z(data: bytes) -> str:
    """UTF-16LE up to the first NUL code unit."""
    if len(data) % 2:
        data = data[:-1]
    text = data.decode("utf-16-le", "replace")
    return text.split("\x00", 1)[0]


class Value:
    __slots__ = ("data", "name", "type", "type_name")

    def __init__(self, name: str, type_: int, data: bytes) -> None:
        self.name = name
        self.type = type_
        self.type_name = REG_TYPES.get(type_, f"0x{type_:x}")
        self.data = data

    def as_str(self) -> str | None:
        if self.type in (1, 2, 6) or (self.type in (0, 3) and len(self.data) % 2 == 0):
            return utf16z(self.data)
        if self.type == 7:
            return "; ".join(self.as_multi_sz())
        number = self.as_int()
        return None if number is None else str(number)

    def as_int(self) -> int | None:
        if self.type == 4 and len(self.data) >= 4:
            return _u32(self.data, 0)
        if self.type == 5 and len(self.data) >= 4:
            return int(struct.unpack_from(">I", self.data, 0)[0])
        if self.type == 11 and len(self.data) >= 8:
            return _u64(self.data, 0)
        return None

    def as_multi_sz(self) -> list[str]:
        data = self.data[: len(self.data) - len(self.data) % 2]
        return [s for s in data.decode("utf-16-le", "replace").split("\x00") if s][:1024]


class Key:
    __slots__ = (
        "_ancestors",
        "depth",
        "hive",
        "last_written_raw",
        "name",
        "offset",
        "path",
        "subkey_count",
        "subkey_list",
        "value_count",
        "value_list",
    )

    def __init__(
        self, hive: Hive, offset: int, parent_path: str, depth: int, ancestors: frozenset[int]
    ) -> None:
        cell = hive.cell(offset)
        if len(cell) < 76 or cell[:2] != b"nk":
            raise RegfError(f"no key node at 0x{offset:x}")
        flags = _u16(cell, 2)
        name_len = _u16(cell, 72)
        if 76 + name_len > len(cell):
            raise RegfError(f"key name overruns its cell at 0x{offset:x}")
        raw = cell[76 : 76 + name_len]
        name = raw.decode("latin-1") if flags & KEY_COMP_NAME else utf16z(raw)
        self.hive = hive
        self.offset = offset
        self.name = name
        self.path = f"{parent_path}\\{name}" if parent_path else name
        self.depth = depth
        self._ancestors = ancestors | {offset}
        self.last_written_raw = _u64(cell, 4)
        self.subkey_count = _u32(cell, 20)
        self.subkey_list = _u32(cell, 28)
        self.value_count = _u32(cell, 36)
        self.value_list = _u32(cell, 40)

    @property
    def last_written(self) -> Converted | None:
        """Key last-write time (``None`` = not set); raises ``TimestampError`` if invalid."""
        return filetime(self.last_written_raw)

    # ------------------------------------------------------------------ subkeys

    def _leaf_offsets(self, offset: int, allow_index_root: bool) -> Iterator[int]:
        cell = self.hive.cell(offset)
        sig = cell[:2]
        if len(cell) < 4:
            raise RegfError(f"subkey list too short at 0x{offset:x}")
        count = _u16(cell, 2)
        if sig in (b"lf", b"lh"):
            if 4 + count * 8 > len(cell):
                raise RegfError(f"subkey list count overruns its cell at 0x{offset:x}")
            for i in range(count):
                yield _u32(cell, 4 + i * 8)
        elif sig == b"li":
            if 4 + count * 4 > len(cell):
                raise RegfError(f"subkey list count overruns its cell at 0x{offset:x}")
            for i in range(count):
                yield _u32(cell, 4 + i * 4)
        elif sig == b"ri" and allow_index_root:
            if 4 + count * 4 > len(cell):
                raise RegfError(f"index root count overruns its cell at 0x{offset:x}")
            for i in range(count):
                yield from self._leaf_offsets(_u32(cell, 4 + i * 4), False)
        else:
            raise RegfError(f"unknown subkey list {bytes(sig)!r} at 0x{offset:x}")

    def subkeys(self) -> Iterator[Key]:
        if self.subkey_count == 0 or self.subkey_list == NONE_OFFSET:
            return
        limits = self.hive.limits
        if self.depth + 1 > limits.max_depth:
            raise RegfError(f"key depth limit ({limits.max_depth}) at {self.path[:200]}")
        n = 0
        for offset in self._leaf_offsets(self.subkey_list, True):
            if offset in self._ancestors:
                self.hive.cycles += 1
                continue
            n += 1
            if n > limits.max_subkeys_per_key:
                raise RegfError("subkey count limit")
            self.hive.count_key()
            yield Key(self.hive, offset, self.path, self.depth + 1, self._ancestors)

    def subkey(self, name: str) -> Key | None:
        wanted = name.lower()
        for key in self.subkeys():
            if key.name.lower() == wanted:
                return key
        return None

    def open(self, path: str) -> Key | None:
        """Descendant by backslash path (case-insensitive), or ``None``."""
        key: Key | None = self
        for part in [p for p in path.split("\\") if p]:
            if key is None:
                return None
            key = key.subkey(part)
        return key

    # ------------------------------------------------------------------ values

    def values(self) -> Iterator[Value]:
        if self.value_count == 0 or self.value_list == NONE_OFFSET:
            return
        limits = self.hive.limits
        if self.value_count > limits.max_values_per_key:
            raise RegfError(f"value count {self.value_count} over the limit")
        cell = self.hive.cell(self.value_list)
        if self.value_count * 4 > len(cell):
            raise RegfError("value list count overruns its cell")
        for i in range(self.value_count):
            yield self.hive.value_at(_u32(cell, i * 4))

    def value(self, name: str) -> Value | None:
        wanted = name.lower()
        for value in self.values():
            if value.name.lower() == wanted:
                return value
        return None


class Hive:
    def __init__(self, path: Path, *, max_bytes: int, limits: HiveLimits | None = None) -> None:
        self.limits = limits or HiveLimits()
        self.keys_visited = 0
        self.cycles = 0
        size = path.stat().st_size
        if size > max_bytes:
            raise RegfError(f"hive is {size} bytes, over the {max_bytes}-byte limit")
        if size < BASE_BLOCK + 32:
            raise RegfError("file too small for a registry hive")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            self._mm = mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
        finally:
            os.close(fd)
        try:
            self._read_base_block(size)
        except BaseException:
            self._mm.close()
            raise

    def _read_base_block(self, size: int) -> None:
        base = self._mm[:BASE_BLOCK]
        if base[:4] != REGF_SIG:
            raise RegfError("not a registry hive (no regf signature)")
        self.seq_primary = _u32(base, 4)
        self.seq_secondary = _u32(base, 8)
        self.last_written_raw = _u64(base, 12)
        self.major = _u32(base, 20)
        self.minor = _u32(base, 24)
        self.root_offset = _u32(base, 36)
        bins_size = _u32(base, 40)
        self.embedded_name = utf16z(base[48 : 48 + 64])
        stored = _u32(base, 508)
        xor = 0
        for (dword,) in struct.iter_unpack("<I", base[:508]):
            xor ^= dword
        xor = 1 if xor == 0 else (0xFFFFFFFE if xor == 0xFFFFFFFF else xor)
        self.checksum_ok = xor == stored
        self.dirty = self.seq_primary != self.seq_secondary
        self.end = min(size, BASE_BLOCK + bins_size) if bins_size else size
        if self.end <= BASE_BLOCK:
            self.end = size
        if self._mm[BASE_BLOCK : BASE_BLOCK + 4] != b"hbin":
            raise RegfError("first hive bin missing")

    # ------------------------------------------------------------------ context manager

    def close(self) -> None:
        self._mm.close()

    def __enter__(self) -> Hive:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ------------------------------------------------------------------ primitives

    def count_key(self) -> None:
        self.keys_visited += 1
        if self.keys_visited > self.limits.max_keys:
            raise RegfError(f"key visit limit ({self.limits.max_keys}) reached")

    def cell(self, offset: int) -> bytes:
        """Payload of the allocated cell at hive-bin ``offset`` (without the size field)."""
        if offset == NONE_OFFSET or offset < 32:
            raise RegfError(f"invalid cell offset 0x{offset:x}")
        start = BASE_BLOCK + offset
        if start + 4 > self.end:
            raise RegfError(f"cell offset 0x{offset:x} beyond the hive bins")
        size = int(struct.unpack_from("<i", self._mm, start)[0])
        if size >= 0:
            raise RegfError(f"cell at 0x{offset:x} is not allocated")
        length = -size
        if length < 8 or start + length > self.end:
            raise RegfError(f"cell at 0x{offset:x} has an invalid size")
        return self._mm[start + 4 : start + length]

    @property
    def last_written(self) -> Converted | None:
        return filetime(self.last_written_raw)

    @property
    def root(self) -> Key:
        return Key(self, self.root_offset, "", 0, frozenset())

    def open(self, path: str) -> Key | None:
        return self.root.open(path)

    def value_at(self, offset: int) -> Value:
        cell = self.cell(offset)
        if len(cell) < 20 or cell[:2] != b"vk":
            raise RegfError(f"no value record at 0x{offset:x}")
        name_len = _u16(cell, 2)
        size_raw = _u32(cell, 4)
        data_offset = _u32(cell, 8)
        type_ = _u32(cell, 12)
        flags = _u16(cell, 16)
        if 20 + name_len > len(cell):
            raise RegfError(f"value name overruns its cell at 0x{offset:x}")
        raw_name = cell[20 : 20 + name_len]
        name = raw_name.decode("latin-1") if flags & VALUE_COMP_NAME else utf16z(raw_name)
        return Value(name, type_, self._value_data(size_raw, data_offset))

    def _value_data(self, size_raw: int, data_offset: int) -> bytes:
        size = size_raw & 0x7FFFFFFF
        if size_raw & 0x80000000:
            if size > 4:
                raise RegfError("inline value data larger than 4 bytes")
            return struct.pack("<I", data_offset)[:size]
        if size == 0:
            return b""
        if size > self.limits.max_value_bytes:
            raise RegfError(f"value data of {size} bytes over the limit")
        cell = self.cell(data_offset)
        if size > BIG_DATA_SEGMENT and self.minor >= 4 and cell[:2] == b"db":
            return self._big_data(cell, size)
        if size > len(cell):
            raise RegfError("value data overruns its cell")
        return bytes(cell[:size])

    def _big_data(self, cell: bytes, size: int) -> bytes:
        if len(cell) < 8:
            raise RegfError("big-data record too short")
        count = _u16(cell, 2)
        needed = -(-size // BIG_DATA_SEGMENT)
        if count < needed or count > needed + 1:
            raise RegfError("big-data segment count does not match the value size")
        segments = self.cell(_u32(cell, 4))
        if count * 4 > len(segments):
            raise RegfError("big-data segment list overruns its cell")
        out = bytearray()
        for i in range(count):
            remaining = size - len(out)
            if remaining <= 0:
                break
            segment = self.cell(_u32(segments, i * 4))
            out += segment[: min(BIG_DATA_SEGMENT, remaining)]
        if len(out) != size:
            raise RegfError("big-data value is truncated")
        return bytes(out)


def hive_kind(hive: Hive, filename: str = "") -> str:
    """``system``/``software``/``ntuser``/``usrclass``/``amcache``/``sam``/``security``/
    ``unknown`` from the embedded file name, the evidence name and the root subkeys."""
    names = [PureWindowsPath(hive.embedded_name).name.lower(), filename.rsplit("/", 1)[-1].lower()]
    for name in names:
        for kind, candidates in (
            ("amcache", ("amcache.hve",)),
            ("ntuser", ("ntuser.dat",)),
            ("usrclass", ("usrclass.dat",)),
            ("system", ("system",)),
            ("software", ("software",)),
            ("sam", ("sam",)),
            ("security", ("security",)),
        ):
            if name in candidates:
                return kind
    try:
        root_names: set[str] = set()
        for n, key in enumerate(hive.root.subkeys()):
            if n >= 512:
                break
            root_names.add(key.name.lower())
    except (RegfError, TimestampError):
        return "unknown"
    if "select" in root_names and any(n.startswith("controlset") for n in root_names):
        return "system"
    if {"microsoft", "classes"} <= root_names:
        return "software"
    if {"software", "control panel"} <= root_names or "environment" in root_names:
        return "ntuser"
    if "local settings" in root_names:
        return "usrclass"
    if root_names == {"root"} or "inventoryapplicationfile" in root_names:
        return "amcache"
    return "unknown"
