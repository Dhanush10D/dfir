"""Minimal registry hive (regf) writer for synthetic test fixtures.

Produces a valid base block (signature, sequence numbers, root offset, bins size, embedded file
name, XOR checksum) and one hive bin with allocated cells for ``nk``/``vk``/``lf``/value-list/data
cells and ``db`` big-data records for values over 16344 bytes. Only what ``app.parsers.regf``
needs (no security cells, no class names).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

BIG = 16344


@dataclass
class RegValue:
    name: str
    type: int
    data: bytes


@dataclass
class RegKey:
    name: str
    ts: int  # FILETIME
    values: list[RegValue] = field(default_factory=list)
    subkeys: list[RegKey] = field(default_factory=list)

    def key(self, path: str, ts: int) -> RegKey:
        node = self
        for part in path.split("\\"):
            nxt = next((k for k in node.subkeys if k.name.lower() == part.lower()), None)
            if nxt is None:
                nxt = RegKey(part, ts)
                node.subkeys.append(nxt)
            node = nxt
        return node

    def sz(self, name: str, text: str) -> RegKey:
        self.values.append(RegValue(name, 1, (text + "\x00").encode("utf-16-le")))
        return self

    def dword(self, name: str, number: int) -> RegKey:
        self.values.append(RegValue(name, 4, struct.pack("<I", number)))
        return self

    def qword(self, name: str, number: int) -> RegKey:
        self.values.append(RegValue(name, 11, struct.pack("<Q", number)))
        return self

    def binary(self, name: str, data: bytes, type_: int = 3) -> RegKey:
        self.values.append(RegValue(name, type_, data))
        return self


class HiveWriter:
    def __init__(self) -> None:
        self.cells = bytearray()

    def alloc(self, payload: bytes) -> int:
        size = 4 + len(payload)
        size += (-size) % 8
        offset = 32 + len(self.cells)  # hive-bin offsets start after the 32-byte hbin header
        self.cells += struct.pack("<i", -size) + payload + b"\x00" * (size - 4 - len(payload))
        return offset

    def _data(self, data: bytes) -> tuple[int, int]:
        """(size field, data offset) for value data."""
        if len(data) <= 4:
            return 0x80000000 | len(data), struct.unpack("<I", data.ljust(4, b"\x00"))[0]
        if len(data) > BIG:
            segments = [self.alloc(data[i : i + BIG]) for i in range(0, len(data), BIG)]
            seg_list = self.alloc(b"".join(struct.pack("<I", s) for s in segments))
            db = self.alloc(b"db" + struct.pack("<HI", len(segments), seg_list))
            return len(data), db
        return len(data), self.alloc(data)

    def _value(self, value: RegValue) -> int:
        size, offset = self._data(value.data)
        name = value.name.encode("latin-1")
        return self.alloc(
            b"vk"
            + struct.pack("<HIIIHH", len(name), size, offset, value.type, 1 if name else 0, 0)
            + name
        )

    def write_key(self, key: RegKey, root: bool = False) -> int:
        children = [self.write_key(k) for k in key.subkeys]
        values = [self._value(v) for v in key.values]
        subkey_list = 0xFFFFFFFF
        if children:
            subkey_list = self.alloc(
                b"lf"
                + struct.pack("<H", len(children))
                + b"".join(
                    struct.pack("<I4s", c, k.name[:4].encode("latin-1").ljust(4, b"\x00"))
                    for c, k in zip(children, key.subkeys, strict=True)
                )
            )
        value_list = 0xFFFFFFFF
        if values:
            value_list = self.alloc(b"".join(struct.pack("<I", v) for v in values))
        name = key.name.encode("latin-1")
        flags = 0x2C if root else 0x20
        body = (
            b"nk"
            + struct.pack("<HQII", flags, key.ts, 0, 0)
            + struct.pack("<IIII", len(children), 0, subkey_list, 0xFFFFFFFF)
            + struct.pack("<III", len(values), value_list, 0xFFFFFFFF)
            + struct.pack("<I", 0xFFFFFFFF)
            + struct.pack("<IIIII", 0, 0, 0, 0, 0)
            + struct.pack("<HH", len(name), 0)
            + name
        )
        return self.alloc(body)


def build_hive(
    root: RegKey, embedded_name: str, last_written: int, *, dirty: bool = False
) -> bytes:
    writer = HiveWriter()
    root_offset = writer.write_key(root, root=True)
    cells = bytes(writer.cells)
    bin_size = 32 + len(cells)
    bin_size += (-bin_size) % 4096
    hbin = b"hbin" + struct.pack("<IIQQI", 0, bin_size, 0, last_written, 0) + b"\x00" * 0
    hbin = hbin.ljust(32, b"\x00") + cells
    hbin = hbin.ljust(bin_size, b"\x00")
    name = embedded_name.encode("utf-16-le")[:64].ljust(64, b"\x00")
    base = bytearray(4096)
    struct.pack_into(
        "<4sIIQIIIIIII",
        base,
        0,
        b"regf",
        1,
        2 if dirty else 1,
        last_written,
        1,
        5,
        0,
        1,
        root_offset,
        bin_size,
        1,
    )
    base[48:112] = name
    xor = 0
    for (dword,) in struct.iter_unpack("<I", bytes(base[:508])):
        xor ^= dword
    xor = 1 if xor == 0 else (0xFFFFFFFE if xor == 0xFFFFFFFF else xor)
    struct.pack_into("<I", base, 508, xor)
    return bytes(base) + hbin
