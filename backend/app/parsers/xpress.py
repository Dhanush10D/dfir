"""LZXPRESS Huffman decompression ([MS-XCA] 2.1.4 / 2.2.4), used for Win10+ Prefetch (``MAM``).

Own implementation (spec decision 3). Bounded: the caller passes the declared output size (capped
by the caller); output never grows past it, every match offset must point inside the output
already produced, and invalid Huffman tables raise ``XpressError``. Reading past the end of the
input yields zero bits (as the reference decoder does) but a block that needs more than a few
padding words is rejected, so corrupt input cannot spin.
"""

from __future__ import annotations

BLOCK_OUTPUT = 65536
TABLE_BYTES = 256
TABLE_BITS = 15
SYMBOLS = 512


class XpressError(ValueError):
    pass


def _decoding_table(lengths_raw: bytes) -> tuple[list[int], list[int]]:
    lengths = [0] * SYMBOLS
    for i, byte in enumerate(lengths_raw):
        lengths[2 * i] = byte & 0x0F
        lengths[2 * i + 1] = byte >> 4
    table = [0] * (1 << TABLE_BITS)
    entry = 0
    for bit_length in range(1, 16):
        count = 1 << (TABLE_BITS - bit_length)
        for symbol in range(SYMBOLS):
            if lengths[symbol] == bit_length:
                if entry + count > len(table):
                    raise XpressError("Huffman table overflows")
                table[entry : entry + count] = [symbol] * count
                entry += count
    if entry != len(table):
        raise XpressError("Huffman table is incomplete")
    return table, lengths


def decompress_huffman(data: bytes, out_size: int) -> bytes:
    """Decompress ``data`` to exactly ``out_size`` bytes or raise ``XpressError``."""
    if out_size < 0:
        raise XpressError("negative output size")
    out = bytearray()
    pos = 0
    n = len(data)
    overrun = 0

    def read16(at: int) -> int:
        nonlocal overrun
        if at + 2 <= n:
            return data[at] | (data[at + 1] << 8)
        overrun += 1
        if overrun > 8:
            raise XpressError("input ends inside a block")
        return data[at] if at < n else 0

    while len(out) < out_size:
        if pos + TABLE_BYTES > n:
            raise XpressError("truncated Huffman table")
        table, lengths = _decoding_table(data[pos : pos + TABLE_BYTES])
        pos += TABLE_BYTES
        next_bits = (read16(pos) << 16) | read16(pos + 2)
        pos += 4
        extra = 16
        block_end = min(len(out) + BLOCK_OUTPUT, out_size)
        while len(out) < block_end:
            symbol = table[next_bits >> (32 - TABLE_BITS)]
            bits = lengths[symbol]
            next_bits = (next_bits << bits) & 0xFFFFFFFF
            extra -= bits
            if extra < 0:
                next_bits |= read16(pos) << (-extra)
                next_bits &= 0xFFFFFFFF
                extra += 16
                pos += 2
            if symbol < 256:
                out.append(symbol)
                continue
            if symbol == 256 and pos >= n and len(out) >= out_size:
                break
            symbol -= 256
            length = symbol & 0x0F
            offset_bits = symbol >> 4
            if length == 15:
                if pos >= n:
                    raise XpressError("truncated match length")
                length = data[pos]
                pos += 1
                if length == 255:
                    if pos + 2 > n:
                        raise XpressError("truncated match length")
                    length = data[pos] | (data[pos + 1] << 8)
                    pos += 2
                    if length < 15:
                        raise XpressError("invalid match length")
                    length -= 15
                length += 15
            length += 3
            offset = (next_bits >> (32 - offset_bits)) if offset_bits else 0
            offset += 1 << offset_bits
            next_bits = (next_bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                next_bits |= read16(pos) << (-extra)
                next_bits &= 0xFFFFFFFF
                extra += 16
                pos += 2
            if offset > len(out):
                raise XpressError("match offset before the start of the output")
            length = min(length, out_size - len(out))
            start = len(out) - offset
            for i in range(length):  # byte-wise: overlapping matches repeat recent output
                out.append(out[start + i])
    return bytes(out[:out_size])
