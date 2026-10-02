"""Backup encryption (Phase 10): round trip and every way a backup file can be tampered with."""

from __future__ import annotations

import hashlib
import io
import os
import struct

import pytest

from app.ops.backupcrypt import (
    HEADER,
    BackupCryptoError,
    check_passphrase,
    decrypt_stream,
    encrypt_stream,
    main,
)

PASS = "correct horse battery staple 42"
CHUNK = 64


def _enc(data: bytes, passphrase: str = PASS) -> bytes:
    out = io.BytesIO()
    assert (
        encrypt_stream(io.BytesIO(data), out, passphrase, chunk=CHUNK)
        == hashlib.sha256(data).hexdigest()
    )
    return out.getvalue()


def _dec(blob: bytes, passphrase: str = PASS) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, passphrase)
    return out.getvalue()


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 7])
def test_round_trip(size: int) -> None:
    data = os.urandom(size)
    blob = _enc(data)
    assert data not in blob or size == 0
    assert _dec(blob) == data


def test_same_input_encrypts_differently() -> None:
    assert _enc(b"x" * 100) != _enc(b"x" * 100)


def _records(blob: bytes) -> tuple[bytes, list[bytes]]:
    header, rest = blob[: HEADER.size], blob[HEADER.size :]
    records = []
    while rest:
        (n,) = struct.unpack(">I", rest[:4])
        records.append(rest[: 4 + n])
        rest = rest[4 + n :]
    return header, records


def test_tampering_is_detected() -> None:
    blob = _enc(os.urandom(4 * CHUNK + 3))
    header, records = _records(blob)
    assert len(records) == 5
    cases = {
        "wrong passphrase": (blob, "another passphrase, also long"),
        "flipped bit": (blob[:-5] + bytes([blob[-5] ^ 1]) + blob[-4:], PASS),
        "flipped header": (bytes([blob[0] ^ 1]) + blob[1:], PASS),
        "salt changed": (blob[:14] + bytes([blob[14] ^ 1]) + blob[15:], PASS),
        "truncated (last record dropped)": (header + b"".join(records[:-1]), PASS),
        "truncated mid-record": (blob[:-3], PASS),
        "reordered": (header + records[1] + records[0] + b"".join(records[2:]), PASS),
        "duplicated record": (header + records[0] + b"".join(records), PASS),
        "appended data": (blob + b"\x00", PASS),
        "appended record": (blob + records[-1], PASS),
        "empty": (b"", PASS),
        "not a backup": (b"PK\x03\x04" + b"\x00" * 100, PASS),
    }
    for name, (data, passphrase) in cases.items():
        with pytest.raises(BackupCryptoError):
            _dec(data, passphrase)
        assert name


def test_passphrase_policy() -> None:
    for bad in ("", "short", "changeme"):
        with pytest.raises(ValueError):
            check_passphrase(bad)
    with pytest.raises(ValueError):
        encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), "too-short")
    assert check_passphrase(PASS) == PASS


def test_cli_reads_the_passphrase_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    assert main(["encrypt"]) == 1
    assert PASS not in capsys.readouterr().err
