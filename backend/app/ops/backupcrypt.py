"""Streaming authenticated encryption for backups (Phase 10, guide 20.2 "backups encrypted").

File format (all integers big-endian)::

    magic      8 bytes  b"DFIRBK1\\n"
    kdf        1 byte   1 = scrypt
    log2_n     1 byte   scrypt cost (N = 2**log2_n)
    r, p       1 byte each
    salt       16 bytes
    prefix     7 bytes  random nonce prefix
    chunk      4 bytes  plaintext chunk size
    then records: length (4 bytes) + AES-256-GCM ciphertext of one chunk (with its 16-byte tag)

Each chunk is sealed with nonce = prefix || counter (4 bytes) || last-chunk flag (1 byte) and the
header as associated data (the STREAM construction): truncating, reordering, duplicating or
appending records, a wrong passphrase, or any flipped bit makes decryption fail, and nothing after
a failing record is written. The key is derived from ``BACKUP_PASSPHRASE`` with scrypt; the
passphrase is never logged or written anywhere.

    python -m app.ops.backupcrypt encrypt < plain > file.enc   # passphrase from BACKUP_PASSPHRASE
    python -m app.ops.backupcrypt decrypt < file.enc > plain
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"DFIRBK1\n"
KDF_SCRYPT = 1
CHUNK = 1024 * 1024
MAX_CHUNK = 16 * 1024 * 1024
TAG = 16
SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P = 15, 8, 1
HEADER = struct.Struct(">8sBBBB16s7sI")
MIN_PASSPHRASE = 20
PLACEHOLDERS = frozenset({"changeme", "change-me", "backup-passphrase", "dev-only-backup"})


class BackupCryptoError(Exception):
    """The file is not a backup, the passphrase is wrong, or the data was modified."""


def check_passphrase(value: str | None) -> str:
    if not value or len(value) < MIN_PASSPHRASE:
        raise ValueError(f"BACKUP_PASSPHRASE must be at least {MIN_PASSPHRASE} characters")
    if value.strip().lower() in PLACEHOLDERS:
        raise ValueError("BACKUP_PASSPHRASE is a placeholder")
    return value


def _key(passphrase: str, salt: bytes, log2_n: int, r: int, p: int) -> bytes:
    if not 14 <= log2_n <= 20 or not 1 <= r <= 16 or not 1 <= p <= 4:
        raise BackupCryptoError("unsupported key derivation parameters")
    kdf = Scrypt(salt=salt, length=32, n=2**log2_n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= 2**32:
        raise BackupCryptoError("too many chunks")
    return prefix + struct.pack(">I", counter) + (b"\x01" if last else b"\x00")


def _read_exact(src: BinaryIO, n: int) -> bytes:
    data = b""
    while len(data) < n:
        part = src.read(n - len(data))
        if not part:
            break
        data += part
    return data


def encrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str, *, chunk: int = CHUNK) -> str:
    """Encrypt ``src`` into ``dst``; returns the SHA-256 of the plaintext."""
    check_passphrase(passphrase)
    salt, prefix = os.urandom(16), os.urandom(7)
    header = HEADER.pack(MAGIC, KDF_SCRYPT, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P, salt, prefix, chunk)
    aead = AESGCM(_key(passphrase, salt, SCRYPT_LOG2_N, SCRYPT_R, SCRYPT_P))
    dst.write(header)
    digest = hashlib.sha256()
    counter = 0
    current = _read_exact(src, chunk)
    while True:
        following = _read_exact(src, chunk) if len(current) == chunk else b""
        last = not following
        digest.update(current)
        sealed = aead.encrypt(_nonce(prefix, counter, last), current, header)
        dst.write(struct.pack(">I", len(sealed)) + sealed)
        counter += 1
        if last:
            break
        current = following
    dst.flush()
    return digest.hexdigest()


def decrypt_stream(src: BinaryIO, dst: BinaryIO, passphrase: str) -> str:
    """Decrypt ``src`` into ``dst`` (record by record); returns the plaintext SHA-256."""
    header = _read_exact(src, HEADER.size)
    if len(header) != HEADER.size:
        raise BackupCryptoError("not a dfirbench backup file")
    magic, kdf, log2_n, r, p, salt, prefix, chunk = HEADER.unpack(header)
    if magic != MAGIC or kdf != KDF_SCRYPT or not 0 < chunk <= MAX_CHUNK:
        raise BackupCryptoError("not a dfirbench backup file")
    aead = AESGCM(_key(passphrase, salt, log2_n, r, p))
    digest = hashlib.sha256()
    counter = 0
    while True:
        size_bytes = _read_exact(src, 4)
        if len(size_bytes) != 4:
            raise BackupCryptoError("backup is truncated (no final chunk)")
        (size,) = struct.unpack(">I", size_bytes)
        if not TAG <= size <= chunk + TAG:
            raise BackupCryptoError("corrupt record length")
        sealed = _read_exact(src, size)
        if len(sealed) != size:
            raise BackupCryptoError("backup is truncated")
        plain: bytes | None = None
        last = False
        for flag in (False, True):
            try:
                plain = aead.decrypt(_nonce(prefix, counter, flag), sealed, header)
                last = flag
                break
            except InvalidTag:
                continue
        if plain is None:
            raise BackupCryptoError("wrong passphrase or modified backup")
        digest.update(plain)
        dst.write(plain)
        counter += 1
        if last:
            if src.read(1):
                raise BackupCryptoError("data after the final chunk")
            dst.flush()
            return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.ops.backupcrypt")
    parser.add_argument("mode", choices=("encrypt", "decrypt"))
    parser.add_argument("--passphrase-env", default="BACKUP_PASSPHRASE")
    args = parser.parse_args(argv)
    passphrase = os.environ.get(args.passphrase_env, "")
    try:
        if args.mode == "encrypt":
            encrypt_stream(sys.stdin.buffer, sys.stdout.buffer, passphrase)
        else:
            decrypt_stream(sys.stdin.buffer, sys.stdout.buffer, passphrase)
    except (ValueError, BackupCryptoError) as exc:
        print(f"error: {exc}", file=sys.stderr)  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
