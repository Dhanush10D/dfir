from __future__ import annotations

import hashlib
import io

import pytest

from app.core.hashing import HashingReader, UploadTooLargeError, hash_chunks
from app.db.models import CaseStatus
from app.repositories.vault import object_key, storage_uri
from app.services.cases import transition_allowed
from app.services.evidence import safe_filename
from tests.fakes import FakeVault


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Security.evtx", "Security.evtx"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", "Security.evtx"),
        ("evil\x00name.bin", "evilname.bin"),
        ("a b;rm -rf *.log", "a b_rm -rf _.log"),
        ("..", "evidence.bin"),
        ("", "evidence.bin"),
        ("x" * 300, "x" * 200),
        ('quote"s.txt', "quote_s.txt"),
    ],
)
def test_safe_filename(name: str, expected: str) -> None:
    assert safe_filename(name) == expected


def test_vault_layout() -> None:
    key = object_key("c1", "e1", "a.log")
    assert key == "c1/e1/original/a.log"
    assert storage_uri("evidence", key) == "s3://evidence/c1/e1/original/a.log"


def test_hashing_reader_hashes_and_limits() -> None:
    data = b"0123456789" * 100
    reader = HashingReader(io.BytesIO(data), max_bytes=len(data))
    chunks = []
    while chunk := reader.read(64):
        chunks.append(chunk)
    digests = reader.hasher.digests()
    assert b"".join(chunks) == data
    assert digests.sha256 == hashlib.sha256(data).hexdigest()
    assert digests.md5 == hashlib.md5(data).hexdigest()
    assert digests.size == len(data)
    assert reader.max_read == 64
    assert digests.as_dict() == {"sha256": digests.sha256, "md5": digests.md5, "size": 1000}
    too_big = HashingReader(io.BytesIO(data), max_bytes=999)
    with pytest.raises(UploadTooLargeError):
        while too_big.read(100):
            pass


def test_hash_chunks_empty() -> None:
    assert hash_chunks([]).sha256 == hashlib.sha256(b"").hexdigest()


def test_case_transitions() -> None:
    s = CaseStatus
    assert transition_allowed(s.open, s.containment)
    assert transition_allowed(s.containment, s.triage)
    assert not transition_allowed(s.recovery, s.triage)
    assert not transition_allowed(s.open, s.closed)
    assert transition_allowed(s.closed, s.open)
    assert not transition_allowed(s.closed, s.triage)
    assert transition_allowed(s.triage, s.triage)


def test_fake_vault_versions() -> None:
    vault = FakeVault()
    first = vault.put_stream("k", io.BytesIO(b"abc"), 5, "x").version_id
    second = vault.tamper_put("k", b"xyz")
    assert vault.stat("k").version_id == second
    assert b"".join(vault.iter_object("k", first)) == b"abc"
    vault.corrupt("k", first)
    assert b"".join(vault.iter_object("k", first)) != b"abc"
