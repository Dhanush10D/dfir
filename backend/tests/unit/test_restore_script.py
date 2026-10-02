"""scripts/restore.py helpers (Phase 10): authenticate first, stream plaintext, report findings."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from app.ops.backupcrypt import BackupCryptoError, encrypt_stream

ROOT = Path(__file__).resolve().parents[3]
DATA_PASS = "data passphrase for the restore tests"
KEYS_PASS = "keys passphrase for the restore tests"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("restore_script", ROOT / "scripts" / "restore.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


restore = _module()


def _backup(tmp_path: Path) -> dict[str, Any]:
    """Three encrypted files like a format-2 backup: the key archive has its own passphrase."""
    files: dict[str, Any] = {}
    for name in restore.FILES:
        plain = f"plain {name} ".encode() * 1000
        passphrase = KEYS_PASS if name == "keys.tar.enc" else DATA_PASS
        with (tmp_path / name).open("wb") as out:
            encrypt_stream(io.BytesIO(plain), out, passphrase)
        files[name] = {"plain_sha256": hashlib.sha256(plain).hexdigest()}
    return {"version": 2, "files": files}


PASSPHRASES = {"data": DATA_PASS, "keys": KEYS_PASS}


def test_authentication_pass_writes_nothing_and_needs_both_passphrases(tmp_path: Path) -> None:
    index = _backup(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    restore.authenticate_all(tmp_path, index, PASSPHRASES)
    assert sorted(p.name for p in tmp_path.iterdir()) == before  # no plaintext anywhere
    with pytest.raises(BackupCryptoError):  # the data passphrase does not open the key archive
        restore.authenticate_all(tmp_path, index, {"data": DATA_PASS, "keys": DATA_PASS})
    index["files"]["db.dump.enc"]["plain_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match=r"differs from index.json"):
        restore.authenticate_all(tmp_path, index, PASSPHRASES)


def test_decrypt_into_streams_to_the_consumer(tmp_path: Path) -> None:
    index = _backup(tmp_path)
    target = tmp_path / "consumed"
    copy = [
        sys.executable,
        "-c",
        "import sys, shutil; shutil.copyfileobj(sys.stdin.buffer, open(sys.argv[1], 'wb'))",
        str(target),
    ]
    restore.decrypt_into(copy, None, tmp_path, "keys.tar.enc", index, PASSPHRASES)
    expected = index["files"]["keys.tar.enc"]["plain_sha256"]
    assert hashlib.sha256(target.read_bytes()).hexdigest() == expected


def test_decrypt_into_reports_a_failing_consumer(tmp_path: Path) -> None:
    index = _backup(tmp_path)
    fail = [sys.executable, "-c", "import sys; sys.stderr.write('no space left'); sys.exit(4)"]
    with pytest.raises(RuntimeError, match=r"restoring db.dump.enc failed: no space left"):
        restore.decrypt_into(fail, None, tmp_path, "db.dump.enc", index, PASSPHRASES)


def test_known_findings_are_listed() -> None:
    baseline = {
        "problems": [
            {"code": "evidence_changed", "evidence_id": "e1", "message": "bytes differ"},
            {"code": "chain_broken", "message": "custody chain"},
        ]
    }
    assert restore.known_findings(baseline) == [
        "chain_broken: custody chain",
        "evidence_changed evidence=e1: bytes differ",
    ]
    assert restore.known_findings({"problems": []}) == []


def test_index_accepts_format_1_and_2_only(tmp_path: Path) -> None:
    for version in (0, 3):
        (tmp_path / "index.json").write_text(
            json.dumps({"format": "dfirbench-backup", "version": version, "files": {}})
        )
        with pytest.raises(RuntimeError, match="not a dfirbench backup index"):
            restore.verify_index(tmp_path)
