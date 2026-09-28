from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import Settings
from app.core.signing import (
    SigningKeyError,
    generate_key_file,
    key_fingerprint_id,
    load_public_key_pem,
    load_signer,
    main,
    verify_signature,
)


def settings(**kw: object) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[arg-type]


def test_generate_and_load_signer(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "custody.pem"
    key = generate_key_file(path)
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    signer = load_signer(settings(custody_signing_key_path=str(path)))
    assert signer.key_id == key_fingerprint_id(key.public_key())
    assert signer.key_id.startswith("ed25519-") and len(signer.key_id) == 24
    sig = signer.sign("ab" * 32)
    public = load_public_key_pem(signer.public_key_pem())
    assert verify_signature(public, sig, "ab" * 32)
    assert not verify_signature(public, sig, "cd" * 32)
    assert not verify_signature(public, "zz", "ab" * 32)
    explicit = load_signer(settings(custody_signing_key_path=str(path), custody_key_id="custody-1"))
    assert explicit.key_id == "custody-1"
    with pytest.raises(FileExistsError):
        generate_key_file(path)  # never overwrite a key


def test_passphrase_protected_key(tmp_path: Path) -> None:
    path = tmp_path / "enc.pem"
    generate_key_file(path, passphrase=b"s3cret-passphrase")
    assert b"ENCRYPTED" in path.read_bytes()
    with pytest.raises(SigningKeyError):
        load_signer(settings(custody_signing_key_path=str(path)))
    signer = load_signer(
        settings(
            custody_signing_key_path=str(path), custody_signing_key_passphrase="s3cret-passphrase"
        )
    )
    assert signer.sign("00")


def test_load_signer_errors(tmp_path: Path) -> None:
    with pytest.raises(SigningKeyError, match="CUSTODY_SIGNING_KEY_PATH"):
        load_signer(settings())
    with pytest.raises(SigningKeyError):
        load_signer(settings(custody_signing_key_path=str(tmp_path / "missing.pem")))
    with pytest.raises(SigningKeyError):
        load_public_key_pem(
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"
        )
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(SigningKeyError, match="not Ed25519"):
        load_public_key_pem(ec_pem.decode())
    ec_file = tmp_path / "ec.pem"
    ec_file.write_bytes(
        ec_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(SigningKeyError):
        load_signer(settings(custody_signing_key_path=str(ec_file)))


def test_cli_generate_if_missing_and_show(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "dev.pem"
    assert main(["generate", "--out", str(path)]) == 0
    first = path.read_bytes()
    assert "created" in capsys.readouterr().out
    assert main(["generate", "--out", str(path)]) == 1  # refuses to overwrite
    assert main(["generate", "--out", str(path), "--if-missing"]) == 0
    assert path.read_bytes() == first
    assert main(["show", str(path)]) == 0
    out = capsys.readouterr().out
    assert "ed25519-" in out and "BEGIN PUBLIC KEY" in out

    monkeypatch.setenv("KEY_PASS", "pass-phrase-123")
    enc = tmp_path / "enc.pem"
    assert main(["generate", "--out", str(enc), "--passphrase-env", "KEY_PASS"]) == 0
    assert main(["show", str(enc), "--passphrase-env", "KEY_PASS"]) == 0
    assert main(["generate", "--out", str(tmp_path / "x.pem"), "--passphrase-env", "NOPE"]) == 2
