"""Envelope encryption of integration secrets and webhook signatures (pure)."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from app.config import Settings
from app.integrations import webhooks
from app.integrations.crypto import (
    Keyring,
    SealedSecret,
    SecretDecryptError,
    SecretsUnavailableError,
    integration_aad,
)

KEK = "unit-test-kek-material-0123456789"
SECRET = {"signing_secret": "s3cr3t-value-that-must-never-leak-0001"}


def _settings(**kw: object) -> Settings:
    return Settings(_env_file=None, app_env="test", **kw)  # type: ignore[call-arg,arg-type]


def test_seal_and_open_round_trip() -> None:
    ring = Keyring("kek-1", KEK)
    aad = integration_aad("11111111-1111-1111-1111-111111111111")
    sealed = ring.seal(SECRET, aad)
    assert sealed.key_id == "kek-1"
    assert ring.open(sealed, aad) == SECRET
    blob = sealed.ciphertext + sealed.wrapped_key
    assert b"s3cr3t" not in blob and KEK.encode() not in blob
    # Fresh data key and nonces every time: equal secrets do not give equal ciphertexts.
    again = ring.seal(SECRET, aad)
    assert again.ciphertext != sealed.ciphertext and again.wrapped_key != sealed.wrapped_key


def test_ciphertext_is_bound_to_its_row_and_key() -> None:
    ring = Keyring("kek-1", KEK)
    aad = integration_aad("row-a")
    sealed = ring.seal(SECRET, aad)
    with pytest.raises(SecretDecryptError):
        ring.open(sealed, integration_aad("row-b"))  # copied to another integration
    with pytest.raises(SecretDecryptError):
        Keyring("kek-1", KEK + "x").open(sealed, aad)  # another KEK under the same id
    with pytest.raises(SecretDecryptError, match="unknown key id"):
        Keyring("kek-2", KEK).open(sealed, aad)
    flipped = bytearray(sealed.ciphertext)
    flipped[-1] ^= 1
    with pytest.raises(SecretDecryptError):
        ring.open(SealedSecret(bytes(flipped), sealed.wrapped_key, sealed.key_id), aad)
    with pytest.raises(SecretDecryptError):
        ring.open(SealedSecret(sealed.ciphertext, sealed.wrapped_key[:-1], sealed.key_id), aad)
    with pytest.raises(SecretDecryptError):
        ring.open(SealedSecret(b"\x02" + sealed.ciphertext[1:], sealed.wrapped_key, "kek-1"), aad)
    # A wrapped key relabelled with another key id does not open either (the id is in the AAD).
    both = Keyring("kek-2", "another-kek-material-0123456789", {"kek-1": KEK})
    with pytest.raises(SecretDecryptError):
        both.open(SealedSecret(sealed.ciphertext, sealed.wrapped_key, "kek-2"), aad)


def test_rotation_keeps_old_rows_readable_and_rewrap_moves_them() -> None:
    old = Keyring("kek-1", KEK)
    aad = integration_aad("row")
    sealed = old.seal(SECRET, aad)
    new = Keyring("kek-2", "rotated-kek-material-9876543210", {"kek-1": KEK})
    assert new.open(sealed, aad) == SECRET and new.needs_rewrap(sealed)
    moved = new.rewrap(sealed, aad)
    assert moved.key_id == "kek-2" and moved.ciphertext == sealed.ciphertext
    assert not new.needs_rewrap(moved)
    assert Keyring("kek-2", "rotated-kek-material-9876543210").open(moved, aad) == SECRET
    with pytest.raises(SecretDecryptError):
        old.open(moved, aad)  # the retired KEK no longer opens it


def test_fingerprint_is_keyed_and_short() -> None:
    ring = Keyring("kek-1", KEK)
    fp = ring.fingerprint(SECRET)
    assert len(fp) == 12 and fp == ring.fingerprint(dict(SECRET))
    assert fp != ring.fingerprint({"signing_secret": "other"})
    assert fp != Keyring("kek-1", KEK + "x").fingerprint(SECRET)
    plain = hashlib.sha256(json.dumps(SECRET, sort_keys=True).encode()).hexdigest()
    assert fp not in plain[:12]


def test_keyring_from_settings(tmp_path: Path) -> None:
    with pytest.raises(SecretsUnavailableError):
        Keyring.from_settings(_settings())
    with pytest.raises(SecretsUnavailableError):
        Keyring.from_settings(_settings(integration_kek="short"))
    ring = Keyring.from_settings(_settings(integration_kek=KEK, integration_kek_id="k-env"))
    assert ring.current_id == "k-env"
    key_file = tmp_path / "kek"
    key_file.write_text("file-kek-material-0123456789abcdef\n", encoding="utf-8")
    previous = tmp_path / "previous.json"
    previous.write_text(json.dumps({"k-env": KEK, "bad": 5}), encoding="utf-8")
    sealed = ring.seal(SECRET, b"aad")
    from_file = Keyring.from_settings(
        _settings(
            integration_kek_path=str(key_file),
            integration_kek_id="k-file",
            integration_kek_previous_path=str(previous),
        )
    )
    assert from_file.current_id == "k-file" and from_file.open(sealed, b"aad") == SECRET
    with pytest.raises(SecretsUnavailableError):
        Keyring.from_settings(_settings(integration_kek_path=str(tmp_path / "missing")))
    previous.write_text("[1]", encoding="utf-8")
    with pytest.raises(SecretsUnavailableError):
        Keyring.from_settings(
            _settings(integration_kek=KEK, integration_kek_previous_path=str(previous))
        )
    with pytest.raises(ValueError, match="too large"):
        ring.seal({"x": "y" * 20000}, b"aad")


def test_prod_refuses_a_placeholder_kek(bare_env: None) -> None:
    base = {
        "app_env": "prod",
        "jwt_secret": "x" * 40,
        "totp_enc_key": "y" * 40,
        "s3_secret_key": "z" * 20,
        "database_url": "postgresql+psycopg://u:p@db/d",
        "cors_origins": ["https://dfir.example"],
        "custody_signing_key_path": "/k.pem",
        "custody_key_id": "k1",
    }
    with pytest.raises(ValueError, match="INTEGRATION_KEK"):
        Settings(_env_file=None, **base, integration_kek="dev-only-integration-kek-change-me")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ENRICHMENT_FAKE"):
        Settings(_env_file=None, **base, enrichment_fake=True)  # type: ignore[arg-type]
    ok = Settings(_env_file=None, **base, integration_kek="k" * 40)  # type: ignore[arg-type]
    assert ok.integration_kek is not None and "kkkk" not in repr(ok)


# ------------------------------------------------------------------------------ signatures


def test_signature_matches_the_documented_construction() -> None:
    body = b'{"type":"alert.created"}'
    value = webhooks.sign("topsecret", 1_700_000_000, body)
    expected = hmac.new(b"topsecret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert value == "sha256=" + expected


def test_verify_accepts_only_fresh_authentic_deliveries() -> None:
    body = b'{"alerts":[]}'
    now = 1_700_000_000
    sig = webhooks.sign("topsecret", now, body)
    digest = sig.removeprefix("sha256=")

    def check(**kw: object) -> str | None:
        args: dict[str, object] = {
            "secret": "topsecret",
            "timestamp": str(now),
            "body": body,
            "signature": sig,
            "now": float(now),
            "window_s": 300,
        }
        args.update(kw)
        return webhooks.verify(
            args["secret"],  # type: ignore[arg-type]
            args["timestamp"],  # type: ignore[arg-type]
            args["body"],  # type: ignore[arg-type]
            args["signature"],  # type: ignore[arg-type]
            now=args["now"],  # type: ignore[arg-type]
            window_s=args["window_s"],  # type: ignore[arg-type]
        )

    assert check() == digest
    assert check(signature=digest) == digest  # prefix optional
    assert check(signature=sig.upper().replace("SHA256=", "sha256=")) == digest
    assert check(now=float(now + 300)) == digest and check(now=float(now - 300)) == digest
    for bad in (
        {"secret": "other"},
        {"body": body + b" "},
        {"timestamp": str(now + 1)},
        {"now": float(now + 301)},
        {"now": float(now - 301)},
        {"signature": None},
        {"signature": ""},
        {"signature": "sha256=" + "0" * 64},
        {"signature": "md5=abc"},
        {"signature": sig[:-1]},
        {"timestamp": None},
        {"timestamp": "-5"},
        {"timestamp": "1e9"},
        {"timestamp": "9" * 40},
    ):
        assert check(**bad) is None, bad


def test_verify_uses_a_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(webhooks.hmac, "compare_digest", spy)
    webhooks.verify(
        "s", "1700000000", b"x", "sha256=" + "a" * 64, now=1_700_000_000.0, window_s=300
    )
    webhooks.verify("s", None, b"x", None, now=1_700_000_000.0, window_s=300)
    assert len(calls) == 2  # also for malformed input: no early exit
