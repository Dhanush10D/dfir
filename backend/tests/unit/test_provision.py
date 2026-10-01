"""SCRAM-SHA-256 verifier for the app login (Phase 10), checked against RFC 7677's example."""

from __future__ import annotations

import base64
import hashlib
import hmac

import pytest

from app.db.provision import check_password, scram_sha256_verifier

# RFC 7677 section 3: user "user", password "pencil", 4096 iterations.
SALT = base64.b64decode("W22ZaJ0SNY7soEsUEjb6gQ==")
AUTH_MESSAGE = (
    b"n=user,r=rOprNGfwEbeRWgbNEkqO,"
    b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,"
    b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
)
CLIENT_PROOF = base64.b64decode("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
SERVER_SIGNATURE = base64.b64decode("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")


def test_verifier_matches_the_rfc_7677_exchange() -> None:
    verifier = scram_sha256_verifier("pencil", salt=SALT)
    scheme, rest = verifier.split("$", 1)
    params, keys = rest.split("$")
    assert scheme == "SCRAM-SHA-256" and params == "4096:W22ZaJ0SNY7soEsUEjb6gQ=="
    stored_key, server_key = (base64.b64decode(k) for k in keys.split(":"))
    # The server signature of the RFC exchange is HMAC(ServerKey, AuthMessage) ...
    assert hmac.new(server_key, AUTH_MESSAGE, hashlib.sha256).digest() == SERVER_SIGNATURE
    # ... and the client proof recovers a ClientKey whose hash is the StoredKey.
    signature = hmac.new(stored_key, AUTH_MESSAGE, hashlib.sha256).digest()
    client_key = bytes(a ^ b for a, b in zip(CLIENT_PROOF, signature, strict=True))
    assert hashlib.sha256(client_key).digest() == stored_key


def test_verifier_uses_a_fresh_salt() -> None:
    assert scram_sha256_verifier("x" * 20) != scram_sha256_verifier("x" * 20)


@pytest.mark.parametrize("bad", ["", "short", "nön-ascii-password-xx", "tab\tin-password-xxxx"])
def test_password_policy(bad: str) -> None:
    with pytest.raises(ValueError):
        check_password(bad)
    if bad and not (bad.isascii() and bad.isprintable()):
        with pytest.raises(ValueError):
            scram_sha256_verifier(bad)
    assert check_password("a-long-enough-password") == "a-long-enough-password"
