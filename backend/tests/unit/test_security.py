from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.exceptions import InvalidTag

from app.config import Settings
from app.core.security import (
    JwtCodec,
    SecretBox,
    TokenError,
    check_password_policy,
    common_passwords,
    hash_password,
    make_password_hasher,
    match_totp_step,
    new_api_key,
    new_recovery_code,
    new_totp_secret,
    normalize_recovery_code,
    sha256_hex,
    totp_code,
    totp_uri,
    verify_password,
)
from app.core.signing import generate_key_file


def fast(**kw: object) -> Settings:
    base: dict[str, object] = {
        "argon2_time_cost": 1,
        "argon2_memory_kib": 1024,
        "argon2_parallelism": 1,
        "jwt_secret": "unit-test-jwt-secret-0123456789abcdef",
    }
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_default_argon2_parameters_are_rfc9106_low_memory() -> None:
    hasher = make_password_hasher(Settings(_env_file=None))  # type: ignore[call-arg]
    assert (hasher.time_cost, hasher.memory_cost, hasher.parallelism) == (3, 65536, 4)


def test_argon2id_hash_and_verify() -> None:
    hasher = make_password_hasher(fast())
    stored = hash_password(hasher, "Correct-Horse-Battery-42")
    assert stored.startswith("$argon2id$v=19$m=1024,t=1,p=1$")
    assert verify_password(hasher, stored, "Correct-Horse-Battery-42")
    assert not verify_password(hasher, stored, "correct-horse-battery-42")
    assert not verify_password(hasher, "not-a-hash", "x")
    assert not verify_password(hasher, None, "x")  # still burns one hash (timing)
    stronger = make_password_hasher(fast(argon2_time_cost=2))
    assert stronger.check_needs_rehash(stored)


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("short", "at least 12"),
        ("password1234", "commonly used"),
        ("PASSWORD1234", "commonly used"),
        ("aaaabbbbaaaa", "too few distinct"),
        ("jane.doe-rocks-2026", "e-mail name"),
        ("x" * 257, "at most 256"),
    ],
)
def test_password_policy_rejects(password: str, problem: str) -> None:
    problems = check_password_policy(password, "jane.doe@example.org")
    assert any(problem in p for p in problems), problems


def test_password_policy_accepts_good_passphrase() -> None:
    assert check_password_policy("Correct-Horse-Battery-42", "jane@example.org") == []
    assert "password1234" in common_passwords()


def test_opaque_tokens() -> None:
    key = new_api_key()
    assert key.startswith("dfk_") and len(key) > 40
    assert new_api_key() != key
    code = new_recovery_code()
    assert len(code) == 11 and code[5] == "-"
    assert normalize_recovery_code(code.upper()) == code.replace("-", "")
    assert sha256_hex("abc") == sha256_hex(b"abc") and len(sha256_hex("abc")) == 64


def test_jwt_access_roundtrip() -> None:
    codec = JwtCodec(fast())
    uid = uuid.uuid4()
    issued = codec.issue_access(uid, "lead")
    header = jwt.get_unverified_header(issued.token)
    assert header == {"alg": "HS256", "kid": "jwt-1", "typ": "JWT"}
    claims = codec.decode(issued.token, "access")
    assert claims["sub"] == str(uid) and claims["role"] == "lead" and claims["jti"] == issued.jti
    assert claims["exp"] - claims["iat"] == 15 * 60


def test_jwt_rejections() -> None:
    codec = JwtCodec(fast())
    uid = uuid.uuid4()
    expired = codec.issue_access(uid, "lead", now=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(TokenError):
        codec.decode(expired.token, "access")
    challenge = codec.issue_mfa_challenge(uid)
    with pytest.raises(TokenError, match="wrong token type"):
        codec.decode(challenge.token, "access")
    assert codec.decode(challenge.token, "mfa")["sub"] == str(uid)
    other = JwtCodec(fast(jwt_secret="another-secret-0123456789abcdefghijkl"))
    with pytest.raises(TokenError):
        other.decode(codec.issue_access(uid, "lead").token, "access")
    unsigned = jwt.encode(
        {"sub": str(uid), "typ": "access", "iss": "dfirbench", "jti": "x", "iat": 1, "exp": 2**40},
        key=None,
        algorithm="none",
        headers={"kid": "jwt-1"},
    )
    with pytest.raises(TokenError):
        codec.decode(unsigned, "access")
    rotated = JwtCodec(fast(jwt_key_id="jwt-2"))
    with pytest.raises(TokenError, match="unknown key id"):
        rotated.decode(codec.issue_access(uid, "lead").token, "access")
    token = codec.issue_access(uid, "lead").token
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(TokenError):
        codec.decode(tampered, "access")


def test_jwt_eddsa_with_private_key_file(tmp_path: Path) -> None:
    path = tmp_path / "jwt.pem"
    generate_key_file(path)
    codec = JwtCodec(fast(jwt_private_key_path=str(path)))
    assert codec.algorithm == "EdDSA"
    uid = uuid.uuid4()
    assert codec.decode(codec.issue_access(uid, "viewer").token, "access")["role"] == "viewer"


def test_jwt_requires_a_key() -> None:
    with pytest.raises(ValueError, match="JWT_SECRET"):
        JwtCodec(fast(jwt_secret=None))


def test_secret_box_roundtrip_and_binding() -> None:
    box = SecretBox("some-key-material")
    user = uuid.uuid4().bytes
    blob = box.encrypt(b"JBSWY3DPEHPK3PXP", user)
    assert blob[:1] == b"\x01" and b"JBSWY3DP" not in blob
    assert box.decrypt(blob, user) == b"JBSWY3DPEHPK3PXP"
    assert box.encrypt(b"same", user) != box.encrypt(b"same", user)  # random nonce
    with pytest.raises(InvalidTag):
        box.decrypt(blob, uuid.uuid4().bytes)  # bound to the user id
    with pytest.raises(InvalidTag):
        SecretBox("other-key").decrypt(blob, user)
    with pytest.raises(ValueError):
        box.decrypt(b"\x02" + blob[1:], user)
    with pytest.raises(ValueError):
        SecretBox("")


def test_totp_matching_window_and_replay() -> None:
    secret = new_totp_secret()
    now = datetime(2026, 9, 28, 12, 0, 10, tzinfo=UTC)
    code = totp_code(secret, now)
    step = match_totp_step(secret, code, now=now)
    assert step == int(now.timestamp()) // 30
    # Accepted one step late (clock skew), rejected two steps late.
    assert match_totp_step(secret, code, now=now + timedelta(seconds=30)) == step
    assert match_totp_step(secret, code, now=now + timedelta(seconds=90)) is None
    # Replay protection: the same or an earlier step is refused.
    assert match_totp_step(secret, code, now=now, last_step=step) is None
    later = totp_code(secret, now + timedelta(seconds=30))
    assert match_totp_step(secret, later, now=now, last_step=step) == step + 1
    for bad in ("", "12345", "1234567", "abcdef"):
        assert match_totp_step(secret, bad, now=now) is None
    assert totp_uri(secret, "a@b.c", "dfirbench").startswith("otpauth://totp/dfirbench:a%40b.c")


def test_totp_default_clock() -> None:
    secret = new_totp_secret()
    assert match_totp_step(secret, totp_code(secret)) is not None
