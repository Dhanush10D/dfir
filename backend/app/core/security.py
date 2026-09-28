"""Password hashing, password policy, tokens, JWT, secret encryption and TOTP helpers (guide 16).

Pure helpers: no database, no web framework. ``services/iam.py`` composes them.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import jwt
import pyotp
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import Settings

# ---------------------------------------------------------------------------------------------
# Passwords (Argon2id)
# ---------------------------------------------------------------------------------------------


def make_password_hasher(settings: Settings) -> PasswordHasher:
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_kib,
        parallelism=settings.argon2_parallelism,
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )


def hash_password(hasher: PasswordHasher, password: str) -> str:
    return hasher.hash(password)


def verify_password(hasher: PasswordHasher, stored_hash: str | None, password: str) -> bool:
    """Verify an Argon2id hash. A missing hash still burns one Argon2 computation (timing)."""
    if not stored_hash:
        _burn(hasher, password)
        return False
    try:
        return hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _burn(hasher: PasswordHasher, password: str) -> None:
    with contextlib.suppress(VerifyMismatchError, VerificationError, InvalidHashError):
        hasher.verify(_dummy_hash(hasher), password)


_DUMMY_CACHE: dict[tuple[int, int, int], str] = {}


def _dummy_hash(hasher: PasswordHasher) -> str:
    key = (hasher.time_cost, hasher.memory_cost, hasher.parallelism)
    if key not in _DUMMY_CACHE:
        _DUMMY_CACHE[key] = hasher.hash(secrets.token_urlsafe(16))
    return _DUMMY_CACHE[key]


@cache
def common_passwords() -> frozenset[str]:
    """Bundled list of breached/common passwords (offline stand-in for a k-anonymity API)."""
    text = resources.files("app.core.data").joinpath("common-passwords.txt").read_text("utf-8")
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )


def check_password_policy(password: str, email: str | None, min_length: int = 12) -> list[str]:
    """Human-readable policy violations (guide 16.2: length >= 12, not breached)."""
    problems: list[str] = []
    if len(password) < min_length:
        problems.append(f"must be at least {min_length} characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    lowered = password.lower()
    if lowered in common_passwords():
        problems.append("is a commonly used password")
    if len(set(password)) < 4:
        problems.append("uses too few distinct characters")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 4 and local in lowered:
            problems.append("must not contain your e-mail name")
    return problems


# ---------------------------------------------------------------------------------------------
# Opaque tokens (refresh tokens, API keys, recovery codes)
# ---------------------------------------------------------------------------------------------

API_KEY_PREFIX = "dfk_"
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def new_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def new_recovery_code() -> str:
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def normalize_recovery_code(code: str) -> str:
    return code.strip().lower().replace("-", "").replace(" ", "")


# ---------------------------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------------------------

TokenType = Literal["access", "mfa"]


class TokenError(Exception):
    """Token missing, malformed, expired, of the wrong type, or badly signed."""


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


class JwtCodec:
    """Access tokens and MFA challenges. HS256 by default, EdDSA with JWT_PRIVATE_KEY_PATH."""

    def __init__(self, settings: Settings) -> None:
        self.issuer = settings.jwt_issuer
        self.kid = settings.jwt_key_id
        self.access_ttl = timedelta(minutes=settings.access_token_minutes)
        self.mfa_ttl = timedelta(minutes=settings.mfa_challenge_minutes)
        self._sign_key: Any
        self._verify_key: Any
        if settings.jwt_private_key_path:
            private = load_ed25519_private_key(Path(settings.jwt_private_key_path))
            self.algorithm = "EdDSA"
            self._sign_key = private
            self._verify_key = private.public_key()
        else:
            if settings.jwt_secret is None or not settings.jwt_secret.get_secret_value():
                raise ValueError("JWT_SECRET or JWT_PRIVATE_KEY_PATH must be configured")
            secret = settings.jwt_secret.get_secret_value().encode("utf-8")
            self.algorithm = "HS256"
            self._sign_key = self._verify_key = secret

    def _issue(
        self, typ: TokenType, subject: str, ttl: timedelta, now: datetime | None, **claims: Any
    ) -> IssuedToken:
        issued = now or datetime.now(UTC)
        jti = uuid.uuid4().hex
        exp = issued + ttl
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "typ": typ,
            "jti": jti,
            "iat": int(issued.timestamp()),
            "exp": int(exp.timestamp()),
            **claims,
        }
        token = jwt.encode(
            payload, self._sign_key, algorithm=self.algorithm, headers={"kid": self.kid}
        )
        return IssuedToken(token=token, jti=jti, expires_at=exp)

    def issue_access(
        self, user_id: uuid.UUID, role: str, now: datetime | None = None
    ) -> IssuedToken:
        return self._issue("access", str(user_id), self.access_ttl, now, role=role)

    def issue_mfa_challenge(self, user_id: uuid.UUID, now: datetime | None = None) -> IssuedToken:
        return self._issue("mfa", str(user_id), self.mfa_ttl, now)

    def decode(self, token: str, expected: TokenType) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("kid") != self.kid:
                raise TokenError("unknown key id")
            claims: dict[str, Any] = jwt.decode(
                token,
                self._verify_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub", "jti", "typ", "iss"]},
                leeway=5,
            )
        except jwt.PyJWTError as exc:
            raise TokenError(type(exc).__name__) from exc
        if claims.get("typ") != expected:
            raise TokenError("wrong token type")
        return claims


def load_ed25519_private_key(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


# ---------------------------------------------------------------------------------------------
# Column encryption for TOTP secrets (AES-256-GCM, key derived from TOTP_ENC_KEY with HKDF)
# ---------------------------------------------------------------------------------------------

_BOX_VERSION = b"\x01"


class SecretBox:
    def __init__(self, key_material: str, purpose: bytes = b"dfirbench/totp/v1") -> None:
        if not key_material:
            raise ValueError("encryption key material is empty")
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=purpose)
        self._aead = AESGCM(hkdf.derive(key_material.encode("utf-8")))

    def encrypt(self, plaintext: bytes, associated: bytes = b"") -> bytes:
        nonce = secrets.token_bytes(12)
        return _BOX_VERSION + nonce + self._aead.encrypt(nonce, plaintext, associated)

    def decrypt(self, blob: bytes, associated: bytes = b"") -> bytes:
        if len(blob) < 1 + 12 + 16 or blob[:1] != _BOX_VERSION:
            raise ValueError("unsupported ciphertext")
        return self._aead.decrypt(blob[1:13], blob[13:], associated)


# ---------------------------------------------------------------------------------------------
# TOTP (RFC 6238 via pyotp) with replay protection by time step
# ---------------------------------------------------------------------------------------------


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)


def totp_code(secret: str, at: datetime | None = None) -> str:
    return pyotp.TOTP(secret).at(at or datetime.now(UTC))


def match_totp_step(
    secret: str,
    code: str,
    *,
    now: datetime | None = None,
    last_step: int | None = None,
    window: int = 1,
) -> int | None:
    """Time step the code belongs to (within +-window), or None. Steps <= last_step are replays."""
    code = code.strip().replace(" ", "")
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current = totp.timecode(now or datetime.now(UTC))
    for step in range(current - window, current + window + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None
