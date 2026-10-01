"""Envelope encryption for integration credentials and webhook secrets (guide 19.3, 20.3).

* Each secret gets a random 256-bit data key (DEK); the secret is encrypted with AES-256-GCM
  under the DEK, and the DEK is wrapped with AES-256-GCM under the key-encryption key (KEK).
* The KEK never touches the database: it is derived (HKDF-SHA256) from ``INTEGRATION_KEK`` or the
  file ``INTEGRATION_KEK_PATH``. ``INTEGRATION_KEK_ID`` names it and is stored with every sealed
  secret, so a rotation can keep reading old rows (retired KEKs: ``INTEGRATION_KEK_PREVIOUS_PATH``,
  JSON ``{key_id: key material}``) and :func:`rewrap` moves a row to the current KEK without
  touching the secret itself.
* The associated data binds a ciphertext to its row (and the wrapped key to its key id): a blob
  copied to another integration does not decrypt.
* :meth:`Keyring.fingerprint` is a keyed (HMAC) fingerprint, so equal secrets can be recognised
  without storing anything an attacker could test guesses against offline.

Nothing here logs or returns key material; errors carry no secret data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import Settings

VERSION = b"\x01"
NONCE_LEN = 12
KEK_INFO = b"dfirbench/integrations/kek/v1"
FINGERPRINT_INFO = b"dfirbench/integrations/fingerprint/v1"
MIN_KEY_MATERIAL = 16
MAX_SECRET_BYTES = 16 * 1024
FINGERPRINT_HEX = 12


class SecretsUnavailableError(Exception):
    """No usable key-encryption key is configured."""


class SecretDecryptError(Exception):
    """A sealed secret could not be opened (unknown key id, wrong key, or tampering)."""


@dataclass(frozen=True)
class SealedSecret:
    ciphertext: bytes
    wrapped_key: bytes
    key_id: str


def _derive(material: str, info: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(material.encode("utf-8"))


def _box(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_LEN)
    return VERSION + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _unbox(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 1 + NONCE_LEN + 16 or blob[:1] != VERSION:
        raise SecretDecryptError("unsupported ciphertext")
    try:
        return AESGCM(key).decrypt(blob[1 : 1 + NONCE_LEN], blob[1 + NONCE_LEN :], aad)
    except InvalidTag as exc:
        raise SecretDecryptError("authentication failed") from exc


class Keyring:
    """The current KEK plus retired ones (decrypt only)."""

    def __init__(
        self, current_id: str, material: str, previous: Mapping[str, str] | None = None
    ) -> None:
        if not current_id or len(current_id) > 64:
            raise SecretsUnavailableError("the key id must be 1-64 characters")
        if len(material) < MIN_KEY_MATERIAL:
            raise SecretsUnavailableError(
                f"key material must be at least {MIN_KEY_MATERIAL} characters"
            )
        self.current_id = current_id
        self._keys: dict[str, bytes] = {current_id: _derive(material, KEK_INFO)}
        self._fingerprint_key = _derive(material, FINGERPRINT_INFO)
        for key_id, old in (previous or {}).items():
            if key_id != current_id and isinstance(old, str) and len(old) >= MIN_KEY_MATERIAL:
                self._keys[str(key_id)] = _derive(old, KEK_INFO)

    @classmethod
    def from_settings(cls, settings: Settings) -> Keyring:
        material: str | None = None
        if settings.integration_kek_path:
            try:
                material = Path(settings.integration_kek_path).read_text("utf-8").strip()
            except OSError as exc:
                raise SecretsUnavailableError("INTEGRATION_KEK_PATH is not readable") from exc
        elif settings.integration_kek is not None:
            material = settings.integration_kek.get_secret_value().strip()
        if not material:
            raise SecretsUnavailableError(
                "INTEGRATION_KEK or INTEGRATION_KEK_PATH is not configured"
            )
        previous: dict[str, str] = {}
        if settings.integration_kek_previous_path:
            try:
                loaded = json.loads(Path(settings.integration_kek_previous_path).read_text("utf-8"))
            except (OSError, ValueError) as exc:
                raise SecretsUnavailableError(
                    "INTEGRATION_KEK_PREVIOUS_PATH is not readable JSON"
                ) from exc
            if not isinstance(loaded, dict):
                raise SecretsUnavailableError("INTEGRATION_KEK_PREVIOUS_PATH must be an object")
            previous = {str(k): v for k, v in loaded.items() if isinstance(v, str)}
        return cls(settings.integration_kek_id, material, previous)

    @staticmethod
    def _wrap_aad(aad: bytes, key_id: str) -> bytes:
        return aad + b"|kek:" + key_id.encode("utf-8")

    def seal(self, secret: Mapping[str, Any], aad: bytes) -> SealedSecret:
        plaintext = json.dumps(dict(secret), separators=(",", ":"), sort_keys=True).encode()
        if len(plaintext) > MAX_SECRET_BYTES:
            raise ValueError("the secret is too large")
        dek = secrets.token_bytes(32)
        return SealedSecret(
            ciphertext=_box(dek, plaintext, aad),
            wrapped_key=_box(
                self._keys[self.current_id], dek, self._wrap_aad(aad, self.current_id)
            ),
            key_id=self.current_id,
        )

    def _dek(self, sealed: SealedSecret, aad: bytes) -> bytes:
        kek = self._keys.get(sealed.key_id)
        if kek is None:
            raise SecretDecryptError("unknown key id")
        dek = _unbox(kek, sealed.wrapped_key, self._wrap_aad(aad, sealed.key_id))
        if len(dek) != 32:
            raise SecretDecryptError("unsupported data key")
        return dek

    def open(self, sealed: SealedSecret, aad: bytes) -> dict[str, Any]:
        plaintext = _unbox(self._dek(sealed, aad), sealed.ciphertext, aad)
        try:
            value = json.loads(plaintext)
        except ValueError as exc:
            raise SecretDecryptError("unsupported plaintext") from exc
        if not isinstance(value, dict):
            raise SecretDecryptError("unsupported plaintext")
        return value

    def needs_rewrap(self, sealed: SealedSecret) -> bool:
        return sealed.key_id != self.current_id

    def rewrap(self, sealed: SealedSecret, aad: bytes) -> SealedSecret:
        """Wrap the same data key under the current KEK (the ciphertext is unchanged)."""
        dek = self._dek(sealed, aad)
        return SealedSecret(
            ciphertext=sealed.ciphertext,
            wrapped_key=_box(
                self._keys[self.current_id], dek, self._wrap_aad(aad, self.current_id)
            ),
            key_id=self.current_id,
        )

    def fingerprint(self, secret: Mapping[str, Any]) -> str:
        data = json.dumps(dict(secret), separators=(",", ":"), sort_keys=True).encode()
        return hmac.new(self._fingerprint_key, data, hashlib.sha256).hexdigest()[:FINGERPRINT_HEX]


def integration_aad(integration_id: object) -> bytes:
    return f"dfirbench/integration/{integration_id}".encode()
