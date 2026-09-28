"""Ed25519 custody signer and key-file tooling (guide 8.3, 20.3).

The private key lives in a PKCS#8 PEM file (optionally passphrase-encrypted) referenced by
``CUSTODY_SIGNING_KEY_PATH``; it is never stored in the database or the repository. The public
key is published in ``signing_keys`` so every signature stays verifiable after rotation.

Dev key generation (writes outside the repo tree or into the git-ignored ``var/``)::

    python -m app.core.signing generate --out ../var/keys/custody-dev.pem --if-missing
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.config import Settings
from app.core.security import load_ed25519_private_key

ALGORITHM = "ed25519"


class SigningKeyError(RuntimeError):
    """The custody signing key is missing or unusable."""


def public_key_pem(public: Ed25519PublicKey) -> str:
    return public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_public_key_pem(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise SigningKeyError("public key is not a valid PEM") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError("public key is not Ed25519")
    return key


def key_fingerprint_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"ed25519-{hashlib.sha256(raw).hexdigest()[:16]}"


def verify_signature(public: Ed25519PublicKey, signature_hex: str, message: str) -> bool:
    try:
        public.verify(bytes.fromhex(signature_hex), message.encode("ascii"))
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class CustodySigner:
    key_id: str
    private_key: Ed25519PrivateKey

    def sign(self, message: str) -> str:
        """Hex Ed25519 signature over the ASCII message (the hex entry hash)."""
        return self.private_key.sign(message.encode("ascii")).hex()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_pem(self) -> str:
        return public_key_pem(self.public_key)


def load_signer(settings: Settings) -> CustodySigner:
    path = settings.custody_signing_key_path
    if not path:
        raise SigningKeyError(
            "CUSTODY_SIGNING_KEY_PATH is not set; generate a dev key with "
            "`python -m app.core.signing generate --out ../var/keys/custody-dev.pem`"
        )
    passphrase = (
        settings.custody_signing_key_passphrase.get_secret_value().encode("utf-8")
        if settings.custody_signing_key_passphrase
        else None
    )
    try:
        private = load_ed25519_private_key(Path(path), passphrase)
    except (OSError, ValueError, TypeError) as exc:
        raise SigningKeyError(f"cannot load custody signing key: {type(exc).__name__}") from exc
    key_id = settings.custody_key_id or key_fingerprint_id(private.public_key())
    return CustodySigner(key_id=key_id, private_key=private)


def generate_key_file(path: Path, passphrase: bytes | None = None) -> Ed25519PrivateKey:
    """Write a new Ed25519 PKCS#8 PEM with owner-only permissions. Refuses to overwrite."""
    key = Ed25519PrivateKey.generate()
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.core.signing")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="create an Ed25519 custody signing key file")
    gen.add_argument("--out", required=True, type=Path)
    gen.add_argument("--if-missing", action="store_true", help="exit 0 if the file exists")
    gen.add_argument(
        "--passphrase-env", help="encrypt the PEM with the passphrase in this env variable"
    )
    show = sub.add_parser("show", help="print key id and public key of a key file")
    show.add_argument("path", type=Path)
    show.add_argument("--passphrase-env")
    args = parser.parse_args(argv)

    passphrase: bytes | None = None
    if args.passphrase_env:
        value = os.environ.get(args.passphrase_env)
        if not value:
            print(f"environment variable {args.passphrase_env} is empty", file=sys.stderr)  # noqa: T201
            return 2
        passphrase = value.encode("utf-8")

    if args.command == "generate":
        if args.out.exists():
            if args.if_missing:
                key = load_ed25519_private_key(args.out, passphrase)
                print(f"exists: {args.out} key_id={key_fingerprint_id(key.public_key())}")  # noqa: T201
                return 0
            print(f"refusing to overwrite {args.out}", file=sys.stderr)  # noqa: T201
            return 1
        key = generate_key_file(args.out, passphrase)
        print(f"created: {args.out} key_id={key_fingerprint_id(key.public_key())}")  # noqa: T201
        return 0

    key = load_ed25519_private_key(args.path, passphrase)
    print(key_fingerprint_id(key.public_key()))  # noqa: T201
    print(public_key_pem(key.public_key()), end="")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
