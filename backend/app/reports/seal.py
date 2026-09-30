"""Report seal: canonical JSON, the artifact manifest, its hash and the Ed25519 signature.

``manifest_sha256`` is the SHA-256 of the canonical JSON of the manifest; the signature is Ed25519
over that hex digest (ASCII), made with the custody signing key. Verification only accepts keys
passed in by the caller (the running signer + ``CUSTODY_TRUSTED_KEYS_PATH``), never keys read from
the database or from the manifest itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.signing import verify_signature

MANIFEST_SCHEMA = "dfirbench.report-manifest/1"


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8, no NaN/Infinity."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_sha256(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


@dataclass(frozen=True)
class Artifact:
    name: str
    format: str
    content_type: str
    data: bytes

    @property
    def sha256(self) -> str:
        return sha256_hex(self.data)

    def entry(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "format": self.format,
            "content_type": self.content_type,
            "sha256": self.sha256,
            "size": len(self.data),
        }


def build_manifest(
    *,
    report_id: str,
    family_id: str,
    version: int,
    case_id: str,
    case_number: str,
    kind: str,
    context_sha256: str,
    content_sha256: str,
    render_meta: Mapping[str, Any],
    artifacts: Sequence[Artifact],
    signed_at: str,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "report_id": report_id,
        "family_id": family_id,
        "version": version,
        "case_id": case_id,
        "case_number": case_number,
        "kind": kind,
        "context_sha256": context_sha256,
        "content_sha256": content_sha256,
        "render_meta": dict(render_meta),
        "artifacts": sorted((a.entry() for a in artifacts), key=lambda e: e["name"]),
        "signed_at": signed_at,
        "key_id": key_id,
    }


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return json_sha256(dict(manifest))


@dataclass
class SealCheck:
    ok: bool = True
    problems: list[dict[str, str]] = field(default_factory=list)

    def fail(self, code: str, message: str) -> None:
        self.ok = False
        self.problems.append({"code": code, "message": message})


def verify_manifest_signature(
    manifest: Mapping[str, Any],
    manifest_hash: str,
    signature: str,
    trusted_keys: Mapping[str, Ed25519PublicKey],
) -> SealCheck:
    """Recompute the manifest hash and check the signature with a trusted key only."""
    check = SealCheck()
    recomputed = manifest_sha256(manifest)
    if recomputed != manifest_hash:
        check.fail("manifest_hash_mismatch", "The manifest does not match its recorded hash.")
    key_id = str(manifest.get("key_id") or "")
    key = trusted_keys.get(key_id)
    if key is None:
        check.fail("untrusted_key", f"Signing key {key_id!r} is not trusted.")
    elif not verify_signature(key, signature, recomputed):
        check.fail("bad_signature", "The Ed25519 signature does not verify.")
    return check
