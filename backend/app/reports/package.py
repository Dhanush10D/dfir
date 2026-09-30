"""Evidence export package (guide 8.4): ``manifest.json`` + ``custody.json`` + ``manifest.sig``.

The ZIP is deterministic (fixed member order and timestamps). ``manifest.sig`` holds an Ed25519
signature over ``sha256(manifest.json) + "\\n" + sha256(custody.json)`` (hex, ASCII). It also
carries the key id and public key PEM for convenience, but verification only trusts keys the
recipient supplies (their copy of the custody key / trusted keys file).

Original evidence bytes are not included (they can be many GB); the manifest carries their hashes
and ``GET /evidence/{id}/download`` returns them with its own custody entry.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.signing import CustodySigner, verify_signature
from app.reports.exports import pretty_json
from app.reports.seal import sha256_hex
from app.services.custody import ChainEntry, verify_chain

PACKAGE_SCHEMA = "dfirbench.evidence-package/1"
MEMBERS = ("manifest.json", "custody.json", "manifest.sig")
MAX_MEMBER_BYTES = 64 * 1024 * 1024
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


class PackageError(ValueError):
    """The package is malformed (not a verification failure of a well-formed package)."""


def signed_message(manifest_sha256: str, custody_sha256: str) -> str:
    return f"{manifest_sha256}\n{custody_sha256}"


def _zip(members: Mapping[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in MEMBERS:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, members[name])
    return buffer.getvalue()


def build_evidence_package(
    manifest: Mapping[str, Any], custody: Mapping[str, Any], signer: CustodySigner
) -> bytes:
    manifest_bytes = pretty_json({"schema": PACKAGE_SCHEMA, **dict(manifest)})
    custody_bytes = pretty_json(dict(custody))
    m_sha, c_sha = sha256_hex(manifest_bytes), sha256_hex(custody_bytes)
    sig = {
        "schema": PACKAGE_SCHEMA,
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "manifest_sha256": m_sha,
        "custody_sha256": c_sha,
        "message": "sha256(manifest.json) + LF + sha256(custody.json), hex, ASCII",
        "signature": signer.sign(signed_message(m_sha, c_sha)),
        "public_key_pem": signer.public_key_pem(),
    }
    return _zip(
        {
            "manifest.json": manifest_bytes,
            "custody.json": custody_bytes,
            "manifest.sig": pretty_json(sig),
        }
    )


def _read_members(data: bytes) -> dict[str, bytes]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PackageError("not a ZIP file") from exc
    with zf:
        infos = zf.infolist()
        names = [i.orig_filename for i in infos]
        if sorted(names) != sorted(MEMBERS):
            raise PackageError(f"unexpected package members: {sorted(names)[:10]}")
        out: dict[str, bytes] = {}
        for info in infos:
            if info.file_size > MAX_MEMBER_BYTES or info.is_dir():
                raise PackageError(f"member {info.orig_filename} is too large or a directory")
            with zf.open(info) as fh:
                blob = fh.read(MAX_MEMBER_BYTES + 1)
            if len(blob) > MAX_MEMBER_BYTES:
                raise PackageError(f"member {info.orig_filename} is too large")
            out[info.orig_filename] = blob
        return out


def _chain_entries(custody: Mapping[str, Any]) -> list[ChainEntry]:
    entries = []
    for e in custody.get("entries") or []:
        entries.append(
            ChainEntry(
                evidence_id=str(e["evidence_id"]),
                seq=int(e["seq"]),
                ts=datetime.fromisoformat(str(e["ts"]).replace("Z", "+00:00")),
                actor_id=e.get("actor_id"),
                actor_label=str(e["actor_label"]),
                action=str(e["action"]),
                detail=dict(e.get("detail") or {}),
                prev_hash=str(e["prev_hash"]),
                entry_hash=str(e["entry_hash"]),
                signature=str(e["signature"]),
                key_id=str(e["key_id"]),
            )
        )
    return entries


def verify_package(data: bytes, trusted_keys: Mapping[str, Ed25519PublicKey]) -> dict[str, Any]:
    """Offline check of a package: member hashes, signature (trusted keys only), custody chain."""
    problems: list[dict[str, str]] = []
    try:
        members = _read_members(data)
        sig = json.loads(members["manifest.sig"])
        manifest = json.loads(members["manifest.json"])
        custody = json.loads(members["custody.json"])
    except (PackageError, ValueError) as exc:
        return {"ok": False, "problems": [{"code": "malformed", "message": str(exc)}]}
    m_sha = sha256_hex(members["manifest.json"])
    c_sha = sha256_hex(members["custody.json"])
    if sig.get("manifest_sha256") != m_sha:
        problems.append({"code": "manifest_hash_mismatch", "message": "manifest.json changed"})
    if sig.get("custody_sha256") != c_sha:
        problems.append({"code": "custody_hash_mismatch", "message": "custody.json changed"})
    key_id = str(sig.get("key_id") or "")
    key = trusted_keys.get(key_id)
    if key is None:
        problems.append({"code": "untrusted_key", "message": f"key {key_id!r} is not trusted"})
    elif not verify_signature(key, str(sig.get("signature") or ""), signed_message(m_sha, c_sha)):
        problems.append({"code": "bad_signature", "message": "signature does not verify"})
    chain_ok: bool | None = None
    try:
        report = verify_chain(
            _chain_entries(custody),
            trusted_keys,
            evidence_id=str(manifest.get("evidence", {}).get("id") or "") or None,
        )
        chain_ok = report.ok
        if not report.ok:
            problems.append(
                {
                    "code": "custody_chain_invalid",
                    "message": f"custody chain problems at seq {report.broken_seqs[:10]}",
                }
            )
    except (KeyError, TypeError, ValueError) as exc:
        chain_ok = False
        problems.append({"code": "custody_malformed", "message": type(exc).__name__})
    return {
        "ok": not problems,
        "key_id": key_id,
        "manifest_sha256": m_sha,
        "custody_sha256": c_sha,
        "custody_chain_ok": chain_ok,
        "evidence_sha256": (manifest.get("evidence") or {}).get("sha256"),
        "problems": problems,
    }
