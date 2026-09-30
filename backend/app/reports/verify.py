"""Offline verification of dfirbench deliverables (no database, no network).

Evidence export package::

    python -m app.reports.verify package EV-001_package.zip --keys trusted.json

Signed report (the ``seal.json`` download plus the artifact files in one directory)::

    python -m app.reports.verify report seal.json --dir ./artifacts --keys trusted.json

``--keys`` is a trusted keys file (``{"key_id": "public key PEM"}``, the format of
``CUSTODY_TRUSTED_KEYS_PATH``); ``--public-key`` adds a single PEM file. Keys embedded in the
package or seal are never trusted. Exit code 0 = verified, 1 = verification failed, 2 = usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.signing import (
    SigningKeyError,
    key_fingerprint_id,
    load_public_key_pem,
    load_trusted_keys_file,
)
from app.reports.package import verify_package
from app.reports.seal import sha256_hex, verify_manifest_signature

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


def verify_report_seal(
    seal: Mapping[str, Any], artifact_dir: Path, trusted_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    manifest = seal.get("manifest") or {}
    check = verify_manifest_signature(
        manifest,
        str(seal.get("manifest_sha256") or ""),
        str(seal.get("signature") or ""),
        trusted_keys,
    )
    problems = list(check.problems)
    artifacts = []
    base = artifact_dir.resolve()
    for entry in manifest.get("artifacts") or []:
        name = str(entry.get("name") or "")
        path = (base / name).resolve()
        if path.parent != base or "/" in name or "\\" in name:
            problems.append({"code": "bad_artifact_name", "message": name[:100]})
            continue
        if not path.is_file():
            artifacts.append({"name": name, "ok": None, "reason": "not present"})
            continue
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            problems.append({"code": "artifact_too_large", "message": name})
            continue
        actual = sha256_hex(path.read_bytes())
        ok = actual == entry.get("sha256")
        artifacts.append({"name": name, "ok": ok, "sha256": actual})
        if not ok:
            problems.append({"code": "artifact_hash_mismatch", "message": name})
    return {
        "ok": not problems,
        "report_id": manifest.get("report_id"),
        "version": manifest.get("version"),
        "key_id": manifest.get("key_id"),
        "artifacts": artifacts,
        "problems": problems,
    }


def _keys(args: argparse.Namespace) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    if args.keys:
        keys.update(load_trusted_keys_file(Path(args.keys)))
    for pem_path in args.public_key or []:
        key = load_public_key_pem(Path(pem_path).read_text(encoding="ascii"))
        keys[args.key_id or key_fingerprint_id(key)] = key
    return keys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.reports.verify")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("package", "report"):
        p = sub.add_parser(name)
        p.add_argument("path", type=Path)
        p.add_argument("--keys", help="trusted keys JSON file")
        p.add_argument("--public-key", action="append", help="trusted public key PEM file")
        p.add_argument("--key-id", help="key id for --public-key (default: fingerprint id)")
        if name == "report":
            p.add_argument("--dir", type=Path, help="directory with the artifact files")
    args = parser.parse_args(argv)
    try:
        keys = _keys(args)
    except (OSError, SigningKeyError) as exc:
        print(f"cannot load trusted keys: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    if not keys:
        print("no trusted keys given (--keys or --public-key)", file=sys.stderr)  # noqa: T201
        return 2
    try:
        if args.command == "package":
            result = verify_package(args.path.read_bytes(), keys)
        else:
            seal = json.loads(args.path.read_text(encoding="utf-8"))
            result = verify_report_seal(seal, args.dir or args.path.parent, keys)
    except (OSError, ValueError) as exc:
        print(f"cannot read input: {type(exc).__name__}: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    print(json.dumps(result, indent=2))  # noqa: T201
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
