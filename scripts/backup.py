#!/usr/bin/env python3
"""Encrypted, signed backup of the compose stack (Phase 10, guide 7.6, 21.6; docs/backup-restore.md).

    BACKUP_PASSPHRASE=... backend/.venv/Scripts/python scripts/backup.py --out backups/2026-10-01

Runs on the Docker host with the backend venv (for ``app.ops.backupcrypt``). Steps:

1. stop ``web``, ``api`` and ``worker`` (writers) for a short maintenance window;
2. ``manifest.json``: the signed state manifest from a one-off api container
   (``python -m app.cli backup-manifest``: Alembic revision, row counts, every evidence hash and
   vault version, every custody chain head, signed reports; Ed25519 with the custody key);
3. ``db.dump.enc``: ``pg_dump -Fc`` in the postgres container (no role passwords are dumped);
4. ``objects.tar.enc``: the MinIO volume, copied with MinIO stopped and mounted read-only, so
   object versions, Object Lock retention and metadata are restored exactly;
5. ``keys.tar.enc``: the custody key volume (the private signing key);
6. ``integrity-at-backup.json``: ``integrity-check`` on the live stack at that moment (findings a
   restore must reproduce exactly, e.g. evidence a tamper demo damaged on purpose);
7. ``index.json``: names, sizes and SHA-256 of the encrypted files;
8. start what was running before (also after an error).

Encryption: AES-256-GCM STREAM with a scrypt key from BACKUP_PASSPHRASE (never printed). Original
evidence is only ever read (read-only volume mount); nothing in the live stack is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ops.backupcrypt import check_passphrase, encrypt_stream  # noqa: E402

WRITERS = ("web", "api", "worker")
TAR_IMAGE = "dfirbench/api:dev"


class Compose:
    def __init__(self, project: str, compose_file: Path, env: dict[str, str] | None = None) -> None:
        self.project = project
        self.base = ["docker", "compose", "-p", project, "-f", str(compose_file)]
        self.env = {**os.environ, **(env or {})}

    def run(self, *args: str, check: bool = True, capture: bool = True) -> str:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [*self.base, *args], env=self.env, capture_output=capture, text=True, check=False
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"docker compose {args[0]} failed: {proc.stderr.strip()[-2000:]}")
        return proc.stdout if capture else ""

    def running(self) -> set[str]:
        out = self.run("ps", "--status", "running", "--services")
        return {line.strip() for line in out.splitlines() if line.strip()}

    def volume(self, name: str) -> str:
        out = subprocess.run(  # noqa: S603 - fixed argv
            [
                "docker", "volume", "ls", "-q",
                "--filter", f"label=com.docker.compose.project={self.project}",
                "--filter", f"label=com.docker.compose.volume={name}",
            ],
            capture_output=True, text=True, check=True,
        ).stdout.split()
        if len(out) != 1:
            raise RuntimeError(f"volume {name!r} of project {self.project!r} not found")
        return out[0]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encrypt_from(cmd: list[str], target: Path, passphrase: str, env: dict[str, str]) -> str:
    """Run ``cmd`` and encrypt its stdout into ``target`` (never on disk in plain text)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)  # noqa: S603
    assert proc.stdout is not None and proc.stderr is not None
    with target.open("xb") as out:
        plain_sha = encrypt_stream(proc.stdout, out, passphrase)
    err = proc.stderr.read().decode("utf-8", "replace")
    if proc.wait() != 0:
        raise RuntimeError(f"{cmd[:3]} failed: {err.strip()[-2000:]}")
    return plain_sha


def tar_volume_cmd(volume: str) -> list[str]:
    return [
        "docker", "run", "--rm", "--network", "none", "--user", "0:0",
        "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH",
        "--security-opt", "no-new-privileges:true",
        "-v", f"{volume}:/data:ro", "--entrypoint", "tar", TAR_IMAGE,
        "--numeric-owner", "-C", "/data", "-cpf", "-", ".",
    ]


def backup(out: Path, compose: Compose, passphrase: str) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=False)
    before = compose.running()
    stopped = sorted(before & set(WRITERS))
    files: dict[str, dict[str, Any]] = {}
    try:
        if stopped:
            compose.run("stop", *stopped)
        manifest = compose.run(
            "run", "--rm", "--no-deps", "-T", "api", "python", "-m", "app.cli", "backup-manifest"
        )
        document = json.loads(manifest)
        (out / "manifest.json").write_text(manifest, encoding="utf-8")
        # Integrity at backup time (read-only): a restore must reproduce exactly these findings
        # (a live store can hold known tamper evidence, e.g. from the Phase 1 demo).
        baseline = compose.run(
            "run", "--rm", "--no-deps", "-T", "api", "python", "-m", "app.cli", "integrity-check",
            check=False,
        )
        (out / "integrity-at-backup.json").write_text(
            json.dumps(json.loads(baseline), indent=2) + "\n", encoding="utf-8"
        )
        pg_dump = [*compose.base, "exec", "-T", "postgres", "pg_dump", "-U", "dfir", "-d",
                   "dfirbench", "-Fc", "--no-password"]
        files["db.dump.enc"] = {"plain_sha256": encrypt_from(pg_dump, out / "db.dump.enc",
                                                             passphrase, compose.env)}
        minio_volume = compose.volume("miniodata")
        if "minio" in before:
            compose.run("stop", "minio")
        try:
            files["objects.tar.enc"] = {
                "plain_sha256": encrypt_from(
                    tar_volume_cmd(minio_volume), out / "objects.tar.enc", passphrase, compose.env
                )
            }
        finally:
            if "minio" in before:
                compose.run("start", "minio")
        files["keys.tar.enc"] = {
            "plain_sha256": encrypt_from(
                tar_volume_cmd(compose.volume("custodykeys")), out / "keys.tar.enc", passphrase,
                compose.env,
            )
        }
    finally:
        if stopped:
            compose.run("start", *stopped, check=False)
    for name, info in files.items():
        info["bytes"] = (out / name).stat().st_size
        info["sha256"] = sha256_file(out / name)
    index = {
        "format": "dfirbench-backup",
        "version": 1,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "project": compose.project,
        "alembic_revision": document["manifest"]["alembic_revision"],
        "manifest_sha256": document["sha256"],
        "signing_key_id": document["signature"]["key_id"],
        "files": files,
        "documents": {
            name: sha256_file(out / name) for name in ("manifest.json", "integrity-at-backup.json")
        },
    }
    (out / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, type=Path, help="new directory for the backup")
    parser.add_argument("--project", default="dfirbench")
    parser.add_argument("--compose-file", type=Path, default=ROOT / "infra" / "compose.yaml")
    args = parser.parse_args()
    try:
        passphrase = check_passphrase(os.environ.get("BACKUP_PASSPHRASE"))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        index = backup(args.out, Compose(args.project, args.compose_file), passphrase)
    except Exception as exc:  # noqa: BLE001 - operator tool: one clear line
        print(f"backup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: index[k] for k in ("created_at", "alembic_revision", "files")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
