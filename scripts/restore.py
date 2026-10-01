#!/usr/bin/env python3
"""Restore a backup into a compose project and verify it (Phase 10; docs/backup-restore.md).

    BACKUP_PASSPHRASE=... backend/.venv/Scripts/python scripts/restore.py \\
        --from backups/2026-10-01 --project dfirbench-restore --trusted-keys trusted.json

1. ``index.json``: every encrypted file must have the recorded size and SHA-256 (a swapped or
   damaged file is refused before anything is decrypted);
2. every file is decrypted and authenticated completely into a private temporary directory
   (a wrong passphrase, truncation or any modification stops the restore);
3. the target project's volumes must not exist (``--force`` replaces them; required for the live
   project). Postgres, MinIO and the key volume are created by ``docker compose create``;
4. the MinIO and key volumes are filled from their tar archives (``--network none``), postgres
   and MinIO start on their own ports, the least-privilege role is created, ``pg_restore`` runs;
5. ``python -m app.cli integrity-check --manifest manifest.json --trusted-keys FILE --no-signer``
   runs against the restored project (read-only): the manifest signature (with keys from outside
   the backup), schema revision, row counts, every custody chain and chain head, and every
   original's bytes, version and Object Lock retention;
6. unless ``--keep``, the restore project is removed again (``down -v``): a restore drill.

The trusted keys file ({key_id: public key PEM}) must come from outside the backup (for example
``python -m app.core.signing trust`` on the live key, or the operator's trust store).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.ops.backupcrypt import check_passphrase, decrypt_stream  # noqa: E402

FILES = ("db.dump.enc", "objects.tar.enc", "keys.tar.enc")
DOCUMENTS = ("manifest.json", "integrity-at-backup.json")
# Problems that mean the restored state is not the backed-up state.
MANIFEST_CODES = frozenset(
    {
        "manifest_invalid",
        "revision_mismatch",
        "count_mismatch",
        "evidence_missing",
        "evidence_unexpected",
        "evidence_changed",
        "chain_head_mismatch",
        "reports_changed",
    }
)
VOLUMES = ("pgdata", "miniodata", "custodykeys")
TAR_IMAGE = "dfirbench/api:dev"


def sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Project:
    def __init__(self, name: str, compose_file: Path, ports: dict[str, int], subnet: int) -> None:
        self.name = name
        self.base = ["docker", "compose", "-p", name, "-f", str(compose_file)]
        self.env = {
            **os.environ,
            "POSTGRES_PORT": str(ports["postgres"]),
            "MINIO_PORT": str(ports["minio"]),
            "MINIO_CONSOLE_PORT": str(ports["minio"] + 1),
            "REDIS_PORT": str(ports["postgres"] + 2),
            "API_PORT": str(ports["postgres"] + 3),
            "WEB_PORT": str(ports["postgres"] + 4),
            "WEB_SUBNET": f"172.30.{subnet}.0/24",
            "WEB_IP": f"172.30.{subnet}.10",
        }

    def compose(self, *args: str, check: bool = True, stdin: Any = None) -> str:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            [*self.base, *args], env=self.env, stdin=stdin, capture_output=True, check=False
        )
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()[-2000:]
            raise RuntimeError(f"docker compose {args[0]} failed: {err}")
        return proc.stdout.decode("utf-8", "replace")

    def volume_name(self, volume: str) -> str:
        return f"{self.name}_{volume}"

    def volume_exists(self, volume: str) -> bool:
        proc = subprocess.run(  # noqa: S603 - fixed argv
            ["docker", "volume", "inspect", self.volume_name(volume)],
            capture_output=True, check=False,
        )
        return proc.returncode == 0

    def wait_healthy(self, services: tuple[str, ...], timeout: float = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            states = []
            for svc in services:
                cid = self.compose("ps", "-q", svc).strip()
                state = subprocess.run(  # noqa: S603 - fixed argv
                    ["docker", "inspect", "-f", "{{.State.Health.Status}}", cid],
                    capture_output=True, text=True, check=False,
                ).stdout.strip() if cid else "missing"
                states.append(state)
            if all(s == "healthy" for s in states):
                return
            time.sleep(3)
        raise RuntimeError(f"restore services not healthy: {dict(zip(services, states, strict=True))}")


def verify_index(source: Path) -> dict[str, Any]:
    index = json.loads((source / "index.json").read_text(encoding="utf-8"))
    if index.get("format") != "dfirbench-backup" or index.get("version") != 1:
        raise RuntimeError("index.json is not a dfirbench backup index")
    for name in FILES:
        info = index["files"].get(name)
        path = source / name
        if not info or not path.is_file():
            raise RuntimeError(f"{name} is missing")
        if path.stat().st_size != info["bytes"] or sha256_file(path) != info["sha256"]:
            raise RuntimeError(f"{name} does not match index.json (size or SHA-256)")
    for name in DOCUMENTS:
        path = source / name
        if not path.is_file() or sha256_file(path) != index.get("documents", {}).get(name):
            raise RuntimeError(f"{name} is missing or does not match index.json")
    return index


def judge(result: dict[str, Any], baseline: dict[str, Any]) -> tuple[bool, str]:
    """Restored = backed up: the manifest matches and the integrity findings are the same."""
    codes = {p["code"] for p in result.get("problems", [])}
    if not result.get("manifest_checked") or codes & MANIFEST_CODES:
        return False, f"restored state differs from the backup manifest: {sorted(codes)}"
    found = {(p["code"], p.get("evidence_id")) for p in result["problems"]}
    expected = {(p["code"], p.get("evidence_id")) for p in baseline.get("problems", [])}
    if found != expected:
        return False, (
            f"integrity findings differ from the backup: unexpected {sorted(found - expected)}, "
            f"missing {sorted(expected - found)}"
        )
    return True, f"{len(found)} findings recorded at backup time reproduced exactly"


def decrypt_all(source: Path, work: Path, index: dict[str, Any], passphrase: str) -> None:
    for name in FILES:
        target = work / name.removesuffix(".enc")
        with (source / name).open("rb") as src, target.open("xb") as dst:
            plain_sha = decrypt_stream(src, dst, passphrase)
        if plain_sha != index["files"][name]["plain_sha256"]:
            raise RuntimeError(f"{name}: decrypted content differs from index.json")


def untar_into(volume: str, archive: Path) -> None:
    cmd = [
        "docker", "run", "--rm", "-i", "--network", "none", "--user", "0:0",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
        "--cap-add", "FOWNER", "--security-opt", "no-new-privileges:true",
        "-v", f"{volume}:/data", "--entrypoint", "tar", TAR_IMAGE,
        "--numeric-owner", "--same-owner", "-C", "/data", "-xpf", "-",
    ]
    with archive.open("rb") as fh:
        proc = subprocess.run(cmd, stdin=fh, capture_output=True, check=False)  # noqa: S603
    if proc.returncode != 0:
        raise RuntimeError(f"untar into {volume} failed: {proc.stderr.decode()[-1000:]}")


STARTED = time.monotonic()


def stage(message: str) -> None:
    print(f"[{time.monotonic() - STARTED:7.1f}s] {message}", file=sys.stderr, flush=True)


def restore(args: argparse.Namespace, passphrase: str) -> dict[str, Any]:
    source: Path = args.source
    index = verify_index(source)
    project = Project(
        args.project, args.compose_file, {"postgres": args.pg_port, "minio": args.minio_port},
        args.subnet,
    )
    existing = [v for v in VOLUMES if project.volume_exists(v)]
    if existing and not args.force:
        raise RuntimeError(f"project {args.project!r} already has volumes {existing}; use --force")
    if args.project == "dfirbench" and not args.force:
        raise RuntimeError("restoring over the live project needs --force")
    if args.project == "dfirbench":
        args.keep = True  # never tear the live project down after restoring it
    work = Path(tempfile.mkdtemp(prefix="dfir-restore-", dir=args.tmp_dir))
    try:
        os.chmod(work, 0o700)
        stage("decrypting and authenticating every file")
        decrypt_all(source, work, index, passphrase)
        if existing:
            project.compose("down", "-v", check=False)
        stage("creating the project and filling the MinIO and key volumes")
        project.compose("create", "postgres", "minio")
        untar_into(project.volume_name("miniodata"), work / "objects.tar")
        project.compose("create", "keygen")  # creates the custodykeys volume
        untar_into(project.volume_name("custodykeys"), work / "keys.tar")
        project.compose("up", "-d", "postgres", "minio")
        project.wait_healthy(("postgres", "minio"))
        stage("postgres and MinIO are healthy; restoring the database")
        project.compose(
            "exec", "-T", "postgres", "psql", "-U", "dfir", "-d", "dfirbench", "-v",
            "ON_ERROR_STOP=1", "-c",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dfirbench_app') "
            "THEN CREATE ROLE dfirbench_app NOLOGIN; END IF; END $$; "
            "GRANT dfirbench_app TO CURRENT_USER;",
        )
        with (work / "db.dump").open("rb") as dump:
            project.compose(
                "exec", "-T", "postgres", "pg_restore", "-U", "dfir", "-d", "dfirbench",
                "--exit-on-error", "--no-password", stdin=dump,
            )
        stage("running the read-only integrity check against the restored project")
        check = run_integrity_check(args, source)
        stage("integrity check finished")
        return {"project": args.project, "index": index, "integrity": check}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if not args.keep:
            project.compose("down", "-v", check=False)


def run_integrity_check(args: argparse.Namespace, source: Path) -> dict[str, Any]:
    pg_password = os.environ.get("POSTGRES_PASSWORD", "dfir_dev_password")
    env = {
        k: v for k, v in os.environ.items()
        if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "USERPROFILE")
    }
    env.update(
        {
            "APP_ENV": "dev",
            "DATABASE_URL": f"postgresql+psycopg://dfir:{pg_password}@127.0.0.1:{args.pg_port}/dfirbench",
            "DATABASE_APP_ROLE": "dfirbench_app",
            "S3_ENDPOINT": f"127.0.0.1:{args.minio_port}",
            "S3_ACCESS_KEY": os.environ.get("MINIO_ROOT_USER", "dfir"),
            "S3_SECRET_KEY": os.environ.get("MINIO_ROOT_PASSWORD", "minio_dev_password"),
            "S3_SECURE": "false",
            "LOG_LEVEL": "WARNING",
        }
    )
    python = sys.executable
    proc = subprocess.run(  # noqa: S603 - fixed argv
        [
            python, "-m", "app.cli", "integrity-check", "--manifest",
            str((source / "manifest.json").resolve()), "--trusted-keys",
            str(args.trusted_keys.resolve()), "--no-signer",
        ],
        cwd=str(ROOT / "backend"), env=env, capture_output=True, text=True, check=False,
    )
    try:
        result: dict[str, Any] = json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"integrity-check failed: {proc.stderr.strip()[-2000:]}") from exc
    result["exit_code"] = proc.returncode
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--from", dest="source", required=True, type=Path)
    parser.add_argument("--project", default="dfirbench-restore")
    parser.add_argument("--trusted-keys", required=True, type=Path)
    parser.add_argument("--compose-file", type=Path, default=ROOT / "infra" / "compose.yaml")
    parser.add_argument("--pg-port", type=int, default=55432)
    parser.add_argument("--minio-port", type=int, default=59000)
    parser.add_argument("--subnet", type=int, default=241, help="172.30.<n>.0/24 for the project")
    parser.add_argument("--tmp-dir", type=Path, default=None)
    parser.add_argument("--keep", action="store_true", help="leave the restored project running")
    parser.add_argument("--force", action="store_true", help="replace the project's volumes")
    args = parser.parse_args()
    try:
        passphrase = check_passphrase(os.environ.get("BACKUP_PASSPHRASE"))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        outcome = restore(args, passphrase)
    except Exception as exc:  # noqa: BLE001 - operator tool: one clear line
        print(f"restore failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    result = outcome["integrity"]
    baseline = json.loads((args.source / "integrity-at-backup.json").read_text(encoding="utf-8"))
    print(json.dumps(result, indent=2))
    ok, reason = judge(result, baseline)
    summary = {k: result.get(k) for k in ("evidence_checked", "objects_hashed", "bytes_hashed")}
    if ok:
        print(f"RESTORE VERIFIED: project {outcome['project']}: {reason}; {summary}",
              file=sys.stderr)
        return 0
    print(f"RESTORE NOT VERIFIED: {reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
