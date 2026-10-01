"""Operator CLI.

    python -m app.cli create-admin --email admin@example.org --name "Admin"
    python -m app.cli sync-playbooks                # load the packaged playbooks (guide 19.1)
    python -m app.cli rewrap-integration-secrets    # after rotating INTEGRATION_KEK (guide 20.3)
    python -m app.cli provision-app-login           # migrate job: login for DATABASE_APP_ROLE
    python -m app.cli integrity-check [--manifest F] [--trusted-keys F]   # read-only re-verify
    python -m app.cli backup-manifest [--out F]     # signed state manifest for a backup

The password is read from the environment variable named by ``--password-env`` (default
``DFIR_ADMIN_PASSWORD``) or prompted for; it is never accepted as a command-line argument.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import Any

from app.config import get_settings
from app.core.exceptions import AppError
from app.db.session import get_sessionmaker
from app.services.iam import IAMService


def create_admin(email: str, name: str, password: str) -> str:
    with get_sessionmaker()() as session:
        user = IAMService(session, get_settings()).bootstrap_admin(email, name, password)
        return str(user.id)


def sync_playbooks() -> dict[str, int]:
    from app.services.playbooks import PlaybookService

    with get_sessionmaker()() as session:
        return PlaybookService(session, get_settings()).sync_builtin()


def rewrap_integration_secrets() -> dict[str, int]:
    """Wrap every integration data key under the current KEK (old KEKs come from
    INTEGRATION_KEK_PREVIOUS_PATH). Secrets themselves are not re-encrypted or printed."""
    from app.services.integrations import IntegrationService

    with get_sessionmaker()() as session:
        return IntegrationService(session, get_settings()).rewrap_all()


def provision_app_login() -> dict[str, object]:
    """Give DATABASE_APP_ROLE its login (password from DATABASE_URL) via DATABASE_MIGRATE_URL."""
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.pool import NullPool

    from app.db.provision import provision_app_login as provision

    settings = get_settings()
    if settings.database_migrate_url is None:
        raise ValueError("DATABASE_MIGRATE_URL is not set (the owner login provisions the role)")
    role = settings.database_app_role
    app_url = make_url(settings.database_url)
    if not role or app_url.username != role:
        raise ValueError("DATABASE_URL must log in as DATABASE_APP_ROLE")
    engine = create_engine(
        settings.migrate_database_url, poolclass=NullPool, connect_args={"connect_timeout": 10}
    )
    try:
        return provision(engine, role, app_url.password or "")
    finally:
        engine.dispose()


def _trusted_keys(extra_file: str | None, use_signer: bool) -> dict[str, Any]:
    """Trust anchors for verification: trust files and, if present, the running signer."""
    from pathlib import Path

    from app.core.signing import (
        SigningKeyError,
        load_signer,
        load_trusted_keys,
        load_trusted_keys_file,
        trusted_key_set,
    )

    settings = get_settings()
    keys = dict(load_trusted_keys(settings))
    if extra_file:
        keys.update(load_trusted_keys_file(Path(extra_file)))
    signer = None
    if use_signer:
        try:
            signer = load_signer(settings)
        except SigningKeyError:
            signer = None
    return trusted_key_set(signer, keys)


def integrity_check(
    manifest_path: str | None, trusted_file: str | None, *, use_signer: bool, hash_objects: bool
) -> dict[str, Any]:
    """Read-only check of every custody chain and original (and a signed manifest, if given)."""
    import json
    from pathlib import Path

    from app.deps import get_vault
    from app.services.integrity import IntegrityChecker

    manifest = None
    if manifest_path:
        manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    keys = _trusted_keys(trusted_file, use_signer)
    with get_sessionmaker()() as session:
        report = IntegrityChecker(session, get_vault(), keys, hash_objects=hash_objects).check(
            manifest
        )
    return report.as_dict()


def backup_manifest() -> dict[str, Any]:
    """The signed state manifest a backup records (needs the custody signing key)."""
    from app.core.signing import load_signer
    from app.services.integrity import build_manifest

    signer = load_signer(get_settings())
    with get_sessionmaker()() as session:
        return build_manifest(session, signer)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser(
        "integrity-check",
        help="read-only check of custody chains, originals and Object Lock (exit 1 on problems)",
    )
    check.add_argument("--manifest", help="signed state manifest of a backup to compare with")
    check.add_argument("--trusted-keys", help="JSON {key_id: public PEM}; added to the trust set")
    check.add_argument(
        "--no-signer", action="store_true", help="do not trust the configured signing key"
    )
    check.add_argument("--no-hash", action="store_true", help="skip re-hashing the originals")
    manifest = sub.add_parser(
        "backup-manifest", help="print the signed state manifest (custody key required)"
    )
    manifest.add_argument("--out", help="write to this file instead of stdout")
    sub.add_parser(
        "provision-app-login",
        help="give the least-privilege role its login (migrate job; DATABASE_MIGRATE_URL)",
    )
    admin = sub.add_parser("create-admin", help="create the first admin account (idempotent)")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--password-env", default="DFIR_ADMIN_PASSWORD")
    sub.add_parser("sync-playbooks", help="load the packaged playbooks into the database")
    sub.add_parser(
        "rewrap-integration-secrets", help="re-wrap integration data keys under the current KEK"
    )
    args = parser.parse_args(argv)

    if args.command in ("integrity-check", "backup-manifest"):
        from app.core.logging import setup_logging

        # stdout carries the JSON document only; logs go to stderr.
        setup_logging(get_settings().log_level, get_settings().log_json, stream=sys.stderr)

    if args.command == "integrity-check":
        import json

        try:
            result = integrity_check(
                args.manifest,
                args.trusted_keys,
                use_signer=not args.no_signer,
                hash_objects=not args.no_hash,
            )
        except Exception as exc:  # noqa: BLE001 - operator tool: report the type, not a traceback
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)  # noqa: T201
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))  # noqa: T201
        return 0 if result["ok"] else 1

    if args.command == "backup-manifest":
        import json
        from pathlib import Path

        try:
            document = backup_manifest()
        except Exception as exc:  # noqa: BLE001 - operator tool: report the type, not a traceback
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)  # noqa: T201
            return 1
        text = json.dumps(document, indent=1, sort_keys=True) + "\n"
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0

    if args.command == "provision-app-login":
        try:
            done = provision_app_login()
        except Exception as exc:  # noqa: BLE001 - operator tool: the type and message, no secret
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)  # noqa: T201
            return 1
        print(" ".join(f"{k}={v}" for k, v in sorted(done.items())))  # noqa: T201
        return 0

    if args.command in ("sync-playbooks", "rewrap-integration-secrets"):
        try:
            counts = (
                sync_playbooks()
                if args.command == "sync-playbooks"
                else rewrap_integration_secrets()
            )
        except Exception as exc:  # noqa: BLE001 - operator tool: report the type, not a traceback
            print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)  # noqa: T201
            return 1
        print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())))  # noqa: T201
        return 0

    password = os.environ.get(args.password_env) or ""
    if not password:
        if not sys.stdin.isatty():
            print(f"set {args.password_env} or run interactively", file=sys.stderr)  # noqa: T201
            return 2
        password = getpass.getpass("Admin password: ")
    try:
        user_id = create_admin(args.email, args.name, password)
    except AppError as exc:
        print(f"error: {exc.code}: {exc.message} {exc.details or ''}", file=sys.stderr)  # noqa: T201
        return 1
    print(user_id)  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
