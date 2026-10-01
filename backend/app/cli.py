"""Operator CLI.

    python -m app.cli create-admin --email admin@example.org --name "Admin"
    python -m app.cli sync-playbooks                # load the packaged playbooks (guide 19.1)
    python -m app.cli rewrap-integration-secrets    # after rotating INTEGRATION_KEK (guide 20.3)

The password is read from the environment variable named by ``--password-env`` (default
``DFIR_ADMIN_PASSWORD``) or prompted for; it is never accepted as a command-line argument.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create the first admin account (idempotent)")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--password-env", default="DFIR_ADMIN_PASSWORD")
    sub.add_parser("sync-playbooks", help="load the packaged playbooks into the database")
    sub.add_parser(
        "rewrap-integration-secrets", help="re-wrap integration data keys under the current KEK"
    )
    args = parser.parse_args(argv)

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
