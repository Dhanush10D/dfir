"""Operator CLI.

    python -m app.cli create-admin --email admin@example.org --name "Admin"

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create the first admin account (idempotent)")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--password-env", default="DFIR_ADMIN_PASSWORD")
    args = parser.parse_args(argv)

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
