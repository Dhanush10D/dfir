"""Login for the least-privilege database role (Phase 10, guide 20.2).

Migration 0002 created ``dfirbench_app`` as NOLOGIN and the app connected as the owner with
``SET ROLE``. A compromised API or worker could then ``RESET ROLE`` and act as the owner (in
compose, a superuser), which defeats every grant and trigger. ``provision_app_login`` makes the
role itself loginable so the app never holds the owner's credentials:

* the role must exist and must not be a superuser, have CREATEROLE, CREATEDB, REPLICATION or
  BYPASSRLS, or be a member of any other role (so there is nothing to ``SET ROLE`` to);
* the password is sent as a SCRAM-SHA-256 verifier computed here (RFC 5802/7677, the format
  PostgreSQL stores), so the plaintext never reaches the server, its logs or ``pg_stat_activity``.

It runs in the migrate job with the owner login (``DATABASE_MIGRATE_URL``); the password is the
one in ``DATABASE_URL``. It is idempotent and safe to re-run (a new salt each time).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from typing import Any

from sqlalchemy import Engine, text

SCRAM_ITERATIONS = 4096
MIN_PASSWORD_LENGTH = 16
_ROLE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_VERIFIER = re.compile(r"^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")
_PRIVILEGES = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")


class ProvisionError(Exception):
    """The role cannot be given a login safely."""


def scram_sha256_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS
) -> str:
    """PostgreSQL's stored form ``SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>``.

    Only printable ASCII passwords are accepted: PostgreSQL applies SASLprep, which leaves them
    unchanged, so the verifier computed here always matches what the server would compute.
    """
    if not password or not (password.isascii() and password.isprintable()):
        raise ValueError("the database password must be printable ASCII")
    salt = salt if salt is not None else os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    def b64(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def check_password(password: str | None) -> str:
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"the database password must be at least {MIN_PASSWORD_LENGTH} characters")
    if not (password.isascii() and password.isprintable()):
        raise ValueError("the database password must be printable ASCII")
    return password


def role_state(engine: Engine, role: str) -> dict[str, Any]:
    """Attributes and memberships of ``role`` (for checks and the verify script)."""
    if not _ROLE.fullmatch(role):
        raise ProvisionError(f"invalid role name {role!r}")
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
                "rolcanlogin FROM pg_roles WHERE rolname = :r"
            ),
            {"r": role},
        ).one_or_none()
        if row is None:
            raise ProvisionError(f"role {role!r} does not exist (run the migrations first)")
        member_of: list[str] = list(
            conn.execute(
                text(
                    "SELECT g.rolname FROM pg_auth_members m "
                    "JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles r ON r.oid = m.member "
                    "WHERE r.rolname = :r ORDER BY g.rolname"
                ),
                {"r": role},
            ).scalars()
        )
        state: dict[str, Any] = dict(row._mapping)
        state["member_of"] = list(member_of)
    return state


def provision_app_login(engine: Engine, role: str, password: str) -> dict[str, Any]:
    """Give ``role`` LOGIN with ``password`` (as a SCRAM verifier) after checking it is safe."""
    check_password(password)
    state = role_state(engine, role)
    granted = [name for name in _PRIVILEGES if state[name]]
    if granted:
        raise ProvisionError(f"role {role!r} is too privileged for the app: {granted}")
    if state["member_of"]:
        raise ProvisionError(f"role {role!r} must not be a member of {state['member_of']}")
    verifier = scram_sha256_verifier(password)
    if not _VERIFIER.fullmatch(verifier):  # cannot happen; keeps the literal below quote-free
        raise ProvisionError("unexpected verifier format")
    # Utility statements take no bind parameters: the role name matched _ROLE and the verifier
    # matched _VERIFIER, so neither can close the quotes. exec_driver_sql: no ':name' parsing.
    statement = f"ALTER ROLE \"{role}\" WITH LOGIN PASSWORD '{verifier}'"
    with engine.begin() as conn:
        conn.exec_driver_sql(statement)
    after = role_state(engine, role)
    return {"role": role, "login": bool(after["rolcanlogin"]), "member_of": after["member_of"]}
