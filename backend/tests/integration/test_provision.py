"""Phase 10: the app logs in as the least-privilege role and cannot become the owner.

Uses a throwaway role (cluster-wide objects must not disturb the shared ``dfirbench_app`` that a
running dev stack logs in with).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import psycopg
import pytest
from sqlalchemy import Engine
from sqlalchemy.engine import make_url

from app.db.provision import ProvisionError, provision_app_login, role_state

pytestmark = pytest.mark.integration


@pytest.fixture
def role(admin_engine: Engine, migrated_db_url: str) -> Iterator[str]:
    name = f"dfir_t_{uuid.uuid4().hex[:10]}"
    database = make_url(migrated_db_url).database
    with admin_engine.connect() as conn:
        conn.exec_driver_sql(f'CREATE ROLE "{name}" NOLOGIN')
        conn.exec_driver_sql(f'GRANT CONNECT ON DATABASE "{database}" TO "{name}"')
    yield name
    with admin_engine.connect() as conn:
        conn.exec_driver_sql(f'REVOKE ALL ON DATABASE "{database}" FROM "{name}"')
        conn.exec_driver_sql(f'DROP ROLE IF EXISTS "{name}"')


def _connect(migrated_db_url: str, role: str, password: str) -> psycopg.Connection:
    url = make_url(migrated_db_url)
    return psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        dbname=url.database,
        user=role,
        password=password,
        connect_timeout=5,
    )


def test_provisioned_login_cannot_regain_owner_privileges(
    db_engine: Engine, migrated_db_url: str, role: str
) -> None:
    password = f"Prov-{uuid.uuid4().hex}-Pass"
    done = provision_app_login(db_engine, role, password)
    assert done == {"role": role, "login": True, "member_of": []}
    owner = make_url(migrated_db_url).username
    with _connect(migrated_db_url, role, password) as conn:
        assert conn.execute("SELECT current_user, session_user").fetchone() == (role, role)
        conn.execute("RESET ROLE")
        assert conn.execute("SELECT current_user").fetchone() == (role,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(f'SET ROLE "{owner}"')
        conn.rollback()
        super_flag = conn.execute(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        ).fetchone()
        assert super_flag == (False,)
    with pytest.raises(psycopg.OperationalError):
        _connect(migrated_db_url, role, "wrong-" + password)
    again = f"Prov-{uuid.uuid4().hex}-Next"
    provision_app_login(db_engine, role, again)  # idempotent: re-running rotates the password
    with _connect(migrated_db_url, role, again) as conn:
        assert conn.execute("SELECT 1").fetchone() == (1,)


def test_privileged_or_member_roles_are_refused(
    admin_engine: Engine, db_engine: Engine, role: str
) -> None:
    password = f"Prov-{uuid.uuid4().hex}-Pass"
    with admin_engine.connect() as conn:
        conn.exec_driver_sql(f'ALTER ROLE "{role}" CREATEDB')
    with pytest.raises(ProvisionError, match="too privileged"):
        provision_app_login(db_engine, role, password)
    other = f"{role}_g"
    with admin_engine.connect() as conn:
        conn.exec_driver_sql(f'ALTER ROLE "{role}" NOCREATEDB')
        conn.exec_driver_sql(f'CREATE ROLE "{other}" NOLOGIN')
        conn.exec_driver_sql(f'GRANT "{other}" TO "{role}"')
    try:
        with pytest.raises(ProvisionError, match="member"):
            provision_app_login(db_engine, role, password)
        assert role_state(db_engine, role)["member_of"] == [other]
    finally:
        with admin_engine.connect() as conn:
            conn.exec_driver_sql(f'REVOKE "{other}" FROM "{role}"')
            conn.exec_driver_sql(f'DROP ROLE "{other}"')
    assert role_state(db_engine, role)["rolcanlogin"] is False


def test_missing_role_and_bad_input(db_engine: Engine) -> None:
    with pytest.raises(ProvisionError, match="does not exist"):
        provision_app_login(db_engine, "dfir_no_such_role_x", "a-long-enough-password")
    with pytest.raises(ProvisionError, match="invalid role"):
        role_state(db_engine, 'x"; DROP TABLE users; --')
    with pytest.raises(ValueError):
        provision_app_login(db_engine, "dfirbench_app", "short")


def test_the_shared_app_role_is_not_privileged(db_engine: Engine) -> None:
    state = role_state(db_engine, "dfirbench_app")
    assert not any(state[k] for k in ("rolsuper", "rolcreaterole", "rolcreatedb", "rolbypassrls"))
    assert state["member_of"] == []


def test_cli_refuses_without_a_migrate_url(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import cli
    from app.config import Settings

    plain = Settings(_env_file=None, app_env="test", database_app_role="dfirbench_app")  # type: ignore[call-arg]
    monkeypatch.setattr(cli, "get_settings", lambda: plain)
    assert cli.main(["provision-app-login"]) == 1
    owner_login = plain.model_copy(update={"database_migrate_url": plain.database_url})
    monkeypatch.setattr(cli, "get_settings", lambda: owner_login)
    assert cli.main(["provision-app-login"]) == 1  # DATABASE_URL is the owner, not the role
