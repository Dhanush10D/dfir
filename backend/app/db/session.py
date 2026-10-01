"""SQLAlchemy 2.0 engine and session factory (sync, psycopg 3).

Sync sessions are used on purpose: the same service code runs in FastAPI (threadpool endpoints)
and in Celery workers. One transaction per service call (guide 14.3).
"""

from __future__ import annotations

import re
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

_ROLE_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def make_engine(
    url: str,
    *,
    role: str | None = None,
    pool_pre_ping: bool = True,
    connect_timeout: int = 5,
) -> Engine:
    """Engine whose sessions run in UTC and, when ``role`` is given, as that database role.

    ``role`` is applied as a startup parameter (``SET ROLE``), so every statement the app issues is
    checked against the least-privilege grants of migration 0002 (no UPDATE/DELETE/TRUNCATE on
    custody_log/audit_log), in addition to the append-only triggers.
    """
    connect_args: dict[str, object] = {}
    if url.startswith("postgresql"):
        connect_args["connect_timeout"] = connect_timeout
        # Every session works in UTC; timestamptz values come back tz-aware UTC.
        options = "-c timezone=UTC"
        if role:
            if not _ROLE_NAME.fullmatch(role):
                raise ValueError(f"invalid database role name {role!r}")
            options += f" -c role={role}"
        connect_args["options"] = options
    return create_engine(url, pool_pre_ping=pool_pre_ping, connect_args=connect_args, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = get_settings()
    return make_engine(settings.database_url, role=settings.database_app_role)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    """The process-wide factory (API and workers).

    Its sessions carry the outbox dispatcher in ``session.info`` (see ``services/outbox.py``): a
    commit that added outbound events asks a worker to deliver them. Factories made directly with
    :func:`make_session_factory` (tests, tools) have no dispatcher unless they set one.
    """
    from app.workers.dispatch import dispatch_outbound  # no Celery import until it is called

    factory = make_session_factory(get_engine())
    factory.configure(info={"outbound_dispatch": dispatch_outbound})
    return factory
