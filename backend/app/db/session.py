"""SQLAlchemy 2.0 engine and session factory (sync, psycopg 3).

Sync sessions are used on purpose: the same service code runs in FastAPI (threadpool endpoints)
and in Celery workers. One transaction per service call (guide 14.3).
"""

from __future__ import annotations

from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


def make_engine(url: str, *, pool_pre_ping: bool = True, connect_timeout: int = 5) -> Engine:
    connect_args: dict[str, object] = {}
    if url.startswith("postgresql"):
        connect_args["connect_timeout"] = connect_timeout
        # Every session works in UTC; timestamptz values come back tz-aware UTC.
        connect_args["options"] = "-c timezone=UTC"
    return create_engine(url, pool_pre_ping=pool_pre_ping, connect_args=connect_args, future=True)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return make_engine(get_settings().database_url)


@lru_cache(maxsize=1)
def get_sessionmaker() -> sessionmaker[Session]:
    return make_session_factory(get_engine())
