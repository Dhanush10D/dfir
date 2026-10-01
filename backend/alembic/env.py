"""Alembic environment: migrations against DATABASE_MIGRATE_URL (else DATABASE_URL)."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

import app.db.models  # noqa: F401  (registers all tables on Base.metadata)
from app.config import get_settings
from app.db.base import Base

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logger", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata

# Objects managed by hand-written SQL in migrations (partitions, etc.) that autogenerate must ignore.
_IGNORED_TABLE_PREFIXES = ("events_",)


def _db_url() -> str:
    x_args = context.get_x_argument(as_dictionary=True)
    url = (
        x_args.get("db_url")
        or config.attributes.get("db_url")
        or get_settings().migrate_database_url
    )
    return str(url)


def include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    return not (type_ == "table" and name and name.startswith(_IGNORED_TABLE_PREFIXES))


def run_migrations_offline() -> None:
    context.configure(
        url=_db_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        {"sqlalchemy.url": _db_url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args={"options": "-c timezone=UTC", "connect_timeout": 10},
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
