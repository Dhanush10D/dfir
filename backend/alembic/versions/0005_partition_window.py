"""Bound dfir_ensure_events_partition to the worker's partition window.

The app role holds EXECUTE on this SECURITY DEFINER function, so the database itself must refuse
timestamps outside 1970-01-01 .. now() + 367 days (the worker's window is 366 days; one day of
slack for clock skew). Before this, a direct call could create unbounded partitions, and BC years
produced the same partition name as the matching AD year.

CREATE OR REPLACE keeps the owner, SECURITY DEFINER, and the EXECUTE grants set in 0004.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-29 12:00:00+00:00
"""

import importlib.util
from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NULL_CHECK = """  IF p_ts IS NULL THEN
    RAISE EXCEPTION 'dfir_ensure_events_partition: timestamp is NULL';
  END IF;
"""
WINDOW_CHECK = """  IF p_ts < timestamptz '1970-01-01 00:00:00+00' OR p_ts >= now() + interval '367 days' THEN
    RAISE EXCEPTION 'dfir_ensure_events_partition: timestamp outside partition window';
  END IF;
"""


def _definer_0004() -> str:
    spec = importlib.util.spec_from_file_location(
        "_rev_0004", Path(__file__).with_name("0004_processing.py")
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load revision 0004")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sql: str = module.ENSURE_PARTITION_DEFINER
    if NULL_CHECK not in sql:
        raise RuntimeError("0004 partition function body changed; update 0005")
    return sql


def upgrade() -> None:
    op.execute(_definer_0004().replace(NULL_CHECK, NULL_CHECK + WINDOW_CHECK))


def downgrade() -> None:
    op.execute(_definer_0004())
