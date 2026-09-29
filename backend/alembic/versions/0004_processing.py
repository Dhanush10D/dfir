"""Phase 2: processing pipeline (jobs lifecycle columns, SECURITY DEFINER partition function) and
least-privilege grants for ingest.

jobs
- ``heartbeat_at``: set by the worker at every flush; a ``running`` job whose heartbeat is older
  than ``JOB_LEASE_S`` may be reclaimed (worker crash). ``attempts`` doubles as a fencing token.
- ``superseded_by``: a reprocess run replaces this job's events; the old run manifest is kept.
- ``uq_jobs_active_parse``: at most one queued/running parse job per (evidence, parser), so a
  reprocess can never interleave with the run it replaces.
- ``ck_jobs_progress_range``: progress stays within 0..1.

events
- ``ix_events_evidence_id_parser_name`` for reprocess deletes and evidence filters.
- ``dfir_ensure_events_partition(ts)`` becomes SECURITY DEFINER (owned by the migration owner,
  ``search_path`` pinned, every name schema-qualified) because the app role cannot CREATE tables.
  Rows that already sit in ``events_default`` for the month are moved into the new partition in
  the same transaction (a plain CREATE ... PARTITION OF would fail on them). The app role gets no
  direct privileges on partitions: it reaches rows only through the parent table.

Privileges for ``dfirbench_app`` (it needs no more):
- events: SELECT, INSERT, DELETE (reprocess replaces a job's rows). No UPDATE, no TRUNCATE.
- jobs: SELECT, INSERT, UPDATE. No DELETE: run manifests are provenance records.
- partitions (events_default, events_y*): nothing; EXECUTE on the partition function only.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-28 21:40:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
FN = "public.dfir_ensure_events_partition(timestamptz)"

ENSURE_PARTITION_DEFINER = f"""
CREATE OR REPLACE FUNCTION public.dfir_ensure_events_partition(p_ts timestamptz) RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  month_start timestamp := date_trunc('month', p_ts AT TIME ZONE 'UTC');
  lo          timestamptz := month_start AT TIME ZONE 'UTC';
  hi          timestamptz := (month_start + interval '1 month') AT TIME ZONE 'UTC';
  part_name   text := format('events_y%sm%s', to_char(month_start, 'YYYY'), to_char(month_start, 'MM'));
  cols        text;
BEGIN
  IF p_ts IS NULL THEN
    RAISE EXCEPTION 'dfir_ensure_events_partition: timestamp is NULL';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtext('dfir_events_partition:' || part_name));
  IF to_regclass(format('public.%I', part_name)) IS NOT NULL THEN
    RETURN part_name;
  END IF;
  SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO cols
    FROM pg_attribute
   WHERE attrelid = 'public.events'::regclass AND attnum > 0 AND NOT attisdropped;
  -- Build the partition detached, move any stray rows out of the DEFAULT partition, then attach
  -- (CREATE ... PARTITION OF fails while events_default holds rows of that month).
  EXECUTE format(
    'CREATE TABLE public.%I (LIKE public.events INCLUDING DEFAULTS INCLUDING CONSTRAINTS)',
    part_name);
  EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK (ts >= %L AND ts < %L)',
    part_name, part_name || '_range', lo, hi);
  EXECUTE format(
    'WITH moved AS (DELETE FROM public.events_default WHERE ts >= %L AND ts < %L RETURNING %s) '
    'INSERT INTO public.%I (%s) SELECT %s FROM moved',
    lo, hi, cols, part_name, cols, cols);
  EXECUTE format('ALTER TABLE public.events ATTACH PARTITION public.%I FOR VALUES FROM (%L) TO (%L)',
    part_name, lo, hi);
  EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', part_name, part_name || '_range');
  -- Default privileges would grant DML on the new table; the app reaches rows via the parent only.
  EXECUTE format('REVOKE ALL ON public.%I FROM {APP_ROLE}', part_name);
  RETURN part_name;
END;
$$;
"""

# The Phase 0 definition (SECURITY INVOKER), restored on downgrade.
ENSURE_PARTITION_INVOKER = """
CREATE OR REPLACE FUNCTION dfir_ensure_events_partition(p_ts timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE
  month_start timestamp := date_trunc('month', p_ts AT TIME ZONE 'UTC');
  month_end   timestamp := month_start + interval '1 month';
  part_name   text := format('events_y%sm%s', to_char(month_start, 'YYYY'), to_char(month_start, 'MM'));
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('dfir_events_partition:' || part_name));
  IF to_regclass(format('public.%I', part_name)) IS NULL THEN
    EXECUTE format(
      'CREATE TABLE public.%I PARTITION OF public.events FOR VALUES FROM (%L) TO (%L)',
      part_name,
      (month_start AT TIME ZONE 'UTC'),
      (month_end AT TIME ZONE 'UTC')
    );
  END IF;
  RETURN part_name;
END;
$$;
ALTER FUNCTION dfir_ensure_events_partition(timestamptz) RESET search_path;
"""

REVOKE_PARTITIONS = f"""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
            WHERE i.inhparent = 'public.events'::regclass LOOP
    EXECUTE format('REVOKE ALL ON public.%I FROM {APP_ROLE}', r.relname);
  END LOOP;
END
$$;
"""

GRANT_PARTITIONS = f"""
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.relname FROM pg_inherits i
             JOIN pg_class c ON c.oid = i.inhrelid
            WHERE i.inhparent = 'public.events'::regclass LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON public.%I TO {APP_ROLE}', r.relname);
  END LOOP;
END
$$;
"""

ACTIVE_WHERE = "kind = 'parse' AND status IN ('queued', 'running')"


def upgrade() -> None:
    op.add_column("jobs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("jobs", sa.Column("superseded_by", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_jobs_superseded_by_jobs"), "jobs", "jobs", ["superseded_by"], ["id"]
    )
    op.create_check_constraint("progress_range", "jobs", "progress >= 0 AND progress <= 1")
    op.create_index("ix_jobs_case_id_queued_at", "jobs", ["case_id", "queued_at"], unique=False)
    op.create_index("ix_jobs_evidence_id", "jobs", ["evidence_id"], unique=False)
    op.create_index(
        "uq_jobs_active_parse",
        "jobs",
        ["evidence_id", "parser"],
        unique=True,
        postgresql_where=sa.text(ACTIVE_WHERE),
    )
    op.create_index(
        "ix_events_evidence_id_parser_name",
        "events",
        ["evidence_id", "parser_name"],
        unique=False,
    )

    op.execute(ENSURE_PARTITION_DEFINER)
    op.execute(f"REVOKE ALL ON FUNCTION {FN} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {FN} TO {APP_ROLE}")

    op.execute(f"REVOKE UPDATE, TRUNCATE ON events FROM {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON jobs FROM {APP_ROLE}")
    op.execute(REVOKE_PARTITIONS)


def downgrade() -> None:
    op.execute(GRANT_PARTITIONS)
    op.execute(f"GRANT DELETE ON jobs TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ON events TO {APP_ROLE}")
    op.execute(ENSURE_PARTITION_INVOKER)
    op.execute(f"GRANT EXECUTE ON FUNCTION {FN} TO PUBLIC")
    op.drop_index("ix_events_evidence_id_parser_name", table_name="events")
    op.drop_index("uq_jobs_active_parse", table_name="jobs", postgresql_where=sa.text(ACTIVE_WHERE))
    op.drop_index("ix_jobs_evidence_id", table_name="jobs")
    op.drop_index("ix_jobs_case_id_queued_at", table_name="jobs")
    op.drop_constraint(op.f("ck_jobs_progress_range"), "jobs", type_="check")
    op.drop_constraint(op.f("fk_jobs_superseded_by_jobs"), "jobs", type_="foreignkey")
    op.drop_column("jobs", "superseded_by")
    op.drop_column("jobs", "heartbeat_at")
