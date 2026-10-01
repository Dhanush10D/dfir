"""Phase 9: response (playbook runs, steps, four-eyes action requests) and integrations
(encrypted credentials, outbox + delivery log, inbound deliveries, enrichment cache).

playbooks
- ``sha256``, ``origin`` (builtin/custom), ``notify``, ``created_by``. No DELETE for the app.

playbook_runs
- ``alert_id`` (the triggering alert), ``definition`` (snapshot), ``playbook_sha256``; CHECKs
  ``status`` and ``finished``; trigger ``playbook_runs_guard`` (identity immutable, only
  running -> completed|cancelled, completion needs every step finished). The app may UPDATE only
  ``status`` and ``finished_at``. ``step_states`` stays: the downgrade archives the steps there.

playbook_run_steps (new)
- One row per step. Trigger ``playbook_run_steps_guard``: identity immutable, finished rows
  frozen, only the documented transitions, and a step that requires approval reaches an executed
  state only through a request approved by someone other than its requester.

action_requests (new)
- Trigger ``action_requests_guard`` compares with OLD: requester, action and parameters are
  immutable; pending -> approved needs a decider other than OLD.requested_by before
  OLD.expires_at; approved -> finished needs the recorded four-eyes approval; decision and
  outcome columns change only with their transition; rejected/expired/finished rows are frozen.
  CHECKs ``pending``, ``four_eyes``, ``rejected``, ``expired``, ``finished`` hold even with
  triggers bypassed. UNIQUE idempotency key; at most one open request per step.

integrations
- ``config``, ``case_id``, ``secret_wrapped_key``, ``secret_key_id``, ``secret_fingerprint``,
  ``last_status_at``, ``created_by``, ``created_at``, ``updated_by``; CHECKs ``type``, ``secret``
  (ciphertext, wrapped key and key id come together) and ``ingest_case``. No DELETE for the app.

outbound_events / outbound_deliveries (new), inbound_deliveries (new, append-only),
ioc_enrichments (new), notifications + ``case_id``, ``dedup_key``.

Rows from before this revision and rows that come back after a downgrade are brought to a state
the constraints accept: runs that are not finished become ``cancelled`` (their steps are not in
the new tables), integration secrets are cleared and the integrations disabled.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-01 09:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
INTEGRATION_TYPES = "('webhook_out','webhook_in','slack','teams','email','virustotal','misp')"
RUN_UPDATE = "status, finished_at"
STEP_UPDATE = "status, outcome, result, notes, completed_by, completed_at, updated_by, updated_at"
REQUEST_UPDATE = (
    "status, decided_by, decided_at, decision_reason, executed_by, executed_at, outcome, result"
)
DELIVERY_UPDATE = (
    "status, attempts, next_attempt_at, locked_until, last_error, response_status, updated_at, "
    "delivered_at"
)
# Runs whose steps are not (or no longer) in playbook_run_steps cannot continue.
CANCEL_UNFINISHED_RUNS = (
    "UPDATE playbook_runs SET status = 'cancelled', finished_at = COALESCE(finished_at, now()) "
    "WHERE status NOT IN ('completed', 'cancelled')"
)
# A secret is unreadable without its wrapped data key and key id, so it cannot be kept across the
# schema change in either direction; the integration is switched off until it is re-entered.
CLEAR_SECRETS = (
    "UPDATE integrations SET enabled = false, config_encrypted = NULL, last_status = NULL "
    "WHERE enabled OR config_encrypted IS NOT NULL OR last_status IS NOT NULL"
)

RUNS_GUARD_FN = """
CREATE FUNCTION playbook_runs_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'running' OR NEW.finished_at IS NOT NULL THEN
      RAISE EXCEPTION 'a new playbook run must be running' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.playbook_id IS DISTINCT FROM OLD.playbook_id
     OR NEW.playbook_version IS DISTINCT FROM OLD.playbook_version
     OR NEW.playbook_sha256 IS DISTINCT FROM OLD.playbook_sha256
     OR NEW.definition IS DISTINCT FROM OLD.definition
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
     OR NEW.started_by IS DISTINCT FROM OLD.started_by
     OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION 'playbook run % identity is immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'running' THEN
    RAISE EXCEPTION 'playbook run % is % and cannot change', OLD.id, OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = 'completed' AND EXISTS (
       SELECT 1 FROM playbook_run_steps s
       WHERE s.run_id = OLD.id AND s.status NOT IN ('done', 'skipped')) THEN
    RAISE EXCEPTION 'playbook run % still has open steps', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""

STEPS_GUARD_FN = """
CREATE FUNCTION playbook_run_steps_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  run_status text;
  req_status text;
  req_outcome text;
  req_decided uuid;
  req_requested uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'pending' OR NEW.outcome IS NOT NULL OR NEW.result IS NOT NULL
       OR NEW.notes IS NOT NULL OR NEW.completed_by IS NOT NULL
       OR NEW.completed_at IS NOT NULL THEN
      RAISE EXCEPTION 'a new playbook step must be pending' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.run_id IS DISTINCT FROM OLD.run_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.position IS DISTINCT FROM OLD.position
     OR NEW.phase IS DISTINCT FROM OLD.phase
     OR NEW.step_key IS DISTINCT FROM OLD.step_key
     OR NEW.text IS DISTINCT FROM OLD.text
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.action IS DISTINCT FROM OLD.action
     OR NEW.params IS DISTINCT FROM OLD.params
     OR NEW.requires_approval IS DISTINCT FROM OLD.requires_approval THEN
    RAISE EXCEPTION 'playbook step % identity is immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status IN ('done', 'skipped') THEN
    RAISE EXCEPTION 'playbook step % is % and cannot change', OLD.id, OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  SELECT r.status INTO run_status FROM playbook_runs r WHERE r.id = OLD.run_id;
  IF run_status IS DISTINCT FROM 'running' THEN
    RAISE EXCEPTION 'playbook step % belongs to a run that is not running', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.status = OLD.status THEN
    IF NEW.outcome IS DISTINCT FROM OLD.outcome OR NEW.result IS DISTINCT FROM OLD.result
       OR NEW.notes IS DISTINCT FROM OLD.notes
       OR NEW.completed_by IS DISTINCT FROM OLD.completed_by
       OR NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN
      RAISE EXCEPTION 'playbook step % changes only with a status transition', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  -- The newest action request of this step (NULLs when there is none).
  SELECT q.status, q.outcome, q.decided_by, q.requested_by
    INTO req_status, req_outcome, req_decided, req_requested
    FROM action_requests q WHERE q.step_id = OLD.id
    ORDER BY q.requested_at DESC, q.id DESC LIMIT 1;
  IF NEW.status = 'awaiting_approval' THEN
    IF OLD.status NOT IN ('pending', 'failed') OR OLD.kind <> 'action'
       OR req_status IS DISTINCT FROM 'pending' THEN
      RAISE EXCEPTION 'playbook step % has no pending action request', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.status = 'approved' THEN
    IF OLD.status <> 'awaiting_approval' OR req_status IS DISTINCT FROM 'approved' THEN
      RAISE EXCEPTION 'playbook step % has no approved action request', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.status = 'pending' THEN
    IF NOT ((OLD.status = 'awaiting_approval' AND req_status IN ('rejected', 'expired'))
            OR (OLD.status = 'approved' AND req_status = 'expired')) THEN
      RAISE EXCEPTION 'playbook step % cannot return to pending', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.status = 'skipped' THEN
    IF OLD.status NOT IN ('pending', 'failed', 'not_executed') THEN
      RAISE EXCEPTION 'playbook step % cannot be skipped while %', OLD.id, OLD.status
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.status = 'done' AND OLD.status = 'not_executed' THEN
    IF NEW.outcome IS DISTINCT FROM 'completed_manually' THEN
      RAISE EXCEPTION 'playbook step % was not executed; it can only be completed manually',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
  ELSIF NEW.status IN ('done', 'failed', 'not_executed') THEN
    IF NEW.status = 'done' AND NEW.outcome IS DISTINCT FROM 'completed' THEN
      RAISE EXCEPTION 'playbook step % has an inconsistent outcome', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.requires_approval THEN
      IF OLD.status <> 'approved' OR req_status IS DISTINCT FROM 'finished'
         OR req_decided IS NULL OR req_decided = req_requested
         OR req_outcome IS DISTINCT FROM
            (CASE NEW.status WHEN 'done' THEN 'completed' ELSE NEW.status END) THEN
        RAISE EXCEPTION 'playbook step % needs an approved and executed action request', OLD.id
          USING ERRCODE = 'check_violation';
      END IF;
    ELSIF OLD.status NOT IN ('pending', 'failed') THEN
      RAISE EXCEPTION 'playbook step % cannot move from % to %', OLD.id, OLD.status, NEW.status
        USING ERRCODE = 'check_violation';
    ELSIF OLD.kind = 'manual' AND NEW.status <> 'done' THEN
      RAISE EXCEPTION 'manual playbook step % can only be done or skipped', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    RAISE EXCEPTION 'playbook step % cannot move from % to %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""

REQUESTS_GUARD_FN = """
CREATE FUNCTION action_requests_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  decision_changed boolean;
  exec_changed boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'pending' OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
       OR NEW.decision_reason IS NOT NULL OR NEW.executed_by IS NOT NULL
       OR NEW.executed_at IS NOT NULL OR NEW.outcome IS NOT NULL
       OR NEW.result IS NOT NULL THEN
      RAISE EXCEPTION 'a new action request must be pending and undecided'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.run_id IS DISTINCT FROM OLD.run_id
     OR NEW.step_id IS DISTINCT FROM OLD.step_id
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
     OR NEW.action IS DISTINCT FROM OLD.action
     OR NEW.params IS DISTINCT FROM OLD.params
     OR NEW.params_sha256 IS DISTINCT FROM OLD.params_sha256
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
     OR NEW.requested_at IS DISTINCT FROM OLD.requested_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
    RAISE EXCEPTION 'action request % requester, action and parameters are immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status IN ('rejected', 'expired', 'finished') THEN
    RAISE EXCEPTION 'action request % is % and cannot change', OLD.id, OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  decision_changed := NEW.decided_by IS DISTINCT FROM OLD.decided_by
                      OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
                      OR NEW.decision_reason IS DISTINCT FROM OLD.decision_reason;
  exec_changed := NEW.executed_by IS DISTINCT FROM OLD.executed_by
                  OR NEW.executed_at IS DISTINCT FROM OLD.executed_at
                  OR NEW.outcome IS DISTINCT FROM OLD.outcome
                  OR NEW.result IS DISTINCT FROM OLD.result;
  IF NEW.status = OLD.status THEN
    IF decision_changed OR exec_changed THEN
      RAISE EXCEPTION 'action request % decision and outcome change only with a transition',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'pending' AND NEW.status = 'approved' THEN
    IF exec_changed OR NEW.decided_by IS NULL OR NEW.decided_at IS NULL
       OR NEW.decided_by = OLD.requested_by OR NEW.decided_at > OLD.expires_at THEN
      RAISE EXCEPTION
        'action request % must be approved before it expires by someone other than the requester',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'pending' AND NEW.status = 'rejected' THEN
    IF exec_changed OR NEW.decided_by IS NULL OR NEW.decided_at IS NULL THEN
      RAISE EXCEPTION 'action request % rejection must name who decided', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'pending' AND NEW.status = 'expired' THEN
    IF exec_changed OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NULL
       OR NEW.decision_reason IS DISTINCT FROM OLD.decision_reason
       OR NEW.decided_at < OLD.expires_at THEN
      RAISE EXCEPTION 'action request % has not expired', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'approved' AND NEW.status = 'finished' THEN
    IF decision_changed OR OLD.decided_by IS NULL OR OLD.decided_by = OLD.requested_by
       OR NEW.executed_by IS NULL OR NEW.executed_at IS NULL OR NEW.outcome IS NULL
       OR NEW.executed_at > OLD.expires_at THEN
      RAISE EXCEPTION
        'action request % can only be executed once, after a four-eyes approval, before expiry',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'approved' AND NEW.status = 'expired' THEN
    IF decision_changed OR exec_changed THEN
      RAISE EXCEPTION 'action request % expiry must not change the decision', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    RAISE EXCEPTION 'action request % cannot move from % to %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""

DELIVERIES_GUARD_FN = """
CREATE FUNCTION outbound_deliveries_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.integration_id IS DISTINCT FROM OLD.integration_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.event_type IS DISTINCT FROM OLD.event_type
     OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
     OR NEW.dedup_key IS DISTINCT FROM OLD.dedup_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'outbound delivery % identity is immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'pending' THEN
    RAISE EXCEPTION 'outbound delivery % is % and cannot change', OLD.id, OLD.status
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.attempts < OLD.attempts THEN
    RAISE EXCEPTION 'outbound delivery % attempts never decrease', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""

ARCHIVE_STEPS = """
UPDATE playbook_runs r SET step_states = COALESCE((
  SELECT jsonb_object_agg(s.step_key, jsonb_build_object(
    'phase', s.phase, 'text', s.text, 'action', s.action, 'status', s.status,
    'outcome', s.outcome, 'result', s.result, 'notes', s.notes,
    'completed_by', s.completed_by, 'completed_at', s.completed_at,
    'updated_by', s.updated_by, 'updated_at', s.updated_at))
  FROM playbook_run_steps s WHERE s.run_id = r.id), '{}'::jsonb)
"""


def _tstz(name: str, **kw: object) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.DateTime(timezone=True), **kw)  # type: ignore[arg-type]


def _uuid_pk() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False)


def _jsonb(name: str, default: str = "'{}'::jsonb", nullable: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        name,
        postgresql.JSONB(astext_type=sa.Text()),
        server_default=sa.text(default) if not nullable else None,
        nullable=nullable,
    )


def _now(name: str) -> sa.Column:  # type: ignore[type-arg]
    return _tstz(name, server_default=sa.text("now()"), nullable=False)


def upgrade() -> None:
    # ---- playbooks
    op.add_column("playbooks", sa.Column("sha256", sa.CHAR(64), nullable=True))
    op.add_column(
        "playbooks",
        sa.Column("origin", sa.Text(), server_default=sa.text("'builtin'"), nullable=False),
    )
    op.add_column("playbooks", _jsonb("notify"))
    op.add_column("playbooks", sa.Column("created_by", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_playbooks_created_by_users"), "playbooks", "users", ["created_by"], ["id"]
    )
    op.create_check_constraint("origin", "playbooks", "origin IN ('builtin','custom')")

    # ---- playbook_runs
    op.add_column("playbook_runs", sa.Column("alert_id", sa.UUID(), nullable=True))
    op.add_column("playbook_runs", _jsonb("definition"))
    op.add_column("playbook_runs", sa.Column("playbook_sha256", sa.CHAR(64), nullable=True))
    op.create_foreign_key(
        op.f("fk_playbook_runs_alert_id_alerts"), "playbook_runs", "alerts", ["alert_id"], ["id"]
    )
    # No earlier code wrote runs; any that exist have no step rows and cannot continue.
    op.execute(CANCEL_UNFINISHED_RUNS)
    op.execute("UPDATE playbook_runs SET finished_at = now() WHERE finished_at IS NULL")
    op.create_check_constraint(
        "status", "playbook_runs", "status IN ('running','completed','cancelled')"
    )
    op.create_check_constraint(
        "finished", "playbook_runs", "(status = 'running') = (finished_at IS NULL)"
    )
    op.create_index(
        "ix_playbook_runs_case_id_started_at", "playbook_runs", ["case_id", "started_at"]
    )

    # ---- playbook_run_steps
    op.create_table(
        "playbook_run_steps",
        _uuid_pk(),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("phase", sa.Text(), nullable=False),
        sa.Column("step_key", sa.Text(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=True),
        _jsonb("params"),
        sa.Column(
            "requires_approval", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        _jsonb("result", nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("completed_by", sa.UUID(), nullable=True),
        _tstz("completed_at", nullable=True),
        sa.Column("updated_by", sa.UUID(), nullable=True),
        _now("updated_at"),
        sa.CheckConstraint("kind IN ('manual','action')", name=op.f("ck_playbook_run_steps_kind")),
        sa.CheckConstraint(
            "(kind = 'manual' AND action IS NULL AND NOT requires_approval) "
            "OR (kind = 'action' AND action IS NOT NULL)",
            name=op.f("ck_playbook_run_steps_kind_action"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','awaiting_approval','approved','not_executed','failed',"
            "'done','skipped')",
            name=op.f("ck_playbook_run_steps_status"),
        ),
        sa.CheckConstraint(
            "(status IN ('pending','awaiting_approval','approved') AND outcome IS NULL) "
            "OR (status = 'not_executed' AND outcome = 'not_executed') "
            "OR (status = 'failed' AND outcome = 'failed') "
            "OR (status = 'done' AND outcome IN ('completed','completed_manually')) "
            "OR (status = 'skipped' AND outcome = 'skipped')",
            name=op.f("ck_playbook_run_steps_outcome"),
        ),
        sa.CheckConstraint(
            "(status IN ('done','skipped')) = (completed_by IS NOT NULL) "
            "AND (status IN ('done','skipped')) = (completed_at IS NOT NULL)",
            name=op.f("ck_playbook_run_steps_completed"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["playbook_runs.id"],
            name=op.f("fk_playbook_run_steps_run_id_playbook_runs"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_playbook_run_steps_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["completed_by"], ["users.id"], name=op.f("fk_playbook_run_steps_completed_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["updated_by"], ["users.id"], name=op.f("fk_playbook_run_steps_updated_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_playbook_run_steps")),
        sa.UniqueConstraint(
            "run_id", "step_key", name=op.f("uq_playbook_run_steps_run_id_step_key")
        ),
        sa.UniqueConstraint(
            "run_id", "position", name=op.f("uq_playbook_run_steps_run_id_position")
        ),
    )
    op.create_index("ix_playbook_run_steps_case_id", "playbook_run_steps", ["case_id"])

    # ---- action_requests
    op.create_table(
        "action_requests",
        _uuid_pk(),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("step_id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        _jsonb("params"),
        sa.Column("params_sha256", sa.CHAR(64), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("requested_by", sa.UUID(), nullable=False),
        _now("requested_at"),
        _tstz("expires_at", nullable=False),
        sa.Column("decided_by", sa.UUID(), nullable=True),
        _tstz("decided_at", nullable=True),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("executed_by", sa.UUID(), nullable=True),
        _tstz("executed_at", nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        _jsonb("result", nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired','finished')",
            name=op.f("ck_action_requests_status"),
        ),
        sa.CheckConstraint("expires_at > requested_at", name=op.f("ck_action_requests_expiry")),
        sa.CheckConstraint(
            "status <> 'pending' OR (decided_by IS NULL AND decided_at IS NULL "
            "AND decision_reason IS NULL)",
            name=op.f("ck_action_requests_pending"),
        ),
        sa.CheckConstraint(
            "status NOT IN ('approved','finished') OR (decided_by IS NOT NULL "
            "AND decided_at IS NOT NULL AND decided_by <> requested_by)",
            name=op.f("ck_action_requests_four_eyes"),
        ),
        sa.CheckConstraint(
            "status <> 'rejected' OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)",
            name=op.f("ck_action_requests_rejected"),
        ),
        sa.CheckConstraint(
            "status <> 'expired' OR decided_at IS NOT NULL", name=op.f("ck_action_requests_expired")
        ),
        sa.CheckConstraint(
            "(status = 'finished') = (executed_at IS NOT NULL) "
            "AND (status = 'finished') = (executed_by IS NOT NULL) "
            "AND (status = 'finished') = (outcome IS NOT NULL)",
            name=op.f("ck_action_requests_finished"),
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR outcome IN ('completed','not_executed','failed')",
            name=op.f("ck_action_requests_outcome"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_action_requests_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["playbook_runs.id"], name=op.f("fk_action_requests_run_id_playbook_runs")
        ),
        sa.ForeignKeyConstraint(
            ["step_id"],
            ["playbook_run_steps.id"],
            name=op.f("fk_action_requests_step_id_playbook_run_steps"),
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], name=op.f("fk_action_requests_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"], ["users.id"], name=op.f("fk_action_requests_requested_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["decided_by"], ["users.id"], name=op.f("fk_action_requests_decided_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["executed_by"], ["users.id"], name=op.f("fk_action_requests_executed_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_action_requests")),
        sa.UniqueConstraint("idempotency_key", name=op.f("uq_action_requests_idempotency_key")),
    )
    op.create_index(
        "uq_action_requests_open_step",
        "action_requests",
        ["step_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending','approved')"),
    )
    op.create_index("ix_action_requests_case_id_status", "action_requests", ["case_id", "status"])
    op.create_index(
        "ix_action_requests_step_id_requested_at", "action_requests", ["step_id", "requested_at"]
    )

    # ---- integrations
    op.add_column("integrations", _jsonb("config"))
    op.add_column("integrations", sa.Column("case_id", sa.UUID(), nullable=True))
    op.add_column("integrations", sa.Column("secret_wrapped_key", sa.LargeBinary(), nullable=True))
    op.add_column("integrations", sa.Column("secret_key_id", sa.Text(), nullable=True))
    op.add_column("integrations", sa.Column("secret_fingerprint", sa.Text(), nullable=True))
    op.add_column("integrations", _tstz("last_status_at", nullable=True))
    op.add_column("integrations", sa.Column("created_by", sa.UUID(), nullable=True))
    op.add_column("integrations", _now("created_at"))
    op.add_column("integrations", sa.Column("updated_by", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_integrations_case_id_cases"), "integrations", "cases", ["case_id"], ["id"]
    )
    for col in ("created_by", "updated_by"):
        op.create_foreign_key(
            op.f(f"fk_integrations_{col}_users"), "integrations", "users", [col], ["id"]
        )
    # Rows from before this revision (no earlier code wrote any; a downgrade leaves some): an old
    # secret cannot be read, an unknown type cannot be used, and an ingest source has lost its
    # case, so such rows are cleared, removed or kept disabled until an admin completes them.
    op.execute(CLEAR_SECRETS)
    op.execute(f"DELETE FROM integrations WHERE type NOT IN {INTEGRATION_TYPES}")
    op.create_check_constraint("type", "integrations", f"type IN {INTEGRATION_TYPES}")
    op.create_check_constraint(
        "secret",
        "integrations",
        "(config_encrypted IS NULL) = (secret_wrapped_key IS NULL) "
        "AND (config_encrypted IS NULL) = (secret_key_id IS NULL)",
    )
    op.create_check_constraint(
        "ingest_case", "integrations", "type <> 'webhook_in' OR case_id IS NOT NULL OR NOT enabled"
    )

    # ---- outbound_events / outbound_deliveries
    op.create_table(
        "outbound_events",
        _uuid_pk(),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=True),
        _jsonb("payload"),
        sa.Column("dedup_key", sa.Text(), nullable=True),
        sa.Column("only_integration_id", sa.UUID(), nullable=True),
        _now("created_at"),
        _tstz("fanned_out_at", nullable=True),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_outbound_events_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["only_integration_id"],
            ["integrations.id"],
            name=op.f("fk_outbound_events_only_integration_id_integrations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbound_events")),
        sa.UniqueConstraint("dedup_key", name=op.f("uq_outbound_events_dedup_key")),
    )
    op.create_index(
        "ix_outbound_events_pending",
        "outbound_events",
        ["created_at"],
        postgresql_where=sa.text("fanned_out_at IS NULL"),
    )
    op.create_table(
        "outbound_deliveries",
        _uuid_pk(),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        _tstz("next_attempt_at", nullable=True),
        _tstz("locked_until", nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
        sa.Column("dedup_key", sa.Text(), nullable=True),
        _now("created_at"),
        _now("updated_at"),
        _tstz("delivered_at", nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','delivered','failed','suppressed')",
            name=op.f("ck_outbound_deliveries_status"),
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= max_attempts",
            name=op.f("ck_outbound_deliveries_attempts"),
        ),
        sa.CheckConstraint(
            "(status = 'delivered') = (delivered_at IS NOT NULL)",
            name=op.f("ck_outbound_deliveries_delivered"),
        ),
        sa.CheckConstraint(
            "status <> 'pending' OR next_attempt_at IS NOT NULL",
            name=op.f("ck_outbound_deliveries_pending_due"),
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["outbound_events.id"],
            name=op.f("fk_outbound_deliveries_event_id_outbound_events"),
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_outbound_deliveries_integration_id_integrations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_outbound_deliveries")),
        sa.UniqueConstraint(
            "event_id",
            "integration_id",
            name=op.f("uq_outbound_deliveries_event_id_integration_id"),
        ),
    )
    op.create_index(
        "ix_outbound_deliveries_due",
        "outbound_deliveries",
        ["next_attempt_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_outbound_deliveries_integration_id_created_at",
        "outbound_deliveries",
        ["integration_id", "created_at"],
    )

    # ---- inbound_deliveries
    op.create_table(
        "inbound_deliveries",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("nonce", sa.CHAR(64), nullable=False),
        _now("received_at"),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("body_sha256", sa.CHAR(64), nullable=False),
        sa.Column("items", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("created", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("updated", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("errors", sa.Integer(), server_default=sa.text("0"), nullable=False),
        _jsonb("error_reasons"),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_inbound_deliveries_integration_id_integrations"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_inbound_deliveries_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inbound_deliveries")),
        sa.UniqueConstraint(
            "integration_id", "nonce", name=op.f("uq_inbound_deliveries_integration_id_nonce")
        ),
    )
    op.create_index(
        "ix_inbound_deliveries_integration_id_received_at",
        "inbound_deliveries",
        ["integration_id", "received_at"],
    )

    # ---- ioc_enrichments
    op.create_table(
        "ioc_enrichments",
        _uuid_pk(),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("ioc_type", sa.Text(), nullable=False),
        sa.Column("value_sha256", sa.CHAR(64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("score", sa.REAL(), nullable=True),
        _jsonb("summary"),
        _now("fetched_at"),
        _tstz("expires_at", nullable=False),
        sa.CheckConstraint(
            "verdict IN ('malicious','suspicious','harmless','unknown')",
            name=op.f("ck_ioc_enrichments_verdict"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ioc_enrichments")),
        sa.UniqueConstraint(
            "provider",
            "ioc_type",
            "value_sha256",
            name=op.f("uq_ioc_enrichments_provider_ioc_type_value_sha256"),
        ),
    )

    # ---- notifications
    op.add_column("notifications", sa.Column("case_id", sa.UUID(), nullable=True))
    op.add_column("notifications", sa.Column("dedup_key", sa.Text(), nullable=True))
    op.create_foreign_key(
        op.f("fk_notifications_case_id_cases"), "notifications", "cases", ["case_id"], ["id"]
    )
    op.create_index(
        "uq_notifications_user_id_dedup_key",
        "notifications",
        ["user_id", "dedup_key"],
        unique=True,
        postgresql_where=sa.text("dedup_key IS NOT NULL"),
    )
    op.create_index(
        "ix_notifications_user_id_created_at", "notifications", ["user_id", "created_at"]
    )

    # ---- triggers
    op.execute(RUNS_GUARD_FN)
    op.execute(
        "CREATE TRIGGER playbook_runs_guard BEFORE INSERT OR UPDATE ON playbook_runs "
        "FOR EACH ROW EXECUTE FUNCTION playbook_runs_guard()"
    )
    op.execute(STEPS_GUARD_FN)
    op.execute(
        "CREATE TRIGGER playbook_run_steps_guard BEFORE INSERT OR UPDATE ON playbook_run_steps "
        "FOR EACH ROW EXECUTE FUNCTION playbook_run_steps_guard()"
    )
    op.execute(REQUESTS_GUARD_FN)
    op.execute(
        "CREATE TRIGGER action_requests_guard BEFORE INSERT OR UPDATE ON action_requests "
        "FOR EACH ROW EXECUTE FUNCTION action_requests_guard()"
    )
    op.execute(DELIVERIES_GUARD_FN)
    op.execute(
        "CREATE TRIGGER outbound_deliveries_guard BEFORE UPDATE ON outbound_deliveries "
        "FOR EACH ROW EXECUTE FUNCTION outbound_deliveries_guard()"
    )
    op.execute(
        "CREATE TRIGGER inbound_deliveries_no_update BEFORE UPDATE OR DELETE OR TRUNCATE "
        "ON inbound_deliveries FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()"
    )

    # ---- grants (least privilege: no DELETE anywhere, UPDATE on workflow columns only)
    op.execute(f"REVOKE DELETE, TRUNCATE ON playbooks FROM {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON playbook_runs FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({RUN_UPDATE}) ON playbook_runs TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON playbook_run_steps FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON playbook_run_steps TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({STEP_UPDATE}) ON playbook_run_steps TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON action_requests FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON action_requests TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({REQUEST_UPDATE}) ON action_requests TO {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON integrations FROM {APP_ROLE}")
    op.execute(f"REVOKE ALL ON outbound_events FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON outbound_events TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE (fanned_out_at) ON outbound_events TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON outbound_deliveries FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON outbound_deliveries TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({DELIVERY_UPDATE}) ON outbound_deliveries TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON inbound_deliveries FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON inbound_deliveries TO {APP_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE inbound_deliveries_id_seq TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON ioc_enrichments FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ioc_enrichments TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON notifications FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE (read_at) ON notifications TO {APP_ROLE}")


def downgrade() -> None:
    # ---- grants back to the pre-0012 defaults
    op.execute(f"REVOKE UPDATE (read_at) ON notifications FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON notifications TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON integrations TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE ({RUN_UPDATE}) ON playbook_runs FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON playbook_runs TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON playbooks TO {APP_ROLE}")

    # ---- triggers
    op.execute("DROP TRIGGER IF EXISTS inbound_deliveries_no_update ON inbound_deliveries")
    for table in ("outbound_deliveries", "action_requests", "playbook_run_steps", "playbook_runs"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_guard ON {table}")
        op.execute(f"DROP FUNCTION IF EXISTS {table}_guard()")

    # ---- notifications
    op.drop_index("ix_notifications_user_id_created_at", table_name="notifications")
    op.drop_index("uq_notifications_user_id_dedup_key", table_name="notifications")
    op.drop_constraint(op.f("fk_notifications_case_id_cases"), "notifications", type_="foreignkey")
    op.drop_column("notifications", "dedup_key")
    op.drop_column("notifications", "case_id")

    # ---- playbook runs: keep what each step recorded, then end runs that lose their steps.
    # Downgrade-only: the step and approval tables are dropped below, so a running run could not
    # continue, and a later upgrade would find it without steps.
    op.execute(ARCHIVE_STEPS)
    op.execute(CANCEL_UNFINISHED_RUNS)

    # ---- new tables (children first)
    op.drop_table("ioc_enrichments")
    op.drop_table("inbound_deliveries")
    op.drop_table("outbound_deliveries")
    op.drop_table("outbound_events")
    op.drop_table("action_requests")
    op.drop_table("playbook_run_steps")

    # ---- integrations: the wrapped data key and key id go away, so secrets cannot be kept
    op.execute(CLEAR_SECRETS)
    op.drop_constraint(op.f("ck_integrations_ingest_case"), "integrations", type_="check")
    op.drop_constraint(op.f("ck_integrations_secret"), "integrations", type_="check")
    op.drop_constraint(op.f("ck_integrations_type"), "integrations", type_="check")
    for col in ("updated_by", "created_by"):
        op.drop_constraint(op.f(f"fk_integrations_{col}_users"), "integrations", type_="foreignkey")
    op.drop_constraint(op.f("fk_integrations_case_id_cases"), "integrations", type_="foreignkey")
    for col in (
        "updated_by",
        "created_at",
        "created_by",
        "last_status_at",
        "secret_fingerprint",
        "secret_key_id",
        "secret_wrapped_key",
        "case_id",
        "config",
    ):
        op.drop_column("integrations", col)

    # ---- playbook_runs
    op.drop_index("ix_playbook_runs_case_id_started_at", table_name="playbook_runs")
    op.drop_constraint(op.f("ck_playbook_runs_finished"), "playbook_runs", type_="check")
    op.drop_constraint(op.f("ck_playbook_runs_status"), "playbook_runs", type_="check")
    op.drop_constraint(
        op.f("fk_playbook_runs_alert_id_alerts"), "playbook_runs", type_="foreignkey"
    )
    for col in ("playbook_sha256", "definition", "alert_id"):
        op.drop_column("playbook_runs", col)

    # ---- playbooks
    op.drop_constraint(op.f("ck_playbooks_origin"), "playbooks", type_="check")
    op.drop_constraint(op.f("fk_playbooks_created_by_users"), "playbooks", type_="foreignkey")
    for col in ("created_by", "notify", "origin", "sha256"):
        op.drop_column("playbooks", col)
