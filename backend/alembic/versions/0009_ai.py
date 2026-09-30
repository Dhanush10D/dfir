"""Phase 7: AI layer (provenance, review, RAG index freshness, per-case AI switch) and grants.

ai_interactions
- ``status`` (valid|invalid|refused|error), ``model_served``, ``prompt_sha256``,
  ``input_sha256``, ``output_sha256``, ``prompt_text`` (redacted user message as sent),
  ``warnings``, ``error``, ``started_at``, ``reviewed_by``, ``reviewed_at``, ``review_note``;
  CHECKs on status, feedback and review completeness; indexes (case_id, created_at) and
  (user_id, created_at).
- trigger ``ai_interactions_guard``: a review is final (``accepted`` set once) and only a
  ``valid`` interaction can be accepted or rejected, even for direct SQL.

event_chunks
- ``host``, ``ts_start``, ``ts_end``, ``embedding_model``, ``content_sha256``; index (case_id).

ai_index_state
- one row per case: event count and newest ``ingested_at`` when the index was built.

cases
- ``ai_enabled`` (default true).

Privileges for ``dfirbench_app``:
- ai_interactions: SELECT, INSERT, UPDATE (accepted, reviewed_by, reviewed_at, review_note,
  feedback). No DELETE/TRUNCATE: the AI audit trail is kept.
- event_chunks: SELECT, INSERT, DELETE (rebuilt per case). No UPDATE/TRUNCATE.
- ai_index_state: SELECT, INSERT, UPDATE. No DELETE/TRUNCATE.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-30 09:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
STATUSES = "('valid','invalid','refused','error')"
REVIEW_COLUMNS = "accepted, reviewed_by, reviewed_at, review_note, feedback"

GUARD_FN = """
CREATE FUNCTION ai_interactions_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.accepted IS NOT NULL AND (
       NEW.accepted IS DISTINCT FROM OLD.accepted
       OR NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by
       OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at
       OR NEW.review_note IS DISTINCT FROM OLD.review_note) THEN
    RAISE EXCEPTION 'ai interaction % was already reviewed', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.accepted IS NULL AND NEW.accepted IS NOT NULL AND OLD.status <> 'valid' THEN
    RAISE EXCEPTION 'ai interaction % is not valid and cannot be reviewed', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""


def _tstz(name: str, **kw: object) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.DateTime(timezone=True), **kw)  # type: ignore[arg-type]


def upgrade() -> None:
    # ---- ai_interactions
    op.add_column(
        "ai_interactions",
        sa.Column("status", sa.Text(), server_default=sa.text("'valid'"), nullable=False),
    )
    op.add_column("ai_interactions", sa.Column("model_served", sa.Text(), nullable=True))
    for col in ("prompt_sha256", "input_sha256", "output_sha256"):
        op.add_column("ai_interactions", sa.Column(col, sa.CHAR(64), nullable=True))
    op.add_column("ai_interactions", sa.Column("prompt_text", sa.Text(), nullable=True))
    op.add_column(
        "ai_interactions",
        sa.Column(
            "warnings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("ai_interactions", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("ai_interactions", _tstz("started_at", nullable=True))
    op.add_column("ai_interactions", sa.Column("reviewed_by", sa.UUID(), nullable=True))
    op.add_column("ai_interactions", _tstz("reviewed_at", nullable=True))
    op.add_column("ai_interactions", sa.Column("review_note", sa.Text(), nullable=True))
    op.create_foreign_key(
        op.f("fk_ai_interactions_reviewed_by_users"),
        "ai_interactions",
        "users",
        ["reviewed_by"],
        ["id"],
    )
    op.create_check_constraint("status", "ai_interactions", f"status IN {STATUSES}")
    op.create_check_constraint(
        "feedback", "ai_interactions", "feedback IS NULL OR feedback IN (-1, 0, 1)"
    )
    op.create_check_constraint(
        "review_complete",
        "ai_interactions",
        "accepted IS NULL OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)",
    )
    op.create_index(
        "ix_ai_interactions_case_id_created_at", "ai_interactions", ["case_id", "created_at"]
    )
    op.create_index(
        "ix_ai_interactions_user_id_created_at", "ai_interactions", ["user_id", "created_at"]
    )
    op.execute(GUARD_FN)
    op.execute(
        "CREATE TRIGGER ai_interactions_guard BEFORE UPDATE ON ai_interactions "
        "FOR EACH ROW EXECUTE FUNCTION ai_interactions_guard()"
    )

    # ---- event_chunks
    op.add_column("event_chunks", sa.Column("host", sa.Text(), nullable=True))
    op.add_column("event_chunks", _tstz("ts_start", nullable=True))
    op.add_column("event_chunks", _tstz("ts_end", nullable=True))
    op.add_column("event_chunks", sa.Column("embedding_model", sa.Text(), nullable=True))
    op.add_column("event_chunks", sa.Column("content_sha256", sa.CHAR(64), nullable=True))
    op.create_index("ix_event_chunks_case_id", "event_chunks", ["case_id"])

    # ---- ai_index_state
    op.create_table(
        "ai_index_state",
        sa.Column("case_id", sa.UUID(), nullable=False),
        _tstz("built_at", nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        _tstz("max_ingested_at", nullable=True),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("embedding_model", sa.Text(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_ai_index_state_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_ai_index_state")),
    )

    # ---- cases
    op.add_column(
        "cases",
        sa.Column("ai_enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
    )

    # ---- grants
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON ai_interactions FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({REVIEW_COLUMNS}) ON ai_interactions TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, TRUNCATE ON event_chunks FROM {APP_ROLE}")
    op.execute(f"REVOKE ALL ON ai_index_state FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ai_index_state TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"GRANT UPDATE ON event_chunks TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE ({REVIEW_COLUMNS}) ON ai_interactions FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON ai_interactions TO {APP_ROLE}")
    op.drop_column("cases", "ai_enabled")
    op.drop_table("ai_index_state")
    op.drop_index("ix_event_chunks_case_id", table_name="event_chunks")
    for col in ("content_sha256", "embedding_model", "ts_end", "ts_start", "host"):
        op.drop_column("event_chunks", col)
    op.execute("DROP TRIGGER IF EXISTS ai_interactions_guard ON ai_interactions")
    op.execute("DROP FUNCTION IF EXISTS ai_interactions_guard()")
    # Downgrade-only fix (Phase 7 review): the reviewer columns are dropped below, so a review
    # cannot be kept; clearing ``accepted`` lets a later upgrade add ``review_complete`` again.
    op.execute("UPDATE ai_interactions SET accepted = NULL WHERE accepted IS NOT NULL")
    op.drop_index("ix_ai_interactions_user_id_created_at", table_name="ai_interactions")
    op.drop_index("ix_ai_interactions_case_id_created_at", table_name="ai_interactions")
    for ck in ("review_complete", "feedback", "status"):
        op.drop_constraint(op.f(f"ck_ai_interactions_{ck}"), "ai_interactions", type_="check")
    op.drop_constraint(
        op.f("fk_ai_interactions_reviewed_by_users"), "ai_interactions", type_="foreignkey"
    )
    for col in (
        "review_note",
        "reviewed_at",
        "reviewed_by",
        "started_at",
        "error",
        "warnings",
        "prompt_text",
        "output_sha256",
        "input_sha256",
        "prompt_sha256",
        "model_served",
        "status",
    ):
        op.drop_column("ai_interactions", col)
