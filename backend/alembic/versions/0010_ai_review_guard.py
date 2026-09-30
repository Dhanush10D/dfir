"""Phase 7 review fix: the AI review guard also covers INSERT.

0009's ``ai_interactions_guard`` ran only BEFORE UPDATE, but the app role may INSERT, so a row
could be created already "accepted". Now:

- the trigger runs BEFORE INSERT OR UPDATE; an inserted row must be unreviewed (``accepted``,
  ``reviewed_by``, ``reviewed_at``, ``review_note`` and ``feedback`` all NULL);
- CHECK ``accepted IS NULL OR status = 'valid'`` (only validated output can carry a review).

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-30 18:00:00+00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GUARD_FN = """
CREATE OR REPLACE FUNCTION ai_interactions_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.accepted IS NOT NULL OR NEW.reviewed_by IS NOT NULL OR NEW.reviewed_at IS NOT NULL
       OR NEW.review_note IS NOT NULL OR NEW.feedback IS NOT NULL THEN
      RAISE EXCEPTION 'a new ai interaction cannot already be reviewed'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
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

UPDATE_ONLY_FN = """
CREATE OR REPLACE FUNCTION ai_interactions_guard() RETURNS trigger
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


def upgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS ai_interactions_guard ON ai_interactions")
    op.execute(GUARD_FN)
    op.execute(
        "CREATE TRIGGER ai_interactions_guard BEFORE INSERT OR UPDATE ON ai_interactions "
        "FOR EACH ROW EXECUTE FUNCTION ai_interactions_guard()"
    )
    op.create_check_constraint(
        "accepted_valid", "ai_interactions", "accepted IS NULL OR status = 'valid'"
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_ai_interactions_accepted_valid"), "ai_interactions", type_="check")
    op.execute("DROP TRIGGER IF EXISTS ai_interactions_guard ON ai_interactions")
    op.execute(UPDATE_ONLY_FN)
    op.execute(
        "CREATE TRIGGER ai_interactions_guard BEFORE UPDATE ON ai_interactions "
        "FOR EACH ROW EXECUTE FUNCTION ai_interactions_guard()"
    )
