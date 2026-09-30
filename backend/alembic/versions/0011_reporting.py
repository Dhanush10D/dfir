"""Phase 8: reporting (versioned report families, sections/findings, QA, seal) and grants.

reports
- ``title``, ``family_id`` (id of version 1), ``supersedes_id``, ``revision`` (edit counter for
  optimistic concurrency), ``sections``, ``findings``, ``context_sha256``, ``qa``, ``updated_at``,
  ``updated_by``, ``submitted_by/at``, ``approved_at``, ``signed_by``, ``signed_at``, ``key_id``,
  ``manifest``; CHECKs on kind and status, a signed row carries its seal; UNIQUE (family_id,
  version); index (case_id, created_at).
- CHECKs ``submitted`` (a non-draft row names its submitter) and ``four_eyes`` (an approved or
  signed row names an approver other than the submitter).
- trigger ``reports_guard`` (BEFORE INSERT OR UPDATE): a new row is an unreviewed draft; identity
  and snapshot columns are immutable; sections, findings and title change only while ``draft``;
  status moves only along draft -> in_review -> approved -> signed (and back to draft from
  in_review/approved); the submitter columns change only on submit or return, the approver columns
  only on approve (someone other than the recorded submitter) or return, the seal/signer columns
  only on sign (which needs a four-eyes approval and a signer); a ``signed`` row is frozen.

Privileges for ``dfirbench_app``: reports SELECT, INSERT, and UPDATE of the workflow columns only
(no UPDATE of identity/snapshot columns, no DELETE/TRUNCATE).

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-30 19:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
KINDS = "('technical','executive','custody','ioc')"
STATUSES = "('draft','in_review','approved','signed')"
# Columns the app may UPDATE (workflow + content); identity/snapshot columns are not listed.
UPDATE_COLUMNS = (
    "title, revision, sections, findings, qa, updated_at, updated_by, status, submitted_by, "
    "submitted_at, approved_by, approved_at, signed_by, signed_at, key_id, manifest, "
    "storage_uri, sha256, signature"
)

SUBMITTED_CHECK = "status = 'draft' OR (submitted_by IS NOT NULL AND submitted_at IS NOT NULL)"
FOUR_EYES_CHECK = (
    "status NOT IN ('approved','signed') OR (approved_by IS NOT NULL AND approved_at IS NOT NULL "
    "AND approved_by <> submitted_by)"
)
# Columns of the pre-0011 table that record a review or a seal (used by upgrade and downgrade).
RESET_TO_DRAFT = (
    "UPDATE reports SET status = 'draft', approved_by = NULL, storage_uri = NULL, "
    "sha256 = NULL, signature = NULL WHERE status <> 'draft' OR approved_by IS NOT NULL "
    "OR storage_uri IS NOT NULL OR sha256 IS NOT NULL OR signature IS NOT NULL"
)

GUARD_FN = """
CREATE FUNCTION reports_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  sub_changed boolean;
  appr_changed boolean;
  seal_changed boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'draft' OR NEW.submitted_by IS NOT NULL OR NEW.submitted_at IS NOT NULL
       OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL
       OR NEW.signed_by IS NOT NULL OR NEW.signed_at IS NOT NULL OR NEW.key_id IS NOT NULL
       OR NEW.manifest IS NOT NULL OR NEW.signature IS NOT NULL OR NEW.sha256 IS NOT NULL
       OR NEW.storage_uri IS NOT NULL OR NEW.qa IS NOT NULL THEN
      RAISE EXCEPTION 'a new report must be an unreviewed draft'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'signed' THEN
    RAISE EXCEPTION 'report % is signed and cannot change', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.family_id IS DISTINCT FROM OLD.family_id
     OR NEW.supersedes_id IS DISTINCT FROM OLD.supersedes_id
     OR NEW.context_sha256 IS DISTINCT FROM OLD.context_sha256
     OR NEW.created_by IS DISTINCT FROM OLD.created_by
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.context IS DISTINCT FROM OLD.context THEN
    RAISE EXCEPTION 'report % identity and snapshot are immutable', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.status <> 'draft' AND (
       NEW.sections IS DISTINCT FROM OLD.sections
       OR NEW.findings IS DISTINCT FROM OLD.findings
       OR NEW.title IS DISTINCT FROM OLD.title) THEN
    RAISE EXCEPTION 'report % content can only change in draft', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  sub_changed := NEW.submitted_by IS DISTINCT FROM OLD.submitted_by
                 OR NEW.submitted_at IS DISTINCT FROM OLD.submitted_at;
  appr_changed := NEW.approved_by IS DISTINCT FROM OLD.approved_by
                  OR NEW.approved_at IS DISTINCT FROM OLD.approved_at;
  seal_changed := NEW.signed_by IS DISTINCT FROM OLD.signed_by
                  OR NEW.signed_at IS DISTINCT FROM OLD.signed_at
                  OR NEW.key_id IS DISTINCT FROM OLD.key_id
                  OR NEW.manifest IS DISTINCT FROM OLD.manifest
                  OR NEW.storage_uri IS DISTINCT FROM OLD.storage_uri
                  OR NEW.sha256 IS DISTINCT FROM OLD.sha256
                  OR NEW.signature IS DISTINCT FROM OLD.signature;
  IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
    IF sub_changed OR appr_changed OR seal_changed THEN
      RAISE EXCEPTION 'report % review and seal columns change only with a lifecycle transition',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status = 'draft' AND NEW.status = 'in_review' THEN
    IF NEW.submitted_by IS NULL OR NEW.submitted_at IS NULL OR appr_changed OR seal_changed
       OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL THEN
      RAISE EXCEPTION 'report % submit must record only the submitter', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'in_review' AND NEW.status = 'approved' THEN
    IF sub_changed OR seal_changed OR OLD.submitted_by IS NULL
       OR NEW.approved_by IS NULL OR NEW.approved_at IS NULL
       OR NEW.approved_by = OLD.submitted_by THEN
      RAISE EXCEPTION 'report % must be approved by someone other than the submitter', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status = 'approved' AND NEW.status = 'signed' THEN
    IF sub_changed OR appr_changed OR OLD.submitted_by IS NULL OR OLD.approved_by IS NULL
       OR OLD.approved_by = OLD.submitted_by OR NEW.signed_by IS NULL THEN
      RAISE EXCEPTION 'report % can only be signed by a named signer after a four-eyes approval',
        OLD.id USING ERRCODE = 'check_violation';
    END IF;
  ELSIF OLD.status IN ('in_review', 'approved') AND NEW.status = 'draft' THEN
    IF seal_changed OR NEW.submitted_by IS NOT NULL OR NEW.submitted_at IS NOT NULL
       OR NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL THEN
      RAISE EXCEPTION 'report % returned to draft must clear its review', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
  ELSE
    RAISE EXCEPTION 'report % cannot move from % to %', OLD.id, OLD.status, NEW.status
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$
"""


def _tstz(name: str, **kw: object) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.DateTime(timezone=True), **kw)  # type: ignore[arg-type]


def upgrade() -> None:
    op.add_column(
        "reports", sa.Column("title", sa.Text(), server_default=sa.text("''"), nullable=False)
    )
    op.add_column("reports", sa.Column("family_id", sa.UUID(), nullable=True))
    op.add_column("reports", sa.Column("supersedes_id", sa.UUID(), nullable=True))
    op.add_column(
        "reports", sa.Column("revision", sa.Integer(), server_default=sa.text("0"), nullable=False)
    )
    op.add_column(
        "reports",
        sa.Column(
            "sections",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "reports",
        sa.Column(
            "findings",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("reports", sa.Column("context_sha256", sa.CHAR(64), nullable=True))
    op.add_column(
        "reports", sa.Column("qa", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    op.add_column("reports", _tstz("updated_at", server_default=sa.text("now()"), nullable=False))
    op.add_column("reports", sa.Column("updated_by", sa.UUID(), nullable=True))
    op.add_column("reports", sa.Column("submitted_by", sa.UUID(), nullable=True))
    op.add_column("reports", _tstz("submitted_at", nullable=True))
    op.add_column("reports", _tstz("approved_at", nullable=True))
    op.add_column("reports", sa.Column("signed_by", sa.UUID(), nullable=True))
    op.add_column("reports", _tstz("signed_at", nullable=True))
    op.add_column("reports", sa.Column("key_id", sa.Text(), nullable=True))
    op.add_column(
        "reports", sa.Column("manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=True)
    )
    # Rows from before this revision (if any) become their own family, hashed as stored. No
    # earlier code wrote reports, but a row in any other state could not show who submitted or
    # approved it, so it starts over as an unsealed draft (the same rule as the downgrade).
    op.execute(
        "UPDATE reports SET family_id = id, "
        "context_sha256 = encode(digest(context::text, 'sha256'), 'hex')"
    )
    op.execute(RESET_TO_DRAFT)
    op.alter_column("reports", "family_id", nullable=False)
    op.alter_column("reports", "context_sha256", nullable=False)
    for col in ("updated_by", "submitted_by", "signed_by"):
        op.create_foreign_key(op.f(f"fk_reports_{col}_users"), "reports", "users", [col], ["id"])
    op.create_foreign_key(
        op.f("fk_reports_supersedes_id_reports"), "reports", "reports", ["supersedes_id"], ["id"]
    )
    op.create_check_constraint("kind", "reports", f"kind IN {KINDS}")
    op.create_check_constraint("status", "reports", f"status IN {STATUSES}")
    op.create_check_constraint(
        "signed_sealed",
        "reports",
        "status <> 'signed' OR (sha256 IS NOT NULL AND signature IS NOT NULL "
        "AND manifest IS NOT NULL AND key_id IS NOT NULL AND signed_at IS NOT NULL)",
    )
    op.create_check_constraint("submitted", "reports", SUBMITTED_CHECK)
    op.create_check_constraint("four_eyes", "reports", FOUR_EYES_CHECK)
    op.create_unique_constraint(
        op.f("uq_reports_family_id_version"), "reports", ["family_id", "version"]
    )
    op.create_index("ix_reports_case_id_created_at", "reports", ["case_id", "created_at"])
    op.execute(GUARD_FN)
    op.execute(
        "CREATE TRIGGER reports_guard BEFORE INSERT OR UPDATE ON reports "
        "FOR EACH ROW EXECUTE FUNCTION reports_guard()"
    )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON reports FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({UPDATE_COLUMNS}) ON reports TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE UPDATE ({UPDATE_COLUMNS}) ON reports FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON reports TO {APP_ROLE}")
    op.execute("DROP TRIGGER IF EXISTS reports_guard ON reports")
    op.execute("DROP FUNCTION IF EXISTS reports_guard()")
    # Downgrade-only: the review trail (submitter, approval time) and the seal (manifest, key id,
    # signing time) are dropped below, so a reviewed or signed state cannot be kept. Leaving it
    # would let a later upgrade fail ``signed_sealed`` or skip the four-eyes check (submitter
    # unknown), so every report goes back to an unreviewed, unsealed draft. Rendered artifacts
    # already in object storage are not touched.
    op.execute(RESET_TO_DRAFT)
    op.drop_index("ix_reports_case_id_created_at", table_name="reports")
    op.drop_constraint(op.f("uq_reports_family_id_version"), "reports", type_="unique")
    op.drop_constraint(op.f("ck_reports_four_eyes"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_submitted"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_signed_sealed"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_status"), "reports", type_="check")
    op.drop_constraint(op.f("ck_reports_kind"), "reports", type_="check")
    op.drop_constraint(op.f("fk_reports_supersedes_id_reports"), "reports", type_="foreignkey")
    for col in ("updated_by", "submitted_by", "signed_by"):
        op.drop_constraint(op.f(f"fk_reports_{col}_users"), "reports", type_="foreignkey")
    for col in (
        "manifest",
        "key_id",
        "signed_at",
        "signed_by",
        "approved_at",
        "submitted_at",
        "submitted_by",
        "updated_by",
        "updated_at",
        "qa",
        "context_sha256",
        "findings",
        "sections",
        "revision",
        "supersedes_id",
        "family_id",
        "title",
    ):
        op.drop_column("reports", col)
