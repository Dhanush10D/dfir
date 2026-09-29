"""Phase 5: collection (triage bundle ingest, derived evidence) and least-privilege grants.

evidence
- ``parent_evidence_id`` (FK evidence, RESTRICT, index): a derived item (bundle member) points to
  the bundle it came from. Written once at insert.

bundle_members
- verification record per member per run attempt (statuses, manifest vs actual SHA-256, derived
  evidence, parse job); UNIQUE (job_id, attempt, member_path); append-only (forbid_mutation
  trigger + SELECT/INSERT grants).

jobs
- ``uq_jobs_active_bundle``: one queued/running bundle ingest per evidence item.

Privileges for ``dfirbench_app``:
- bundle_members: SELECT, INSERT.
- evidence: no DELETE/TRUNCATE (originals and their records are never deleted) and UPDATE only on
  the columns the upload -> finalize -> verify flow writes. ``parent_evidence_id``, ``case_id``,
  ``storage_uri``, ``label`` and the acquisition fields are immutable for the app.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-30 00:30:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
STATUSES = "('ingested','verified','hash_mismatch','size_mismatch','missing','unlisted','corrupt')"
EVIDENCE_UPDATABLE = "sha256, md5, size_bytes, storage_version_id, mime_type, status, retain_until"
ACTIVE_BUNDLE = "kind = 'bundle' AND status IN ('queued', 'running')"


def upgrade() -> None:
    op.add_column("evidence", sa.Column("parent_evidence_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_evidence_parent_evidence_id_evidence"),
        "evidence",
        "evidence",
        ["parent_evidence_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_evidence_parent_evidence_id", "evidence", ["parent_evidence_id"])

    op.create_table(
        "bundle_members",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("bundle_evidence_id", sa.UUID(), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("member_path", sa.Text(), nullable=False),
        sa.Column("member_index", sa.Integer(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256_manifest", sa.CHAR(64), nullable=True),
        sa.Column("sha256_actual", sa.CHAR(64), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("parser", sa.Text(), nullable=True),
        sa.Column("derived_evidence_id", sa.UUID(), nullable=True),
        sa.Column("parse_job_id", sa.UUID(), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(f"status IN {STATUSES}", name=op.f("ck_bundle_members_status")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_bundle_members_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["bundle_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_bundle_members_bundle_evidence_id_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["jobs.id"], name=op.f("fk_bundle_members_job_id_jobs")
        ),
        sa.ForeignKeyConstraint(
            ["derived_evidence_id"],
            ["evidence.id"],
            name=op.f("fk_bundle_members_derived_evidence_id_evidence"),
        ),
        sa.ForeignKeyConstraint(
            ["parse_job_id"], ["jobs.id"], name=op.f("fk_bundle_members_parse_job_id_jobs")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_bundle_members")),
        sa.UniqueConstraint(
            "job_id",
            "attempt",
            "member_path",
            name=op.f("uq_bundle_members_job_id_attempt_member_path"),
        ),
    )
    op.create_index(
        "ix_bundle_members_bundle_evidence_id_member_path",
        "bundle_members",
        ["bundle_evidence_id", "member_path"],
    )
    op.create_index(
        "uq_jobs_active_bundle",
        "jobs",
        ["evidence_id"],
        unique=True,
        postgresql_where=sa.text(ACTIVE_BUNDLE),
    )

    op.execute(
        "CREATE TRIGGER bundle_members_no_update BEFORE UPDATE OR DELETE OR TRUNCATE "
        "ON bundle_members FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()"
    )
    op.execute(f"REVOKE ALL ON bundle_members FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON bundle_members TO {APP_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON SEQUENCE bundle_members_id_seq TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON evidence FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({EVIDENCE_UPDATABLE}) ON evidence TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE UPDATE ({EVIDENCE_UPDATABLE}) ON evidence FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON evidence TO {APP_ROLE}")
    op.execute("DROP TRIGGER IF EXISTS bundle_members_no_update ON bundle_members")
    op.drop_index(
        "uq_jobs_active_bundle", table_name="jobs", postgresql_where=sa.text(ACTIVE_BUNDLE)
    )
    op.drop_index("ix_bundle_members_bundle_evidence_id_member_path", table_name="bundle_members")
    op.drop_table("bundle_members")
    op.drop_index("ix_evidence_parent_evidence_id", table_name="evidence")
    op.drop_constraint(
        op.f("fk_evidence_parent_evidence_id_evidence"), "evidence", type_="foreignkey"
    )
    op.drop_column("evidence", "parent_evidence_id")
