"""Phase 4: analysis (versioned notes, bookmarks, entity resolution) and least-privilege grants.

notes
- ``version``, ``updated_at``, ``updated_by``, ``retracted_at``, ``retracted_by``; CHECKs on
  target_type and version; index ``(case_id, created_at)``.
- ``note_versions``: every version of every note (append-only: forbid_mutation trigger and
  SELECT/INSERT grants). Notes are forensic records: never deleted, only retracted.

bookmarks
- UNIQUE ``(case_id, user_id, target_type, target_id)`` (idempotent create), CHECK target_type.

entities / entity_links
- entities: ``event_count``, ``updated_at``, ``last_job_id``, CHECK type, index (case_id, type).
- entity_links: ``first_seen``, ``last_seen``, UNIQUE (case_id, src, dst, relation) so
  resolution upserts aggregate edges, CHECK relation, index (case_id, dst_entity).

Privileges for ``dfirbench_app`` (default privileges from 0002 would grant full DML):
- notes: SELECT, INSERT, UPDATE of the head columns only (no DELETE).
- note_versions: SELECT, INSERT.
- bookmarks: SELECT, INSERT, DELETE (no UPDATE).
- entities, entity_links: SELECT, INSERT, UPDATE (no DELETE).
- entity_aliases: SELECT, INSERT.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-29 20:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
TARGETS = "('case','event','alert','evidence','entity')"
ENTITY_TYPES = "('host','user','ip','process','hash','domain','file')"
RELATIONS = "('logged_on','failed_logon','seen_on','connected_to','executed','ran_on','has_hash')"
NOTE_HEAD = "body_md, tags, version, updated_at, updated_by, retracted_at, retracted_by"


def _tstz(name: str, **kw: object) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.DateTime(timezone=True), **kw)  # type: ignore[arg-type]


def upgrade() -> None:
    # ---- notes + versions
    op.add_column(
        "notes", sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False)
    )
    op.add_column("notes", _tstz("updated_at", server_default=sa.text("now()"), nullable=False))
    op.add_column("notes", sa.Column("updated_by", sa.UUID(), nullable=True))
    op.add_column("notes", _tstz("retracted_at", nullable=True))
    op.add_column("notes", sa.Column("retracted_by", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_notes_updated_by_users"), "notes", "users", ["updated_by"], ["id"]
    )
    op.create_foreign_key(
        op.f("fk_notes_retracted_by_users"), "notes", "users", ["retracted_by"], ["id"]
    )
    op.create_check_constraint(
        "target_type", "notes", f"target_type IS NULL OR target_type IN {TARGETS}"
    )
    op.create_check_constraint("version_positive", "notes", "version >= 1")
    op.create_index("ix_notes_case_id_created_at", "notes", ["case_id", "created_at"])
    op.create_table(
        "note_versions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("note_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("body_md", sa.Text(), nullable=False),
        sa.Column(
            "tags",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        _tstz("created_at", server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "action IN ('created','edited','retracted')", name=op.f("ck_note_versions_action")
        ),
        sa.ForeignKeyConstraint(
            ["note_id"], ["notes.id"], name=op.f("fk_note_versions_note_id_notes")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_note_versions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_note_versions")),
        sa.UniqueConstraint("note_id", "version", name=op.f("uq_note_versions_note_id_version")),
    )
    # Existing notes (if any) get their version-1 history row.
    op.execute(
        "INSERT INTO note_versions (note_id, version, action, body_md, tags, user_id, created_at) "
        "SELECT id, 1, 'created', body_md, tags, author_id, created_at FROM notes"
    )

    # ---- bookmarks
    op.execute(
        "DELETE FROM bookmarks b USING bookmarks o WHERE b.case_id = o.case_id "
        "AND b.user_id = o.user_id AND b.target_type = o.target_type "
        "AND b.target_id = o.target_id AND b.id > o.id"
    )
    op.create_unique_constraint(
        op.f("uq_bookmarks_case_id_user_id_target_type_target_id"),
        "bookmarks",
        ["case_id", "user_id", "target_type", "target_id"],
    )
    op.create_check_constraint("target_type", "bookmarks", f"target_type IN {TARGETS}")

    # ---- entities
    op.add_column(
        "entities",
        sa.Column("event_count", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("entities", _tstz("updated_at", server_default=sa.text("now()"), nullable=False))
    op.add_column("entities", sa.Column("last_job_id", sa.UUID(), nullable=True))
    op.create_foreign_key(
        op.f("fk_entities_last_job_id_jobs"), "entities", "jobs", ["last_job_id"], ["id"]
    )
    op.create_check_constraint("type", "entities", f"type IN {ENTITY_TYPES}")
    op.create_index("ix_entities_case_id_type", "entities", ["case_id", "type"])
    op.add_column("entity_links", _tstz("first_seen", nullable=True))
    op.add_column("entity_links", _tstz("last_seen", nullable=True))
    op.create_unique_constraint(
        op.f("uq_entity_links_case_id_src_entity_dst_entity_relation"),
        "entity_links",
        ["case_id", "src_entity", "dst_entity", "relation"],
    )
    op.create_check_constraint("relation", "entity_links", f"relation IN {RELATIONS}")
    op.create_index("ix_entity_links_case_id_dst_entity", "entity_links", ["case_id", "dst_entity"])

    # ---- append-only trigger and grants
    op.execute(
        "CREATE TRIGGER note_versions_no_update BEFORE UPDATE OR DELETE OR TRUNCATE "
        "ON note_versions FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()"
    )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON notes FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE ({NOTE_HEAD}) ON notes TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON note_versions FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON note_versions TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, TRUNCATE ON bookmarks FROM {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON entities FROM {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON entity_links FROM {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON entity_aliases FROM {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"GRANT UPDATE, DELETE ON entity_aliases TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON entity_links TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON entities TO {APP_ROLE}")
    op.execute(f"GRANT UPDATE ON bookmarks TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE ({NOTE_HEAD}) ON notes FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON notes TO {APP_ROLE}")
    op.execute("DROP TRIGGER IF EXISTS note_versions_no_update ON note_versions")
    op.drop_index("ix_entity_links_case_id_dst_entity", table_name="entity_links")
    op.drop_constraint(op.f("ck_entity_links_relation"), "entity_links", type_="check")
    op.drop_constraint(
        op.f("uq_entity_links_case_id_src_entity_dst_entity_relation"),
        "entity_links",
        type_="unique",
    )
    op.drop_column("entity_links", "last_seen")
    op.drop_column("entity_links", "first_seen")
    op.drop_index("ix_entities_case_id_type", table_name="entities")
    op.drop_constraint(op.f("ck_entities_type"), "entities", type_="check")
    op.drop_constraint(op.f("fk_entities_last_job_id_jobs"), "entities", type_="foreignkey")
    op.drop_column("entities", "last_job_id")
    op.drop_column("entities", "updated_at")
    op.drop_column("entities", "event_count")
    op.drop_constraint(op.f("ck_bookmarks_target_type"), "bookmarks", type_="check")
    op.drop_constraint(
        op.f("uq_bookmarks_case_id_user_id_target_type_target_id"), "bookmarks", type_="unique"
    )
    op.drop_table("note_versions")
    op.drop_index("ix_notes_case_id_created_at", table_name="notes")
    op.drop_constraint(op.f("ck_notes_version_positive"), "notes", type_="check")
    op.drop_constraint(op.f("ck_notes_target_type"), "notes", type_="check")
    op.drop_constraint(op.f("fk_notes_retracted_by_users"), "notes", type_="foreignkey")
    op.drop_constraint(op.f("fk_notes_updated_by_users"), "notes", type_="foreignkey")
    for column in ("retracted_by", "retracted_at", "updated_by", "updated_at", "version"):
        op.drop_column("notes", column)
