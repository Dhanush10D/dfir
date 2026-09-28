"""Phase 1: IAM (refresh tokens, recovery codes, API key lookup), evidence upload columns, audit
indexes, and the least-privilege application role.

Role ``dfirbench_app`` (NOLOGIN, cluster-wide, created if missing): the API and workers run every
session as it (``DATABASE_APP_ROLE``, applied with ``SET ROLE`` at connect). It may read and write
ordinary tables but only SELECT and INSERT on the append-only ``custody_log`` and ``audit_log``
(guide 7.2, 8.3 rule 2, 20.2). Default privileges extend the grants to tables and sequences the
migration owner creates later (e.g. monthly ``events`` partitions); any future append-only table
must REVOKE explicitly.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28 13:25:06+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


APP_ROLE = "dfirbench_app"
APPEND_ONLY_TABLES = ("custody_log", "audit_log")

CREATE_ROLE = f"""
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    CREATE ROLE {APP_ROLE} NOLOGIN;
  END IF;
END
$$;
"""

GRANTS = [
    f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}",
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}",
    f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}",
    f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {APP_ROLE}",
    *[
        f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM {APP_ROLE}"
        for table in APPEND_ONLY_TABLES
    ],
    f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON alembic_version FROM {APP_ROLE}",
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}",
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}",
]

REVOKES = [
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM {APP_ROLE}",
    f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
    f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {APP_ROLE}",
    f"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM {APP_ROLE}",
    f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {APP_ROLE}",
    f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {APP_ROLE}",
    f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE}",
]


def upgrade() -> None:
    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("code_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_mfa_recovery_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_codes")),
    )
    op.create_index(
        op.f("ix_mfa_recovery_codes_user_id"), "mfa_recovery_codes", ["user_id"], unique=False
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("family_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.CHAR(length=64), nullable=False),
        sa.Column(
            "issued_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("session_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.Text(), nullable=True),
        sa.Column("replaced_by", sa.UUID(), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_refresh_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(
        op.f("ix_refresh_tokens_family_id"), "refresh_tokens", ["family_id"], unique=False
    )
    op.create_index(op.f("ix_refresh_tokens_user_id"), "refresh_tokens", ["user_id"], unique=False)
    op.add_column("api_keys", sa.Column("key_prefix", sa.Text(), nullable=True))
    op.add_column("api_keys", sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"], unique=False)
    op.create_index("ix_audit_log_user_id_ts", "audit_log", ["user_id", "ts"], unique=False)
    op.create_index("ix_case_members_user_id", "case_members", ["user_id"], unique=False)
    op.add_column("evidence", sa.Column("expected_sha256", sa.CHAR(length=64), nullable=True))
    op.add_column("evidence", sa.Column("expected_md5", sa.CHAR(length=32), nullable=True))
    op.add_column("evidence", sa.Column("storage_version_id", sa.Text(), nullable=True))
    op.add_column("evidence", sa.Column("retain_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger(), nullable=True))

    op.execute(CREATE_ROLE)
    for statement in GRANTS:
        op.execute(statement)


def downgrade() -> None:
    # The role is cluster-wide (other databases may use it); only this database's grants go.
    for statement in REVOKES:
        op.execute(statement)
    op.drop_column("users", "totp_last_step")
    op.drop_column("evidence", "retain_until")
    op.drop_column("evidence", "storage_version_id")
    op.drop_column("evidence", "expected_md5")
    op.drop_column("evidence", "expected_sha256")
    op.drop_index("ix_case_members_user_id", table_name="case_members")
    op.drop_index("ix_audit_log_user_id_ts", table_name="audit_log")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_index(op.f("ix_api_keys_key_hash"), table_name="api_keys")
    op.drop_column("api_keys", "last_used_at")
    op.drop_column("api_keys", "key_prefix")
    op.drop_index(op.f("ix_refresh_tokens_user_id"), table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_family_id"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index(op.f("ix_mfa_recovery_codes_user_id"), table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")
