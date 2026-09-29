"""Phase 3: detection (rule versions, alert lifecycle, IOC columns, detect-job coalescing) and
least-privilege grants.

rules
- ``status``, ``kind``, ``confidence``, ``sha256``, ``created_by``, ``created_at``; CHECKs on
  origin/kind/confidence. ``rule_versions`` keeps every version (append-only): run manifests cite
  (rule id, version, sha256), so any alert can be traced to the exact rule text that produced it.

alerts
- ``dedup_key`` becomes NOT NULL, so ``UNIQUE (case_id, dedup_key)`` really deduplicates
  (NULLs are distinct in a UNIQUE constraint). Detection upserts with ``ON CONFLICT``.
- ``rule_version``, ``details``, ``status_reason``, ``updated_at``, ``last_detected_at``,
  ``last_job_id``, ``stale``; indexes for the case alert list.
- ``alert_history``: append-only lifecycle (created / status / assign), with triggers.
- ``alert_events``: index on ``event_id``.

iocs
- ``value_original``, ``active``, ``created_by``, ``created_at``; UNIQUE (case_id, type, value)
  becomes NULLS NOT DISTINCT (global IOCs have case_id NULL); CHECKs on type, tlp, confidence.

jobs
- ``uq_jobs_queued_detect``: at most one queued detection job per case (requests coalesce).

Privileges for ``dfirbench_app`` (default privileges would grant full DML on the new tables):
- rules: SELECT, INSERT, UPDATE (no DELETE: disable instead; alerts reference rules).
- rule_versions, alert_history: SELECT, INSERT (plus forbid_mutation triggers).
- alerts: SELECT, INSERT, UPDATE (no DELETE).
- alert_events: SELECT, INSERT, UPDATE (event_ts) only.
- iocs: SELECT, INSERT, UPDATE (removing an IOC deactivates it).
- events: additionally UPDATE (attack_tags) only - ATT&CK tagging of matched events; every
  other column stays immutable for the app.

Never edit this file after it has been applied; add a new revision instead.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-29 18:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_ROLE = "dfirbench_app"
APPEND_ONLY = {
    "rule_versions": "rule_versions_no_update",
    "alert_history": "alert_history_no_update",
}
QUEUED_DETECT = "kind = 'detect' AND status = 'queued'"
ALERT_STATUS = postgresql.ENUM(
    "new",
    "triaged",
    "investigating",
    "true_positive",
    "false_positive",
    "closed",
    name="alert_status",
    create_type=False,
)
IOC_TYPES = "('ip','domain','url','sha256','sha1','md5','email','filename')"
TLP = "('clear','white','green','amber','amber+strict','red')"


def _tstz(name: str, **kw: object) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(name, sa.DateTime(timezone=True), **kw)  # type: ignore[arg-type]


def upgrade() -> None:
    # ---- rules + versions
    op.add_column(
        "rules",
        sa.Column("status", sa.Text(), server_default=sa.text("'experimental'"), nullable=False),
    )
    op.add_column(
        "rules", sa.Column("kind", sa.Text(), server_default=sa.text("'single'"), nullable=False)
    )
    op.add_column(
        "rules", sa.Column("confidence", sa.REAL(), server_default=sa.text("0.5"), nullable=False)
    )
    op.add_column("rules", sa.Column("sha256", sa.CHAR(length=64), nullable=True))
    op.add_column("rules", sa.Column("created_by", sa.UUID(), nullable=True))
    op.add_column("rules", _tstz("created_at", server_default=sa.text("now()"), nullable=False))
    op.create_foreign_key(
        op.f("fk_rules_created_by_users"), "rules", "users", ["created_by"], ["id"]
    )
    op.create_check_constraint("origin", "rules", "origin IN ('builtin','custom','sigma')")
    op.create_check_constraint(
        "kind", "rules", "kind IN ('single','threshold','sequence','detector')"
    )
    op.create_check_constraint("confidence_range", "rules", "confidence >= 0 AND confidence <= 1")
    op.create_table(
        "rule_versions",
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("raw_yaml", sa.Text(), nullable=False),
        sa.Column("source_text", sa.Text(), nullable=True),
        sa.Column("created_by", sa.UUID(), nullable=True),
        _tstz("created_at", server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_rule_versions_created_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"], ["rules.id"], name=op.f("fk_rule_versions_rule_id_rules")
        ),
        sa.PrimaryKeyConstraint("rule_id", "version", name=op.f("pk_rule_versions")),
    )

    # ---- alerts
    op.execute("UPDATE alerts SET dedup_key = 'legacy:' || id::text WHERE dedup_key IS NULL")
    op.alter_column("alerts", "dedup_key", existing_type=sa.Text(), nullable=False)
    op.add_column("alerts", sa.Column("rule_version", sa.Integer(), nullable=True))
    op.add_column(
        "alerts",
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column("alerts", sa.Column("status_reason", sa.Text(), nullable=True))
    op.add_column("alerts", _tstz("updated_at", server_default=sa.text("now()"), nullable=False))
    op.add_column("alerts", _tstz("last_detected_at", nullable=True))
    op.add_column("alerts", sa.Column("last_job_id", sa.UUID(), nullable=True))
    op.add_column(
        "alerts", sa.Column("stale", sa.Boolean(), server_default=sa.text("false"), nullable=False)
    )
    op.create_foreign_key(
        op.f("fk_alerts_last_job_id_jobs"), "alerts", "jobs", ["last_job_id"], ["id"]
    )
    op.create_index("ix_alerts_case_id_status", "alerts", ["case_id", "status"], unique=False)
    op.create_index("ix_alerts_case_id_last_seen", "alerts", ["case_id", "last_seen"], unique=False)
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"], unique=False)
    op.create_index("ix_alert_events_event_id", "alert_events", ["event_id"], unique=False)
    op.create_table(
        "alert_history",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=False),
        _tstz("ts", server_default=sa.text("now()"), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("from_status", ALERT_STATUS, nullable=True),
        sa.Column("to_status", ALERT_STATUS, nullable=True),
        sa.Column("from_assignee", sa.UUID(), nullable=True),
        sa.Column("to_assignee", sa.UUID(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["alert_id"], ["alerts.id"], name=op.f("fk_alert_history_alert_id_alerts")
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], name=op.f("fk_alert_history_job_id_jobs")),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_alert_history_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_history")),
    )
    op.create_index("ix_alert_history_alert_id", "alert_history", ["alert_id", "id"], unique=False)

    # ---- iocs
    op.add_column("iocs", sa.Column("value_original", sa.Text(), nullable=True))
    op.add_column(
        "iocs", sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False)
    )
    op.add_column("iocs", sa.Column("created_by", sa.UUID(), nullable=True))
    op.add_column("iocs", _tstz("created_at", server_default=sa.text("now()"), nullable=False))
    op.create_foreign_key(op.f("fk_iocs_created_by_users"), "iocs", "users", ["created_by"], ["id"])
    op.drop_constraint(op.f("uq_iocs_case_id_type_value"), "iocs", type_="unique")
    op.create_unique_constraint(
        op.f("uq_iocs_case_id_type_value"),
        "iocs",
        ["case_id", "type", "value"],
        postgresql_nulls_not_distinct=True,
    )
    op.create_check_constraint("type", "iocs", f"type IN {IOC_TYPES}")
    op.create_check_constraint("tlp", "iocs", f"tlp IS NULL OR tlp IN {TLP}")
    op.create_check_constraint(
        "confidence_range", "iocs", "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)"
    )

    # ---- jobs
    op.create_index(
        "uq_jobs_queued_detect",
        "jobs",
        ["case_id"],
        unique=True,
        postgresql_where=sa.text(QUEUED_DETECT),
    )

    # ---- append-only triggers and grants
    for table, trigger in APPEND_ONLY.items():
        op.execute(
            f"CREATE TRIGGER {trigger} BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} "
            "FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation()"
        )
    op.execute(f"REVOKE DELETE, TRUNCATE ON rules FROM {APP_ROLE}")
    op.execute(f"REVOKE ALL ON rule_versions FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON rule_versions TO {APP_ROLE}")
    op.execute(f"REVOKE ALL ON alert_history FROM {APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON alert_history TO {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON alerts FROM {APP_ROLE}")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON alert_events FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE (event_ts) ON alert_events TO {APP_ROLE}")
    op.execute(f"REVOKE DELETE, TRUNCATE ON iocs FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE (attack_tags) ON events TO {APP_ROLE}")


def downgrade() -> None:
    op.execute(f"REVOKE UPDATE (attack_tags) ON events FROM {APP_ROLE}")
    op.execute(f"GRANT DELETE ON iocs TO {APP_ROLE}")
    op.execute(f"REVOKE UPDATE (event_ts) ON alert_events FROM {APP_ROLE}")
    op.execute(f"GRANT UPDATE, DELETE ON alert_events TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON alerts TO {APP_ROLE}")
    op.execute(f"GRANT DELETE ON rules TO {APP_ROLE}")
    for table, trigger in APPEND_ONLY.items():
        op.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
    op.drop_index(
        "uq_jobs_queued_detect", table_name="jobs", postgresql_where=sa.text(QUEUED_DETECT)
    )
    op.drop_constraint(op.f("ck_iocs_confidence_range"), "iocs", type_="check")
    op.drop_constraint(op.f("ck_iocs_tlp"), "iocs", type_="check")
    op.drop_constraint(op.f("ck_iocs_type"), "iocs", type_="check")
    op.drop_constraint(op.f("uq_iocs_case_id_type_value"), "iocs", type_="unique")
    op.create_unique_constraint(
        op.f("uq_iocs_case_id_type_value"), "iocs", ["case_id", "type", "value"]
    )
    op.drop_constraint(op.f("fk_iocs_created_by_users"), "iocs", type_="foreignkey")
    op.drop_column("iocs", "created_at")
    op.drop_column("iocs", "created_by")
    op.drop_column("iocs", "active")
    op.drop_column("iocs", "value_original")
    op.drop_index("ix_alert_history_alert_id", table_name="alert_history")
    op.drop_table("alert_history")
    op.drop_index("ix_alert_events_event_id", table_name="alert_events")
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    op.drop_index("ix_alerts_case_id_last_seen", table_name="alerts")
    op.drop_index("ix_alerts_case_id_status", table_name="alerts")
    op.drop_constraint(op.f("fk_alerts_last_job_id_jobs"), "alerts", type_="foreignkey")
    for column in (
        "stale",
        "last_job_id",
        "last_detected_at",
        "updated_at",
        "status_reason",
        "details",
        "rule_version",
    ):
        op.drop_column("alerts", column)
    op.alter_column("alerts", "dedup_key", existing_type=sa.Text(), nullable=True)
    op.drop_table("rule_versions")
    op.drop_constraint(op.f("ck_rules_confidence_range"), "rules", type_="check")
    op.drop_constraint(op.f("ck_rules_kind"), "rules", type_="check")
    op.drop_constraint(op.f("ck_rules_origin"), "rules", type_="check")
    op.drop_constraint(op.f("fk_rules_created_by_users"), "rules", type_="foreignkey")
    for column in ("created_at", "created_by", "sha256", "confidence", "kind", "status"):
        op.drop_column("rules", column)
