"""rules, rule_versions, alerts, alert_events, alert_history, iocs (guide 7.2, 11; migration 0006).

Privileges of the app role (migration 0006):

* ``rules``: SELECT/INSERT/UPDATE (no DELETE: alerts reference rules; disable instead).
* ``rule_versions``, ``alert_history``: SELECT/INSERT only, plus append-only triggers.
* ``alerts``: SELECT/INSERT/UPDATE (no DELETE: an alert and its triage history are records).
* ``alert_events``: SELECT/INSERT and UPDATE of ``event_ts`` only (a reprocess can move an event).
* ``iocs``: SELECT/INSERT/UPDATE (a removed IOC is deactivated, never deleted).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    REAL,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, text_array, uuid_pk
from app.db.models.enums import AlertStatus, Severity, alert_status_enum, severity_enum

RULE_ORIGINS = ("builtin", "custom", "sigma")
RULE_KINDS = ("single", "threshold", "sequence", "detector")
IOC_TYPES_SQL = "('ip','domain','url','sha256','sha1','md5','email','filename')"
TLP_SQL = "('clear','white','green','amber','amber+strict','red')"


class Rule(Base):
    __tablename__ = "rules"
    __table_args__ = (
        CheckConstraint("origin IN ('builtin','custom','sigma')", name="origin"),
        CheckConstraint("kind IN ('single','threshold','sequence','detector')", name="kind"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # DFIR-WIN-0001
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    level: Mapped[Severity] = mapped_column(severity_enum, nullable=False)
    attack: Mapped[list[str]] = text_array()
    logsource: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    origin: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'builtin'"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    # Phase 3 (migration 0006)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'experimental'"))
    kind: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'single'"))
    confidence: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("0.5"))
    sha256: Mapped[str | None] = mapped_column(CHAR(64))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()


class RuleVersion(Base):
    """Every version of every rule (append-only): run manifests cite (rule id, version, sha256)."""

    __tablename__ = "rule_versions"

    rule_id: Mapped[str] = mapped_column(Text, ForeignKey("rules.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    raw_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    source_text: Mapped[str | None] = mapped_column(Text)  # e.g. the original Sigma rule
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("case_id", "dedup_key"),
        Index("ix_alerts_case_id_status", "case_id", "status"),
        Index("ix_alerts_case_id_last_seen", "case_id", "last_seen"),
        Index("ix_alerts_rule_id", "rule_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(Text, ForeignKey("rules.id"))
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(severity_enum, nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("0.5"))
    risk_score: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("0"))
    status: Mapped[AlertStatus] = mapped_column(
        alert_status_enum, nullable=False, server_default=text("'new'")
    )
    host: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column("user", Text)
    attack_tags: Mapped[list[str]] = text_array()
    # rule id + hash(entity, time bucket); NOT NULL since 0006 so the UNIQUE constraint dedups.
    dedup_key: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()
    # Phase 3 (migration 0006)
    rule_version: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = jsonb_obj()
    status_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    # started_at of the newest detection run that produced this alert; older runs never
    # overwrite newer results, and a complete run marks alerts it did not reproduce as stale.
    last_detected_at: Mapped[datetime | None] = mapped_column(TSTZ)
    last_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class AlertEvent(Base):
    """Alert -> event link. No FK to events (partitioned, composite PK); event_ts locates it.

    Event ids are deterministic, so the link survives a reprocess (delete + re-insert of the same
    ids); the next detection run refreshes ``event_ts`` if the reprocess moved the event.
    """

    __tablename__ = "alert_events"
    __table_args__ = (Index("ix_alert_events_event_id", "event_id"),)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(UUID_T, primary_key=True)
    event_ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False)


class AlertHistory(Base):
    """Append-only lifecycle of an alert: creation by a detection job, status/assignee changes."""

    __tablename__ = "alert_history"
    __table_args__ = (Index("ix_alert_history_alert_id", "alert_id", "id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    alert_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("alerts.id"), nullable=False)
    ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    action: Mapped[str] = mapped_column(Text, nullable=False)  # created|status|assign
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))
    from_status: Mapped[AlertStatus | None] = mapped_column(alert_status_enum)
    to_status: Mapped[AlertStatus | None] = mapped_column(alert_status_enum)
    from_assignee: Mapped[uuid.UUID | None] = mapped_column(UUID_T)
    to_assignee: Mapped[uuid.UUID | None] = mapped_column(UUID_T)
    reason: Mapped[str | None] = mapped_column(Text)


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("case_id", "type", "value", postgresql_nulls_not_distinct=True),
        CheckConstraint(f"type IN {IOC_TYPES_SQL}", name="type"),
        CheckConstraint(f"tlp IS NULL OR tlp IN {TLP_SQL}", name="tlp"),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 1)", name="confidence_range"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))  # NULL=global
    # ip|domain|url|sha256|sha1|md5|email|filename (normalized, see app.detection.ioc)
    type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(REAL, server_default=text("0.5"))
    tlp: Mapped[str | None] = mapped_column(Text, server_default=text("'amber'"))
    first_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    expires_at: Mapped[datetime | None] = mapped_column(TSTZ)
    # Phase 3 (migration 0006)
    value_original: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()
