"""rules, alerts, alert_events, iocs (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import REAL, Boolean, ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, text_array, uuid_pk
from app.db.models.enums import AlertStatus, Severity, alert_status_enum, severity_enum


class Rule(Base):
    __tablename__ = "rules"

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


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (UniqueConstraint("case_id", "dedup_key"),)

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
    dedup_key: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()


class AlertEvent(Base):
    """Alert -> event link. No FK to events (partitioned, composite PK); event_ts locates it."""

    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(UUID_T, primary_key=True)
    event_ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False)


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("case_id", "type", "value"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))  # NULL=global
    # ip|domain|url|sha256|md5|email|filename|registry
    type: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(REAL, server_default=text("0.5"))
    tlp: Mapped[str | None] = mapped_column(Text, server_default=text("'amber'"))
    first_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    expires_at: Mapped[datetime | None] = mapped_column(TSTZ)
