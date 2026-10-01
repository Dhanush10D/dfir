"""Response and integration tables added in Phase 9 (guide 15.6, 19; migration 0012).

* ``playbook_run_steps``: one row per step of a run (the guide keeps step state in JSONB; rows let
  the database enforce the approval rules). Identity columns are immutable; ``steps_guard`` allows
  only the documented status transitions and requires an approved/finished action request for
  steps that need approval. Finished (``done``/``skipped``) rows are frozen.
* ``action_requests``: four-eyes approval of an impactful action. ``action_requests_guard``
  compares with ``OLD``: requester, action and parameters never change, approval needs a decider
  other than the recorded requester before ``expires_at``, execution needs a prior approval, and
  rejected/expired/finished rows are frozen. CHECK constraints describe every state.
* ``outbound_events`` / ``outbound_deliveries``: the outbox and the delivery log (terminal
  deliveries are frozen). ``inbound_deliveries``: append-only log of accepted SIEM/EDR
  deliveries; UNIQUE (integration, nonce) is the replay protection.
* ``ioc_enrichments``: cached provider verdicts per indicator.

App role: no DELETE on any of these; UPDATE only on the workflow columns (column grants).
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
)
from sqlalchemy import (
    text as sql_text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, uuid_pk

STEP_STATUSES = (
    "pending",
    "awaiting_approval",
    "approved",
    "not_executed",
    "failed",
    "done",
    "skipped",
)
STEP_OPEN = ("pending", "awaiting_approval", "approved")
STEP_TERMINAL = ("done", "skipped")
REQUEST_STATUSES = ("pending", "approved", "rejected", "expired", "finished")
DELIVERY_STATUSES = ("pending", "delivered", "failed", "suppressed")


class PlaybookRunStep(Base):
    __tablename__ = "playbook_run_steps"
    __table_args__ = (
        UniqueConstraint("run_id", "step_key"),
        UniqueConstraint("run_id", "position"),
        CheckConstraint("kind IN ('manual','action')", name="kind"),
        CheckConstraint(
            "(kind = 'manual' AND action IS NULL AND NOT requires_approval) "
            "OR (kind = 'action' AND action IS NOT NULL)",
            name="kind_action",
        ),
        CheckConstraint(
            "status IN ('pending','awaiting_approval','approved','not_executed','failed',"
            "'done','skipped')",
            name="status",
        ),
        CheckConstraint(
            "(status IN ('pending','awaiting_approval','approved') AND outcome IS NULL) "
            "OR (status = 'not_executed' AND outcome = 'not_executed') "
            "OR (status = 'failed' AND outcome = 'failed') "
            "OR (status = 'done' AND outcome IN ('completed','completed_manually')) "
            "OR (status = 'skipped' AND outcome = 'skipped')",
            name="outcome",
        ),
        CheckConstraint(
            "(status IN ('done','skipped')) = (completed_by IS NOT NULL) "
            "AND (status IN ('done','skipped')) = (completed_at IS NOT NULL)",
            name="completed",
        ),
        Index("ix_playbook_run_steps_case_id", "case_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("playbook_runs.id"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(Text, nullable=False)
    step_key: Mapped[str] = mapped_column(Text, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # manual | action
    action: Mapped[str | None] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = jsonb_obj()
    requires_approval: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=sql_text("false")
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=sql_text("'pending'"))
    # completed | completed_manually | not_executed | failed | skipped
    outcome: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    notes: Mapped[str | None] = mapped_column(Text)
    completed_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    completed_at: Mapped[datetime | None] = mapped_column(TSTZ)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=sql_text("now()")
    )


class ActionRequest(Base):
    __tablename__ = "action_requests"
    __table_args__ = (
        UniqueConstraint("idempotency_key"),
        CheckConstraint(
            "status IN ('pending','approved','rejected','expired','finished')", name="status"
        ),
        CheckConstraint("expires_at > requested_at", name="expiry"),
        CheckConstraint(
            "status <> 'pending' OR (decided_by IS NULL AND decided_at IS NULL "
            "AND decision_reason IS NULL)",
            name="pending",
        ),
        CheckConstraint(
            "status NOT IN ('approved','finished') OR (decided_by IS NOT NULL "
            "AND decided_at IS NOT NULL AND decided_by <> requested_by)",
            name="four_eyes",
        ),
        CheckConstraint(
            "status <> 'rejected' OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)",
            name="rejected",
        ),
        CheckConstraint("status <> 'expired' OR decided_at IS NOT NULL", name="expired"),
        CheckConstraint(
            "(status = 'finished') = (executed_at IS NOT NULL) "
            "AND (status = 'finished') = (executed_by IS NOT NULL) "
            "AND (status = 'finished') = (outcome IS NOT NULL)",
            name="finished",
        ),
        CheckConstraint(
            "outcome IS NULL OR outcome IN ('completed','not_executed','failed')", name="outcome"
        ),
        # At most one open request per step (also the idempotency of "request approval").
        Index(
            "uq_action_requests_open_step",
            "step_id",
            unique=True,
            postgresql_where=sql_text("status IN ('pending','approved')"),
        ),
        Index("ix_action_requests_case_id_status", "case_id", "status"),
        Index("ix_action_requests_step_id_requested_at", "step_id", "requested_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("playbook_runs.id"), nullable=False
    )
    step_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("playbook_run_steps.id"), nullable=False
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("alerts.id"))
    action: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict[str, Any]] = jsonb_obj()
    params_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=sql_text("'pending'"))
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("users.id"), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=sql_text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(TSTZ)
    decision_reason: Mapped[str | None] = mapped_column(Text)
    executed_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    executed_at: Mapped[datetime | None] = mapped_column(TSTZ)
    outcome: Mapped[str | None] = mapped_column(Text)  # completed | not_executed | failed
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class OutboundEvent(Base):
    """Outbox row written in the business transaction that caused the event."""

    __tablename__ = "outbound_events"
    __table_args__ = (
        UniqueConstraint("dedup_key"),
        Index(
            "ix_outbound_events_pending",
            "created_at",
            postgresql_where=sql_text("fanned_out_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    payload: Mapped[dict[str, Any]] = jsonb_obj()  # identifiers and enumerated values only
    dedup_key: Mapped[str | None] = mapped_column(Text)
    # Set for a test delivery: only this integration receives the event.
    only_integration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_T, ForeignKey("integrations.id")
    )
    created_at: Mapped[datetime] = created_at()
    fanned_out_at: Mapped[datetime | None] = mapped_column(TSTZ)


class OutboundDelivery(Base):
    """One event for one integration: the delivery log (webhooks and notifications)."""

    __tablename__ = "outbound_deliveries"
    __table_args__ = (
        UniqueConstraint("event_id", "integration_id"),
        CheckConstraint("status IN ('pending','delivered','failed','suppressed')", name="status"),
        CheckConstraint("attempts >= 0 AND attempts <= max_attempts", name="attempts"),
        CheckConstraint("(status = 'delivered') = (delivered_at IS NOT NULL)", name="delivered"),
        CheckConstraint("status <> 'pending' OR next_attempt_at IS NOT NULL", name="pending_due"),
        Index(
            "ix_outbound_deliveries_due",
            "next_attempt_at",
            postgresql_where=sql_text("status = 'pending'"),
        ),
        Index("ix_outbound_deliveries_integration_id_created_at", "integration_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("outbound_events.id"), nullable=False
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("integrations.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # the integration type at fan-out
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=sql_text("'pending'"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sql_text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(TSTZ)
    locked_until: Mapped[datetime | None] = mapped_column(TSTZ)  # lease of an attempt in flight
    last_error: Mapped[str | None] = mapped_column(Text)  # a category, never a body or a URL
    response_status: Mapped[int | None] = mapped_column(Integer)
    dedup_key: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=sql_text("now()")
    )
    delivered_at: Mapped[datetime | None] = mapped_column(TSTZ)


class InboundDelivery(Base):
    """An accepted SIEM/EDR webhook delivery (append-only)."""

    __tablename__ = "inbound_deliveries"
    __table_args__ = (
        UniqueConstraint("integration_id", "nonce"),
        Index("ix_inbound_deliveries_integration_id_received_at", "integration_id", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    integration_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("integrations.id"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    nonce: Mapped[str] = mapped_column(CHAR(64), nullable=False)  # the signed digest
    received_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=sql_text("now()")
    )
    source_ip: Mapped[str | None] = mapped_column(INET)
    body_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    items: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sql_text("0"))
    created: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sql_text("0"))
    updated: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sql_text("0"))
    errors: Mapped[int] = mapped_column(Integer, nullable=False, server_default=sql_text("0"))
    error_reasons: Mapped[dict[str, Any]] = jsonb_obj()  # {fixed reason code: count}


class IocEnrichment(Base):
    """Cached verdict of one provider for one indicator (not case data)."""

    __tablename__ = "ioc_enrichments"
    __table_args__ = (
        UniqueConstraint("provider", "ioc_type", "value_sha256"),
        CheckConstraint(
            "verdict IN ('malicious','suspicious','harmless','unknown')", name="verdict"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    ioc_type: Mapped[str] = mapped_column(Text, nullable=False)
    value_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float | None] = mapped_column(REAL)
    summary: Mapped[dict[str, Any]] = jsonb_obj()
    fetched_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=sql_text("now()")
    )
    expires_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
