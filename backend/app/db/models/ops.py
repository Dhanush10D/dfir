"""playbooks, playbook_runs, agents, agent_tasks, integrations, settings (guide 7.3, 19;
migrations 0001 and 0012).

* ``playbooks``: definitions synced from the packaged YAML (or imported); never deleted.
* ``playbook_runs``: a run keeps a snapshot of the definition; its steps are rows in
  ``playbook_run_steps`` (``step_states`` only holds archived steps after a 0012 downgrade,
  ``approver_id`` is unused: approvals are ``action_requests``). The app role may UPDATE only
  ``status`` and ``finished_at``; ``playbook_runs_guard`` keeps the rest immutable.
* ``integrations``: ``config`` is non-secret configuration; the secret is envelope-encrypted
  (``config_encrypted`` = ciphertext, ``secret_wrapped_key``, ``secret_key_id``) and never leaves
  the service layer. Rows are disabled, never deleted (delivery logs reference them).
* ``agents`` / ``agent_tasks`` are unused in the Standard profile (remote agent: guide 9.4, P2).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, text_array, uuid_pk

INTEGRATION_TYPES = (
    "webhook_out",
    "webhook_in",
    "slack",
    "teams",
    "email",
    "virustotal",
    "misp",
)
RUN_STATUSES = ("running", "completed", "cancelled")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (CheckConstraint("origin IN ('builtin','custom')", name="origin"),)

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # e.g. PB-RANSOMWARE-01
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    trigger: Mapped[dict[str, Any]] = jsonb_obj()  # rule ids / ATT&CK techniques
    steps: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )  # the phases with their steps
    raw_yaml: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    # Phase 9 (migration 0012)
    sha256: Mapped[str | None] = mapped_column(CHAR(64))  # of raw_yaml
    origin: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'builtin'"))
    notify: Mapped[dict[str, Any]] = jsonb_obj()
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (
        CheckConstraint("status IN ('running','completed','cancelled')", name="status"),
        CheckConstraint("(status = 'running') = (finished_at IS NULL)", name="finished"),
        Index("ix_playbook_runs_case_id_started_at", "case_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    playbook_id: Mapped[str] = mapped_column(Text, ForeignKey("playbooks.id"), nullable=False)
    playbook_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'running'"))
    step_states: Mapped[dict[str, Any]] = jsonb_obj()  # archive after a 0012 downgrade only
    approver_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    started_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    started_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    finished_at: Mapped[datetime | None] = mapped_column(TSTZ)
    # Phase 9 (migration 0012)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("alerts.id"))
    definition: Mapped[dict[str, Any]] = jsonb_obj()  # snapshot of the playbook at start
    playbook_sha256: Mapped[str | None] = mapped_column(CHAR(64))


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = uuid_pk()
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    os: Mapped[str | None] = mapped_column(Text)
    agent_version: Mapped[str | None] = mapped_column(Text)
    enrolled_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=text("now()")
    )
    last_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    cert_fingerprint: Mapped[str | None] = mapped_column(Text, unique=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'active'"))


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    type: Mapped[str] = mapped_column(Text, nullable=False)
    params: Mapped[dict[str, Any]] = jsonb_obj()
    signature: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'pending'"))
    result_uri: Mapped[str | None] = mapped_column(Text)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (
        CheckConstraint(
            "type IN ('webhook_out','webhook_in','slack','teams','email','virustotal','misp')",
            name="type",
        ),
        CheckConstraint(
            "(config_encrypted IS NULL) = (secret_wrapped_key IS NULL) "
            "AND (config_encrypted IS NULL) = (secret_key_id IS NULL)",
            name="secret",
        ),
        # An enabled ingest source always has its case (a disabled one may be incomplete).
        CheckConstraint(
            "type <> 'webhook_in' OR case_id IS NOT NULL OR NOT enabled", name="ingest_case"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    type: Mapped[str] = mapped_column(Text, nullable=False)  # see INTEGRATION_TYPES
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    # AES-256-GCM ciphertext of the secret JSON under a per-row data key (app/integrations/crypto)
    config_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_status: Mapped[str | None] = mapped_column(Text)
    scopes: Mapped[list[str]] = text_array()
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    # Phase 9 (migration 0012)
    config: Mapped[dict[str, Any]] = jsonb_obj()  # non-secret settings (URL, events, mapping)
    # webhook_in: the case its deliveries go to (never taken from a payload)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    secret_wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary)  # data key under the KEK
    secret_key_id: Mapped[str | None] = mapped_column(Text)  # which KEK wrapped it
    secret_fingerprint: Mapped[str | None] = mapped_column(Text)  # keyed, 12 hex characters
    last_status_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
