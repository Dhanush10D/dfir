"""playbooks, playbook_runs, agents, agent_tasks, integrations, settings (guide 7.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, text_array, uuid_pk


class Playbook(Base):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # e.g. PB-RANSOMWARE-001
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    trigger: Mapped[dict[str, Any]] = jsonb_obj()  # rule ids / tags
    steps: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    raw_yaml: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    playbook_id: Mapped[str] = mapped_column(Text, ForeignKey("playbooks.id"), nullable=False)
    playbook_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'running'"))
    step_states: Mapped[dict[str, Any]] = jsonb_obj()
    approver_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    started_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    started_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    finished_at: Mapped[datetime | None] = mapped_column(TSTZ)


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

    id: Mapped[uuid.UUID] = uuid_pk()
    type: Mapped[str] = mapped_column(Text, nullable=False)  # misp|virustotal|webhook|slack|...
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    config_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)  # encrypted at rest
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_status: Mapped[str | None] = mapped_column(Text)
    scopes: Mapped[list[str]] = text_array()
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
