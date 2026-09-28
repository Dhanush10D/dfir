"""cases, case_members (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, uuid_pk
from app.db.models.enums import (
    CaseStatus,
    Severity,
    UserRole,
    case_status_enum,
    severity_enum,
    user_role_enum,
)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_number: Mapped[str] = mapped_column(Text, unique=True, nullable=False)  # IR-2026-0001
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[CaseStatus] = mapped_column(
        case_status_enum, nullable=False, server_default=text("'open'")
    )
    severity: Mapped[Severity] = mapped_column(
        severity_enum, nullable=False, server_default=text("'medium'")
    )
    lead_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    classification: Mapped[str | None] = mapped_column(Text, server_default=text("'confidential'"))
    opened_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    closed_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))


class CaseMember(Base):
    __tablename__ = "case_members"
    __table_args__ = (Index("ix_case_members_user_id", "user_id"),)

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[UserRole] = mapped_column(user_role_enum, nullable=False)  # case-level role
