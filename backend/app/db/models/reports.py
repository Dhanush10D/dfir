"""reports (guide 7.2, 18; migrations 0001 and 0011).

A report is one version of a family (``family_id`` = id of version 1). ``context`` is the data
snapshot the report renders from; it never changes. Lifecycle: draft -> in_review -> approved ->
signed. Privileges of the app role (0011): SELECT, INSERT, UPDATE of the workflow columns (no
DELETE); the ``reports_guard`` trigger keeps the identity/snapshot columns immutable, lets
sections and findings change only in ``draft``, allows only the lifecycle transitions and freezes
a ``signed`` row completely.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
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
from app.db.models._common import TSTZ, UUID_T, created_at, uuid_pk

REPORT_KINDS = ("technical", "executive", "custody", "ioc")
REPORT_STATUSES = ("draft", "in_review", "approved", "signed")


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("kind IN ('technical','executive','custody','ioc')", name="kind"),
        CheckConstraint("status IN ('draft','in_review','approved','signed')", name="status"),
        CheckConstraint(
            "status <> 'signed' OR (sha256 IS NOT NULL AND signature IS NOT NULL "
            "AND manifest IS NOT NULL AND key_id IS NOT NULL AND signed_at IS NOT NULL)",
            name="signed_sealed",
        ),
        UniqueConstraint("family_id", "version"),
        Index("ix_reports_case_id_created_at", "case_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # technical|executive|custody|ioc
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    # draft|in_review|approved|signed
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'draft'"))
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)  # render snapshot
    storage_uri: Mapped[str | None] = mapped_column(Text)  # the signed PDF (or main artifact)
    sha256: Mapped[str | None] = mapped_column(CHAR(64))  # SHA-256 of the canonical manifest
    signature: Mapped[str | None] = mapped_column(Text)  # Ed25519 over ``sha256`` (hex)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()
    # Phase 8 (migration 0011)
    title: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("''"))
    family_id: Mapped[uuid.UUID] = mapped_column(UUID_T, nullable=False)
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("reports.id"))
    revision: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    sections: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    findings: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    context_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    qa: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    submitted_at: Mapped[datetime | None] = mapped_column(TSTZ)
    approved_at: Mapped[datetime | None] = mapped_column(TSTZ)
    signed_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    signed_at: Mapped[datetime | None] = mapped_column(TSTZ)
    key_id: Mapped[str | None] = mapped_column(Text)
    manifest: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
