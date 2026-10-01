"""notes, note_versions (7.2, migration 0007); bookmarks, saved_queries, notifications (7.3).

Notes are part of the forensic record: the app role may INSERT notes and UPDATE only the head
columns (body, tags, version, updated/retracted markers); every version is kept in the
append-only ``note_versions`` (triggers + SELECT/INSERT grants). Nothing is ever deleted: a note
is *retracted*. Bookmarks are personal markers (SELECT/INSERT/DELETE, deletions audited).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
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
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, text_array, uuid_pk

TARGET_TYPES = ("case", "event", "alert", "evidence", "entity")
TARGET_TYPES_SQL = "('case','event','alert','evidence','entity')"


class Note(Base):
    __tablename__ = "notes"
    __table_args__ = (
        CheckConstraint(
            f"target_type IS NULL OR target_type IN {TARGET_TYPES_SQL}", name="target_type"
        ),
        CheckConstraint("version >= 1", name="version_positive"),
        Index("ix_notes_case_id_created_at", "case_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    author_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("users.id"), nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)  # event|alert|evidence|entity|case
    target_id: Mapped[str | None] = mapped_column(Text)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list[str]] = text_array()
    created_at: Mapped[datetime] = created_at()
    # Phase 4 (migration 0007): versioning and retraction.
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    retracted_at: Mapped[datetime | None] = mapped_column(TSTZ)
    retracted_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))


class NoteVersion(Base):
    __tablename__ = "note_versions"
    __table_args__ = (
        UniqueConstraint("note_id", "version"),
        CheckConstraint("action IN ('created','edited','retracted')", name="action"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    note_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("notes.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list[str]] = text_array()
    user_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("users.id"), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()


class Bookmark(Base):
    __tablename__ = "bookmarks"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", "target_type", "target_id"),
        CheckConstraint(f"target_type IN {TARGET_TYPES_SQL}", name="target_type"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    target_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str] = mapped_column(Text, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at()


class SavedQuery(Base):
    __tablename__ = "saved_queries"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID_T, ForeignKey("cases.id", ondelete="CASCADE")
    )  # NULL = global preset
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    query: Mapped[str] = mapped_column(Text, nullable=False)
    shared: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    created_at: Mapped[datetime] = created_at()


class Notification(Base):
    """In-app notification. The app role may INSERT and set ``read_at`` only (migration 0012)."""

    __tablename__ = "notifications"
    __table_args__ = (
        # One notification per user and dedup key (the key carries the time bucket).
        Index(
            "uq_notifications_user_id_dedup_key",
            "user_id",
            "dedup_key",
            unique=True,
            postgresql_where=text("dedup_key IS NOT NULL"),
        ),
        Index("ix_notifications_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = jsonb_obj()
    read_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
    # Phase 9 (migration 0012)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    dedup_key: Mapped[str | None] = mapped_column(Text)
