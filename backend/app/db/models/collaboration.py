"""notes (7.2); bookmarks, saved_queries, notifications (7.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, ForeignKey, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, text_array, uuid_pk


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    author_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("users.id"), nullable=False)
    target_type: Mapped[str | None] = mapped_column(Text)  # event|alert|evidence|entity|case
    target_id: Mapped[str | None] = mapped_column(Text)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list[str]] = text_array()
    created_at: Mapped[datetime] = created_at()


class Bookmark(Base):
    __tablename__ = "bookmarks"

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
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = jsonb_obj()
    read_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
