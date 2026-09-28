"""reports (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CHAR, ForeignKey, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import UUID_T, created_at, uuid_pk


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # technical|executive|custody|ioc
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    # draft|in_review|approved|signed
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'draft'"))
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)  # render snapshot
    storage_uri: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(CHAR(64))
    signature: Mapped[str | None] = mapped_column(Text)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()
