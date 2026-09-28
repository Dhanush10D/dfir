"""jobs (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import REAL, ForeignKey, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, jsonb_obj, uuid_pk
from app.db.models.enums import JobStatus, job_status_enum


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("evidence.id"))
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # parse|detect|ai|report|collect
    parser: Mapped[str | None] = mapped_column(Text)
    params: Mapped[dict[str, Any]] = jsonb_obj()
    # hash(evidence_id, parser, parser_version, params)
    idempotency_key: Mapped[str | None] = mapped_column(Text, unique=True)
    status: Mapped[JobStatus] = mapped_column(
        job_status_enum, nullable=False, server_default=text("'queued'")
    )
    progress: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("0"))
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    error: Mapped[str | None] = mapped_column(Text)
    run_manifest: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    queued_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    started_at: Mapped[datetime | None] = mapped_column(TSTZ)
    finished_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
