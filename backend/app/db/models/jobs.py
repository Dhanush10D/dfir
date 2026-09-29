"""jobs (guide 7.2, 10.6). Lifecycle: queued -> running -> succeeded | partial | failed | cancelled.

``attempts`` is incremented atomically when a worker claims the job and doubles as a fencing token:
every write a worker makes re-checks ``(status, attempts)`` under a row lock, so a worker whose
lease was taken over (``heartbeat_at`` older than ``JOB_LEASE_S``) cannot write any more. The app
role has no DELETE on this table (migration 0004): run manifests are provenance records.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import REAL, CheckConstraint, ForeignKey, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, jsonb_obj, uuid_pk
from app.db.models.enums import JobStatus, job_status_enum


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("progress >= 0 AND progress <= 1", name="progress_range"),
        Index("ix_jobs_case_id_queued_at", "case_id", "queued_at"),
        Index("ix_jobs_evidence_id", "evidence_id"),
        # One active parse job per (evidence, parser): reprocess never interleaves with a run.
        Index(
            "uq_jobs_active_parse",
            "evidence_id",
            "parser",
            unique=True,
            postgresql_where=text("kind = 'parse' AND status IN ('queued', 'running')"),
        ),
        # Phase 5: one active triage-bundle ingest per evidence item.
        Index(
            "uq_jobs_active_bundle",
            "evidence_id",
            unique=True,
            postgresql_where=text("kind = 'bundle' AND status IN ('queued', 'running')"),
        ),
        # Phase 3: at most one *queued* detection job per case; later requests coalesce into it.
        Index(
            "uq_jobs_queued_detect",
            "case_id",
            unique=True,
            postgresql_where=text("kind = 'detect' AND status = 'queued'"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("evidence.id"))
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # parse|detect|bundle|ai|report
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
    # Phase 2 (migration 0004)
    heartbeat_at: Mapped[datetime | None] = mapped_column(TSTZ)
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))
