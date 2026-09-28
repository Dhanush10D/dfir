"""events: the normalized unified timeline (guide 7.2, Appendix A).

Range-partitioned by month on ``ts`` (Standard profile). The baseline migration creates the
partitioned parent, a DEFAULT partition, and ``dfir_ensure_events_partition(ts)`` which ingest must
call for each month before bulk insert. Retention drops whole partitions, never rows (guide 7.6).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, text_array


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_case_id_ts", "case_id", "ts"),
        Index("ix_events_case_id_event_code", "case_id", "event_code"),
        Index("ix_events_case_id_host", "case_id", "host"),
        Index("ix_events_attack_tags", "attack_tags", postgresql_using="gin"),
        # Full-text index over message + cmdline (guide 7.2).
        Index(
            "ix_events_fts",
            # Written in PostgreSQL's normalized form so Alembic drift checks compare equal.
            text(
                "to_tsvector('simple'::regconfig, (COALESCE(message, ''::text) || ' '::text) "
                "|| COALESCE(cmdline, ''::text))"
            ),
            postgresql_using="gin",
        ),
        {"postgresql_partition_by": "RANGE (ts)"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, primary_key=True, server_default=text("gen_random_uuid()")
    )
    ts: Mapped[datetime] = mapped_column(TSTZ, primary_key=True)  # UTC, tz-aware
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("evidence.id"))
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))
    ts_original: Mapped[str | None] = mapped_column(Text)  # raw timestamp string + tz as found
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_file: Mapped[str | None] = mapped_column(Text)
    source_record_id: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    user: Mapped[str | None] = mapped_column("user", Text)
    event_code: Mapped[str | None] = mapped_column(Text)
    event_category: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text)
    process_name: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    cmdline: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    file_hash: Mapped[str | None] = mapped_column(Text)
    src_ip: Mapped[str | None] = mapped_column(INET)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(Text)
    registry_key: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    attack_tags: Mapped[list[str]] = text_array()
    tags: Mapped[list[str]] = text_array()
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    parser_name: Mapped[str | None] = mapped_column(Text)
    parser_version: Mapped[str | None] = mapped_column(Text)
    ingested_at: Mapped[datetime] = mapped_column(
        TSTZ, nullable=False, server_default=text("now()")
    )
