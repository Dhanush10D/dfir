"""evidence, custody_log (guide 7.2).

custody_log is append-only: the database rejects UPDATE, DELETE and TRUNCATE via triggers created in
the baseline migration. Only ``services/custody.py`` (Phase 1) may insert into it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CHAR, BigInteger, ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj, uuid_pk


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("case_id", "label"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
    )
    label: Mapped[str] = mapped_column(Text, nullable=False)  # EV-001
    # disk_image, memory, evtx, pcap, triage_bundle, log, file, cloud_export
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    original_name: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(CHAR(64))
    md5: Mapped[str | None] = mapped_column(CHAR(32))
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(Text)
    source_host: Mapped[str | None] = mapped_column(Text)
    acquired_at: Mapped[datetime | None] = mapped_column(TSTZ)
    acquired_by: Mapped[str | None] = mapped_column(Text)
    acquisition_tool: Mapped[str | None] = mapped_column(Text)
    acquisition_notes: Mapped[str | None] = mapped_column(Text)
    # uploading|stored|processing|processed|partial|archived|failed
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'uploading'"))
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    created_at: Mapped[datetime] = created_at()


class CustodyLog(Base):
    __tablename__ = "custody_log"
    __table_args__ = (UniqueConstraint("evidence_id", "seq"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)  # per-evidence sequence
    ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    actor_label: Mapped[str] = mapped_column(Text, nullable=False)
    # ingested|verified|accessed|processed|exported|transferred|note
    action: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = jsonb_obj()
    prev_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)  # Ed25519 over entry_hash (hex)
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
