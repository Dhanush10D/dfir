"""bundle_members (Phase 5, migration 0008): the verification record of one triage bundle run.

One row per archive member (or manifest entry without a member) per run attempt: what the
manifest claimed, what the bytes hashed to, the verdict, and the derived evidence item + parse job
when the member was ingested. Append-only for the app role (SELECT/INSERT grants and a
``forbid_mutation`` trigger): a verification result is never rewritten, a new run adds rows.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import UUID_T, created_at, jsonb_obj

MEMBER_STATUSES = (
    "ingested",
    "verified",
    "hash_mismatch",
    "size_mismatch",
    "missing",
    "unlisted",
    "corrupt",
)
MEMBER_STATUSES_SQL = "(" + ",".join(f"'{s}'" for s in MEMBER_STATUSES) + ")"


class BundleMember(Base):
    __tablename__ = "bundle_members"
    __table_args__ = (
        UniqueConstraint("job_id", "attempt", "member_path"),
        CheckConstraint(f"status IN {MEMBER_STATUSES_SQL}", name="status"),
        Index(
            "ix_bundle_members_bundle_evidence_id_member_path", "bundle_evidence_id", "member_path"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    bundle_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("evidence.id"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("jobs.id"), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    member_path: Mapped[str] = mapped_column(Text, nullable=False)
    member_index: Mapped[int | None] = mapped_column(Integer)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256_manifest: Mapped[str | None] = mapped_column(CHAR(64))
    sha256_actual: Mapped[str | None] = mapped_column(CHAR(64))
    status: Mapped[str] = mapped_column(Text, nullable=False)
    parser: Mapped[str | None] = mapped_column(Text)
    derived_evidence_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("evidence.id"))
    parse_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))
    detail: Mapped[dict[str, Any]] = jsonb_obj()
    created_at: Mapped[datetime] = created_at()
