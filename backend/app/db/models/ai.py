"""ai_interactions (AI audit trail + review), event_chunks (pgvector RAG index) and
ai_index_state (per-case index freshness) (guide 7.2, 13; migrations 0001 and 0009).

Privileges of the app role (migration 0009):

* ``ai_interactions``: SELECT, INSERT, and UPDATE of the review columns only (``accepted``,
  ``reviewed_by``, ``reviewed_at``, ``review_note``, ``feedback``); a trigger allows ``accepted``
  to be set once and only on a ``valid`` interaction. Never deleted.
* ``event_chunks``: SELECT, INSERT, DELETE (derived data, rebuilt per case); no UPDATE.
* ``ai_index_state``: SELECT, INSERT, UPDATE; no DELETE.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    CHAR,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, uuid_pk

# Must match EMBEDDING_DIM (settings validation); changing it needs a migration.
EMBEDDING_DIM = 384
AI_STATUSES = ("valid", "invalid", "refused", "error")
AI_STATUSES_SQL = "('valid','invalid','refused','error')"


class AiInteraction(Base):
    __tablename__ = "ai_interactions"
    __table_args__ = (
        CheckConstraint(f"status IN {AI_STATUSES_SQL}", name="status"),
        CheckConstraint("feedback IS NULL OR feedback IN (-1, 0, 1)", name="feedback"),
        CheckConstraint(
            "accepted IS NULL OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="review_complete",
        ),
        CheckConstraint("accepted IS NULL OR status = 'valid'", name="accepted_valid"),
        Index("ix_ai_interactions_case_id_created_at", "case_id", "created_at"),
        Index("ix_ai_interactions_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    # nlq|alert_explain|narrative|chat|script_explain
    feature: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)  # requested model id
    prompt_version: Mapped[str] = mapped_column(Text, nullable=False)
    input_refs: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    redactions: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    output: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    citations: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    citations_valid: Mapped[bool | None] = mapped_column(Boolean)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[Decimal | None] = mapped_column(Numeric(10, 4))
    feedback: Mapped[int | None] = mapped_column(SmallInteger)  # -1, 0, +1
    accepted: Mapped[bool | None] = mapped_column(Boolean)  # None = not reviewed
    created_at: Mapped[datetime] = created_at()  # = finished
    # Phase 7 (migration 0009): outcome, provenance and review
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'valid'"))
    model_served: Mapped[str | None] = mapped_column(Text)
    prompt_sha256: Mapped[str | None] = mapped_column(CHAR(64))
    input_sha256: Mapped[str | None] = mapped_column(CHAR(64))
    output_sha256: Mapped[str | None] = mapped_column(CHAR(64))
    prompt_text: Mapped[str | None] = mapped_column(Text)  # redacted user message as sent
    warnings: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(TSTZ)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(TSTZ)
    review_note: Mapped[str | None] = mapped_column(Text)


class EventChunk(Base):
    __tablename__ = "event_chunks"
    __table_args__ = (
        Index(
            "ix_event_chunks_embedding",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        Index("ix_event_chunks_case_id", "case_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    event_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID_T), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[Any] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    created_at: Mapped[datetime] = created_at()
    # Phase 7 (migration 0009)
    host: Mapped[str | None] = mapped_column(Text)
    ts_start: Mapped[datetime | None] = mapped_column(TSTZ)
    ts_end: Mapped[datetime | None] = mapped_column(TSTZ)
    embedding_model: Mapped[str | None] = mapped_column(Text)
    content_sha256: Mapped[str | None] = mapped_column(CHAR(64))


class AiIndexState(Base):
    """Freshness of a case's chunk index: what the events looked like when it was built."""

    __tablename__ = "ai_index_state"

    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), primary_key=True)
    built_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_ingested_at: Mapped[datetime | None] = mapped_column(TSTZ)
    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    embedding_model: Mapped[str] = mapped_column(Text, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
