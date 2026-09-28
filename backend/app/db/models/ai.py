"""ai_interactions (AI audit trail) and event_chunks (pgvector RAG index) (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import Boolean, ForeignKey, Index, Integer, Numeric, SmallInteger, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import UUID_T, created_at, uuid_pk

# Must match EMBEDDING_DIM; changing it needs a migration (Phase 7).
EMBEDDING_DIM = 384


class AiInteraction(Base):
    __tablename__ = "ai_interactions"

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("cases.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("users.id"))
    # nlq|alert_explain|narrative|report_draft|chat|script_explain
    feature: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
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
    accepted: Mapped[bool | None] = mapped_column(Boolean)
    created_at: Mapped[datetime] = created_at()


class EventChunk(Base):
    __tablename__ = "event_chunks"
    __table_args__ = (
        Index(
            "ix_event_chunks_embedding",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    event_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID_T), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[Any] = mapped_column(Vector(EMBEDDING_DIM), nullable=True)
    created_at: Mapped[datetime] = created_at()
