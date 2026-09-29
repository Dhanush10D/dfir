"""entities, entity_aliases, entity_links (guide 7.2, 12.3; migration 0007).

Written by the entity-resolution step of detection runs (``app.analysis.entities`` +
``services/entities.py``): upserts keyed by ``(case_id, type, canonical)`` and
``(case_id, src_entity, dst_entity, relation)``, so reruns are idempotent. App-role privileges:
entities and entity_links SELECT/INSERT/UPDATE, entity_aliases SELECT/INSERT (never DELETE: notes
may point at entities).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    REAL,
    BigInteger,
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
from app.db.models._common import TSTZ, UUID_T, jsonb_obj, uuid_pk

ENTITY_TYPES = ("host", "user", "ip", "process", "hash", "domain", "file")
RELATIONS = (
    "logged_on",
    "failed_logon",
    "seen_on",
    "connected_to",
    "executed",
    "ran_on",
    "has_hash",
)
ENTITY_TYPES_SQL = "('host','user','ip','process','hash','domain','file')"
RELATIONS_SQL = (
    "('logged_on','failed_logon','seen_on','connected_to','executed','ran_on','has_hash')"
)


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        UniqueConstraint("case_id", "type", "canonical"),
        CheckConstraint(f"type IN {ENTITY_TYPES_SQL}", name="type"),
        Index("ix_entities_case_id_type", "case_id", "type"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)  # host|user|ip|domain|file|process|hash
    canonical: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict[str, Any]] = jsonb_obj()
    first_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    last_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    risk_score: Mapped[float | None] = mapped_column(REAL, server_default=text("0"))
    # Phase 4 (migration 0007)
    event_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default=text("0"))
    updated_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    last_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T, ForeignKey("jobs.id"))


class EntityAlias(Base):
    __tablename__ = "entity_aliases"

    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    # hostname|fqdn|sid|upn|domain_user|name|ip|machine_guid
    alias_type: Mapped[str] = mapped_column(Text, primary_key=True)
    alias: Mapped[str] = mapped_column(Text, primary_key=True)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("1.0"))


class EntityLink(Base):
    __tablename__ = "entity_links"
    __table_args__ = (
        UniqueConstraint("case_id", "src_entity", "dst_entity", "relation"),
        CheckConstraint(f"relation IN {RELATIONS_SQL}", name="relation"),
        Index("ix_entity_links_case_id_dst_entity", "case_id", "dst_entity"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    src_entity: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("entities.id"), nullable=False)
    dst_entity: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("entities.id"), nullable=False)
    relation: Mapped[str] = mapped_column(Text, nullable=False)
    event_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T)  # a sample event
    ts: Mapped[datetime | None] = mapped_column(TSTZ)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
    # Phase 4 (migration 0007)
    first_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    last_seen: Mapped[datetime | None] = mapped_column(TSTZ)
