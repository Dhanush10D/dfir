"""entities, entity_aliases, entity_links (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import REAL, BigInteger, ForeignKey, Integer, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, jsonb_obj, uuid_pk


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("case_id", "type", "canonical"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    type: Mapped[str] = mapped_column(Text, nullable=False)  # host|user|ip|domain|file|process|hash
    canonical: Mapped[str] = mapped_column(Text, nullable=False)
    attributes: Mapped[dict[str, Any]] = jsonb_obj()
    first_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    last_seen: Mapped[datetime | None] = mapped_column(TSTZ)
    risk_score: Mapped[float | None] = mapped_column(REAL, server_default=text("0"))


class EntityAlias(Base):
    __tablename__ = "entity_aliases"

    entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("entities.id", ondelete="CASCADE"), primary_key=True
    )
    # hostname|fqdn|sid|upn|sam|ip|machine_guid
    alias_type: Mapped[str] = mapped_column(Text, primary_key=True)
    alias: Mapped[str] = mapped_column(Text, primary_key=True)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False, server_default=text("1.0"))


class EntityLink(Base):
    __tablename__ = "entity_links"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("cases.id"), nullable=False)
    src_entity: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("entities.id"), nullable=False)
    dst_entity: Mapped[uuid.UUID] = mapped_column(UUID_T, ForeignKey("entities.id"), nullable=False)
    # logged_on|executed|connected_to|created|resolved|downloaded|member_of
    relation: Mapped[str] = mapped_column(Text, nullable=False)
    event_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T)
    ts: Mapped[datetime | None] = mapped_column(TSTZ)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))
