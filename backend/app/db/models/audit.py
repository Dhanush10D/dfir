"""audit_log (7.2); signing_keys, anchors (7.3).

audit_log is append-only (UPDATE/DELETE/TRUNCATE rejected by triggers) and excluded from purges.
signing_keys history is kept forever so old custody signatures stay verifiable (guide 7.6).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CHAR, BigInteger, Integer, LargeBinary, Text, text
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, jsonb_obj


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID_T)
    ip: Mapped[str | None] = mapped_column(INET)
    method: Mapped[str | None] = mapped_column(Text)
    path: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    # login|read|create|update|delete|export|ai_call
    action: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str | None] = mapped_column(Text)
    object_id: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = jsonb_obj()


class SigningKey(Base):
    __tablename__ = "signing_keys"

    key_id: Mapped[str] = mapped_column(Text, primary_key=True)
    algorithm: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'ed25519'"))
    public_key: Mapped[str] = mapped_column(Text, nullable=False)  # PEM or hex
    purpose: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'custody'"))
    created_at: Mapped[datetime] = created_at()
    retired_at: Mapped[datetime | None] = mapped_column(TSTZ)


class Anchor(Base):
    """Periodic Merkle root over custody entries (ADR-5), optionally RFC 3161 time-stamped."""

    __tablename__ = "anchors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(TSTZ, nullable=False, server_default=text("now()"))
    root_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    first_custody_id: Mapped[int | None] = mapped_column(BigInteger)
    last_custody_id: Mapped[int | None] = mapped_column(BigInteger)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    tsa_token: Mapped[bytes | None] = mapped_column(LargeBinary)  # RFC 3161 token (DER)
