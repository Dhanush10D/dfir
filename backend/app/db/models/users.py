"""users, api_keys (guide 7.2); refresh_tokens, mfa_recovery_codes (Phase 1, guide 16.2)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    LargeBinary,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import CITEXT, INET
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, text_array, uuid_pk
from app.db.models.enums import UserRole, user_role_enum


class User(Base):
    __tablename__ = "users"
    # Stored lower-case (migration 0003); citext keeps the UNIQUE case-insensitive too.
    __table_args__ = (CheckConstraint("email::text = lower(email::text)", name="email_lowercase"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(CITEXT(), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)  # Argon2id; NULL if SSO-only
    role: Mapped[UserRole] = mapped_column(
        user_role_enum, nullable=False, server_default=text("'analyst'")
    )
    totp_secret: Mapped[bytes | None] = mapped_column(LargeBinary)  # encrypted at rest
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    locked_until: Mapped[datetime | None] = mapped_column(TSTZ)
    last_login_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
    # Last accepted TOTP time step; codes for this step or earlier are replays (Phase 1).
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the key; the key itself is shown once at creation.
    key_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    scopes: Mapped[list[str]] = text_array()
    expires_at: Mapped[datetime | None] = mapped_column(TSTZ)
    revoked_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
    key_prefix: Mapped[str | None] = mapped_column(Text)  # first characters, for display
    last_used_at: Mapped[datetime | None] = mapped_column(TSTZ)


class RefreshToken(Base):
    """Server-side refresh token (hash only), rotated on every use; a family is one login."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    family_id: Mapped[uuid.UUID] = mapped_column(UUID_T, nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)
    issued_at: Mapped[datetime] = created_at()
    expires_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    session_started_at: Mapped[datetime] = mapped_column(TSTZ, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TSTZ)
    revoked_reason: Mapped[str | None] = mapped_column(Text)  # rotated|logout|reuse|...
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(UUID_T)
    user_agent: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(INET)


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
