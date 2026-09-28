"""users, api_keys (guide 7.2)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, Text, text
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models._common import TSTZ, UUID_T, created_at, text_array, uuid_pk
from app.db.models.enums import UserRole, user_role_enum


class User(Base):
    __tablename__ = "users"

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


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID_T, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)  # hash only; key shown once
    scopes: Mapped[list[str]] = text_array()
    expires_at: Mapped[datetime | None] = mapped_column(TSTZ)
    revoked_at: Mapped[datetime | None] = mapped_column(TSTZ)
    created_at: Mapped[datetime] = created_at()
