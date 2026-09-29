"""Auth, users, sessions, MFA and API key schemas (guide 15.2 "Auth and users")."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.models.enums import UserRole


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_at: datetime
    refresh_token: str | None = Field(
        default=None, description="Omitted with X-Token-Delivery: cookie (HttpOnly cookie)."
    )
    refresh_expires_at: datetime


class LoginResponse(BaseModel):
    """Either tokens, or ``mfa_required`` with a short-lived challenge for /auth/mfa/verify."""

    mfa_required: bool = False
    mfa_challenge: str | None = None
    mfa_expires_at: datetime | None = None
    tokens: TokenResponse | None = None


class MfaVerifyRequest(BaseModel):
    mfa_challenge: str = Field(min_length=10, max_length=4096)
    code: str | None = Field(default=None, max_length=16)
    recovery_code: str | None = Field(default=None, max_length=32)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=10, max_length=512)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str
    role: UserRole
    mfa_enabled: bool
    is_active: bool
    failed_logins: int
    locked_until: datetime | None
    last_login_at: datetime | None
    created_at: datetime


class MeResponse(BaseModel):
    user: UserOut
    permissions: list[str]
    auth_method: str


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=16)


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=6, max_length=16)


class SessionOut(BaseModel):
    family_id: uuid.UUID
    started_at: datetime
    last_refreshed_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[Literal["read", "write"]] = Field(default=["read"], min_length=1)
    expires_in_days: int | None = Field(default=90, ge=1, le=3650)


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str | None
    scopes: list[str]
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="Shown once; store it securely.")


EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$"


class UserCreate(BaseModel):
    email: str = Field(max_length=320, pattern=EMAIL_PATTERN)
    display_name: str = Field(min_length=1, max_length=200)
    role: UserRole = UserRole.analyst
    password: str = Field(min_length=1, max_length=1024)


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    role: UserRole | None = None
    is_active: bool | None = None
    reset_mfa: bool = False
    unlock: bool = False
    admin_password: str | None = Field(
        default=None, max_length=1024, description="Required for role, activation and MFA changes"
    )


class ReauthRequest(BaseModel):
    admin_password: str = Field(min_length=1, max_length=1024)
