"""Identity and access management (guide 16.2, 16.4): logins, MFA, tokens, users, API keys.

Every public method is one transaction and commits itself. Security-relevant failures (bad
password, bad MFA code, refresh-token reuse) are committed *before* the error is raised so the
lockout counter and the audit row survive.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnauthenticatedError,
)
from app.core.permissions import Permission, Principal
from app.core.ratelimit import RateLimitedError, RateLimiterUnavailableError, WindowLimiter
from app.core.security import (
    JwtCodec,
    SecretBox,
    TokenError,
    check_password_policy,
    hash_password,
    make_password_hasher,
    match_totp_step,
    new_api_key,
    new_recovery_code,
    new_token,
    new_totp_secret,
    normalize_recovery_code,
    sha256_hex,
    totp_uri,
    verify_password,
)
from app.db.models import ApiKey, MfaRecoveryCode, RefreshToken, User, UserRole
from app.services.audit import AuditService, RequestMeta, clean_ip
from app.services.authz import require_global

RECOVERY_CODE_COUNT = 10
API_KEY_SCOPES = frozenset({"read", "write"})


def utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_email(email: str) -> str:
    """E-mail addresses are stored and compared lower-cased (migration 0003 enforces it)."""
    return email.strip().lower()


def invalid_credentials() -> AppError:
    return AppError("invalid_credentials", "Invalid e-mail or password.", 401)


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret


@dataclass(frozen=True)
class LoginResult:
    tokens: TokenPair | None = None
    mfa_challenge: str | None = None
    mfa_expires_at: datetime | None = None


@dataclass(frozen=True)
class MfaEnrollment:
    secret: str
    otpauth_uri: str


@dataclass(frozen=True)
class CreatedApiKey:
    record: ApiKey
    key: str


@dataclass(frozen=True)
class SessionInfo:
    family_id: uuid.UUID
    started_at: datetime
    last_refreshed_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None


class IAMService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        clock: Callable[[], datetime] = utcnow,
        limiter: WindowLimiter | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.clock = clock
        self.limiter = limiter  # per-IP limits on authentication (None: CLI and tools)
        self.hasher = make_password_hasher(settings)
        self.jwt = JwtCodec(settings)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers

    def _box(self) -> SecretBox:
        key = self.settings.totp_enc_key
        if key is None or not key.get_secret_value():
            raise AppError("mfa_unavailable", "TOTP_ENC_KEY is not configured.", 503)
        return SecretBox(key.get_secret_value())

    def _totp_secret(self, user: User) -> str:
        if user.totp_secret is None:
            raise AppError("mfa_not_enrolled", "MFA is not enrolled.", 409)
        return self._box().decrypt(user.totp_secret, user.id.bytes).decode("ascii")

    def _user_by_email(self, email: str, *, lock: bool = False) -> User | None:
        # citext equality is case-insensitive and uses the unique index; 0003 stores lower case.
        stmt = select(User).where(User.email == normalize_email(email))
        if lock:
            # Serialize concurrent attempts on one account: the lockout counter and the TOTP
            # replay guard are read-modify-write and must not race. NO KEY UPDATE (key_share)
            # keeps FK checks from other inserts (audit, custody, tokens) from queueing behind it.
            stmt = stmt.with_for_update(key_share=True).execution_options(populate_existing=True)
        return self.session.execute(stmt).scalar_one_or_none()

    def _lock_user(self, user_id: uuid.UUID) -> User:
        user = self.session.execute(
            select(User)
            .where(User.id == user_id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError("User not found.")
        return user

    def _require_password(
        self, user: User, password: str | None, meta: RequestMeta, message: str
    ) -> None:
        """Re-authentication for sensitive actions; failures count towards the same lockout."""
        now = self.clock()
        if user.locked_until is not None and user.locked_until > now:
            raise self._locked_error(user, now)
        if not password or not verify_password(self.hasher, user.password_hash, password):
            self._register_failure(user, now, "bad_reauth_password", meta)
            self.session.commit()
            raise AppError("reauth_required", message, 403)

    def _locked_error(self, user: User, now: datetime) -> AppError:
        remaining = (user.locked_until - now).total_seconds() if user.locked_until else 0
        seconds = max(1, int(remaining) + 1)
        return AppError(
            "account_locked",
            "Too many failed attempts; the account is temporarily locked.",
            429,
            details={"retry_after_s": seconds},
            headers={"Retry-After": str(seconds)},
        )

    def _register_failure(self, user: User, now: datetime, reason: str, meta: RequestMeta) -> None:
        """Count a failed secret (caller holds the row lock on ``user``)."""
        s = self.settings
        user.failed_logins += 1
        detail: dict[str, Any] = {"reason": reason, "failed_logins": user.failed_logins}
        if user.failed_logins >= s.login_lockout_threshold:
            exponent = min(user.failed_logins - s.login_lockout_threshold, 20)
            seconds = min(s.login_lockout_base_s * 2**exponent, s.login_lockout_max_s)
            user.locked_until = now + timedelta(seconds=seconds)
            detail["locked_until"] = user.locked_until.isoformat()
        self.audit.record("auth.login_failed", user_id=user.id, meta=meta, detail=detail)

    def _check_password(self, user: User, password: str) -> None:
        problems = check_password_policy(password, user.email, self.settings.password_min_length)
        if problems:
            raise AppError(
                "weak_password",
                "Password does not meet the policy.",
                422,
                details={"problems": problems},
            )

    def _issue_refresh(
        self,
        user: User,
        family_id: uuid.UUID,
        session_started_at: datetime,
        now: datetime,
        meta: RequestMeta,
    ) -> tuple[str, RefreshToken]:
        plaintext = new_token(32)
        expires = min(
            now + timedelta(days=self.settings.refresh_token_days),
            session_started_at + timedelta(days=self.settings.session_absolute_days),
        )
        row = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            family_id=family_id,
            token_hash=sha256_hex(plaintext),
            issued_at=now,
            expires_at=expires,
            session_started_at=session_started_at,
            user_agent=(meta.user_agent or "")[:512] or None,
            ip=clean_ip(meta.ip),
        )
        self.session.add(row)
        return plaintext, row

    def _complete_login(
        self, user: User, now: datetime, meta: RequestMeta, method: str
    ) -> TokenPair:
        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = now
        access = self.jwt.issue_access(user.id, user.role.value, now)
        refresh, row = self._issue_refresh(user, uuid.uuid4(), now, now, meta)
        self.audit.record(
            "auth.login", user_id=user.id, meta=meta, detail={"method": method, "jti": access.jti}
        )
        return TokenPair(access.token, access.expires_at, refresh, row.expires_at)

    def _revoke_families(self, user_id: uuid.UUID, reason: str, family_id: uuid.UUID | None) -> int:
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=self.clock(), revoked_reason=reason)
        )
        if family_id is not None:
            stmt = stmt.where(RefreshToken.family_id == family_id)
        result = self.session.execute(stmt)
        return int(getattr(result, "rowcount", 0) or 0)

    def _get_user(self, user_id: uuid.UUID) -> User:
        user = self.session.get(User, user_id)
        if user is None:
            raise NotFoundError("User not found.")
        return user

    # ------------------------------------------------------------------ authentication

    def limit_attempts(self, kind: Literal["login", "refresh"], meta: RequestMeta) -> None:
        """Per client IP limit on authentication requests (guide 14.3, Phase 10).

        ``login`` covers password and MFA attempts, ``refresh`` token refreshes; fixed one-minute
        windows shared through Redis. The account lockout stays the per-account control.
        """
        if self.limiter is None:
            return
        limit = (
            self.settings.auth_rate_limit_per_minute
            if kind == "login"
            else self.settings.auth_refresh_rate_limit_per_minute
        )
        ip = clean_ip(meta.ip) or "unknown"
        try:
            self.limiter.hit(f"auth:{kind}:{ip}", limit, 60)
        except RateLimitedError as exc:
            self.audit.record("auth.rate_limited", user_id=None, meta=meta, detail={"kind": kind})
            self.session.commit()
            raise AppError(
                "rate_limited",
                "Too many attempts from this address; try again later.",
                429,
                details={"retry_after_s": exc.retry_after_s},
                headers={"Retry-After": str(exc.retry_after_s)},
            ) from exc
        except RateLimiterUnavailableError as exc:
            raise AppError("auth_unavailable", "Sign-in is temporarily unavailable.", 503) from exc

    def login(self, email: str, password: str, meta: RequestMeta) -> LoginResult:
        now = self.clock()
        user = self._user_by_email(email, lock=True)
        if user is None or not user.is_active or not user.password_hash:
            verify_password(self.hasher, None, password)  # equalize timing
            self.audit.record(
                "auth.login_failed",
                user_id=user.id if user else None,
                meta=meta,
                detail={"reason": "unknown_or_inactive", "email": email.strip()[:320]},
            )
            self.session.commit()
            raise invalid_credentials()
        if user.locked_until is not None and user.locked_until > now:
            self.audit.record("auth.login_locked", user_id=user.id, meta=meta)
            self.session.commit()
            raise self._locked_error(user, now)
        if not verify_password(self.hasher, user.password_hash, password):
            self._register_failure(user, now, "bad_password", meta)
            self.session.commit()
            raise invalid_credentials()
        if self.hasher.check_needs_rehash(user.password_hash):
            user.password_hash = hash_password(self.hasher, password)
        if user.mfa_enabled:
            challenge = self.jwt.issue_mfa_challenge(user.id, now)
            self.audit.record("auth.mfa_challenge", user_id=user.id, meta=meta)
            self.session.commit()
            return LoginResult(mfa_challenge=challenge.token, mfa_expires_at=challenge.expires_at)
        tokens = self._complete_login(user, now, meta, "password")
        self.session.commit()
        return LoginResult(tokens=tokens)

    def verify_mfa(
        self,
        challenge: str,
        meta: RequestMeta,
        *,
        code: str | None = None,
        recovery_code: str | None = None,
    ) -> TokenPair:
        now = self.clock()
        try:
            claims = self.jwt.decode(challenge, "mfa")
            user_id = uuid.UUID(claims["sub"])
        except (TokenError, ValueError) as exc:
            raise UnauthenticatedError(
                "MFA challenge is invalid or expired.", "token_invalid"
            ) from exc
        user = self.session.execute(
            select(User)
            .where(User.id == user_id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if user is None or not user.is_active or not user.mfa_enabled:
            raise UnauthenticatedError("MFA challenge is invalid or expired.", "token_invalid")
        if user.locked_until is not None and user.locked_until > now:
            raise self._locked_error(user, now)
        ok = False
        method = "totp"
        if code:
            step = match_totp_step(
                self._totp_secret(user), code, now=now, last_step=user.totp_last_step
            )
            if step is not None:
                user.totp_last_step = step
                ok = True
        elif recovery_code:
            method = "recovery_code"
            row = self.session.execute(
                select(MfaRecoveryCode)
                .where(
                    MfaRecoveryCode.user_id == user.id,
                    MfaRecoveryCode.code_hash == sha256_hex(normalize_recovery_code(recovery_code)),
                    MfaRecoveryCode.used_at.is_(None),
                )
                .with_for_update(key_share=True)
            ).scalar_one_or_none()
            if row is not None:
                row.used_at = now
                ok = True
        if not ok:
            self._register_failure(user, now, f"bad_{method}", meta)
            self.session.commit()
            raise AppError("mfa_invalid", "The MFA code is invalid or was already used.", 401)
        tokens = self._complete_login(user, now, meta, method)
        self.session.commit()
        return tokens

    def refresh(self, refresh_token: str, meta: RequestMeta) -> TokenPair:
        now = self.clock()
        row = self.session.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == sha256_hex(refresh_token))
            .with_for_update(key_share=True)
        ).scalar_one_or_none()
        if row is None:
            raise UnauthenticatedError("Refresh token is invalid.", "token_invalid")
        if row.revoked_at is not None:
            if row.revoked_reason == "rotated":
                # A rotated token came back: assume theft and kill the whole session family.
                self._revoke_families(row.user_id, "reuse_detected", row.family_id)
                self.audit.record(
                    "auth.refresh_reuse",
                    user_id=row.user_id,
                    meta=meta,
                    detail={"family_id": str(row.family_id)},
                )
                self.session.commit()
                raise UnauthenticatedError(
                    "Refresh token reuse detected; the session was revoked.", "refresh_reused"
                )
            raise UnauthenticatedError("Refresh token is revoked.", "token_invalid")
        if row.expires_at <= now:
            raise UnauthenticatedError("Refresh token expired.", "token_expired")
        user = self.session.get(User, row.user_id)
        if user is None or not user.is_active:
            self._revoke_families(row.user_id, "user_inactive", None)
            self.session.commit()
            raise UnauthenticatedError("Account is not active.", "token_invalid")
        # Rotation makes each refresh token single-use; the revoked predecessor remains available
        # above so replay can revoke the entire session family.
        plaintext, new_row = self._issue_refresh(
            user, row.family_id, row.session_started_at, now, meta
        )
        if new_row.expires_at <= now:
            self.session.expunge(new_row)
            raise UnauthenticatedError("Session lifetime exceeded; log in again.", "token_expired")
        row.revoked_at = now
        row.revoked_reason = "rotated"
        row.replaced_by = new_row.id
        access = self.jwt.issue_access(user.id, user.role.value, now)
        self.session.commit()
        return TokenPair(access.token, access.expires_at, plaintext, new_row.expires_at)

    def logout(self, refresh_token: str, meta: RequestMeta) -> None:
        row = self.session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(refresh_token))
        ).scalar_one_or_none()
        if row is not None:
            self._revoke_families(row.user_id, "logout", row.family_id)
            self.audit.record(
                "auth.logout", user_id=row.user_id, meta=meta, detail={"family": str(row.family_id)}
            )
        self.session.commit()

    def logout_all(self, principal: Principal, meta: RequestMeta) -> int:
        count = self._revoke_families(principal.user_id, "logout_all", None)
        self.audit.record(
            "auth.logout_all", user_id=principal.user_id, meta=meta, detail={"revoked": count}
        )
        self.session.commit()
        return count

    def sessions(self, principal: Principal) -> list[SessionInfo]:
        rows = self.session.execute(
            select(RefreshToken)
            .where(
                RefreshToken.user_id == principal.user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > self.clock(),
            )
            .order_by(RefreshToken.issued_at.desc())
        ).scalars()
        return [
            SessionInfo(
                family_id=r.family_id,
                started_at=r.session_started_at,
                last_refreshed_at=r.issued_at,
                expires_at=r.expires_at,
                ip=str(r.ip) if r.ip is not None else None,  # psycopg returns ipaddress objects
                user_agent=r.user_agent,
            )
            for r in rows
        ]

    def _principal(self, user: User, **extra: Any) -> Principal:
        return Principal(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            **extra,
        )

    def principal_from_access_token(self, token: str) -> Principal:
        try:
            claims = self.jwt.decode(token, "access")
            user_id = uuid.UUID(claims["sub"])
        except (TokenError, ValueError) as exc:
            raise UnauthenticatedError(
                "Access token is invalid or expired.", "token_invalid"
            ) from exc
        user = self.session.get(User, user_id)
        if user is None or not user.is_active:
            raise UnauthenticatedError("Access token is invalid or expired.", "token_invalid")
        # The role comes from the database, so role changes and deactivation apply immediately.
        return self._principal(user)

    def principal_from_api_key(self, key: str) -> Principal:
        now = self.clock()
        row = self.session.execute(
            select(ApiKey).where(ApiKey.key_hash == sha256_hex(key))
        ).scalar_one_or_none()
        if row is None or row.revoked_at is not None or (row.expires_at and row.expires_at <= now):
            raise UnauthenticatedError("API key is invalid, revoked or expired.", "token_invalid")
        user = self.session.get(User, row.user_id)
        if user is None or not user.is_active:
            raise UnauthenticatedError("API key is invalid, revoked or expired.", "token_invalid")
        if row.last_used_at is None or now - row.last_used_at > timedelta(minutes=1):
            row.last_used_at = now
            self.session.commit()
        return self._principal(
            user, auth_method="api_key", scopes=frozenset(row.scopes), api_key_id=row.id
        )

    # ------------------------------------------------------------------ self-service

    def get_user(self, user_id: uuid.UUID) -> User:
        return self._get_user(user_id)

    def change_password(
        self, principal: Principal, current: str, new: str, meta: RequestMeta
    ) -> None:
        user = self._lock_user(principal.user_id)
        self._require_password(user, current, meta, "Current password is incorrect.")
        self._check_password(user, new)
        user.password_hash = hash_password(self.hasher, new)
        revoked = self._revoke_families(user.id, "password_changed", None)
        self.audit.record(
            "user.password_changed",
            user_id=user.id,
            meta=meta,
            detail={"sessions_revoked": revoked},
        )
        self.session.commit()

    def mfa_enroll(self, principal: Principal, meta: RequestMeta) -> MfaEnrollment:
        user = self._lock_user(principal.user_id)  # a racing confirm must not see a new secret
        if user.mfa_enabled:
            raise ConflictError("MFA is already enabled; disable it first.", "mfa_already_enabled")
        secret = new_totp_secret()
        user.totp_secret = self._box().encrypt(secret.encode("ascii"), user.id.bytes)
        user.totp_last_step = None
        self.audit.record("user.mfa_enroll_started", user_id=user.id, meta=meta)
        self.session.commit()
        return MfaEnrollment(
            secret=secret, otpauth_uri=totp_uri(secret, user.email, self.settings.totp_issuer)
        )

    def _replace_recovery_codes(self, user: User) -> list[str]:
        for old in self.session.execute(
            select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)
        ).scalars():
            self.session.delete(old)
        codes = [new_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        for code in codes:
            self.session.add(
                MfaRecoveryCode(
                    user_id=user.id, code_hash=sha256_hex(normalize_recovery_code(code))
                )
            )
        return codes

    def mfa_confirm(self, principal: Principal, code: str, meta: RequestMeta) -> list[str]:
        user = self._lock_user(principal.user_id)
        if user.mfa_enabled:
            raise ConflictError("MFA is already enabled.", "mfa_already_enabled")
        step = match_totp_step(
            self._totp_secret(user), code, now=self.clock(), last_step=user.totp_last_step
        )
        if step is None:
            raise AppError("mfa_invalid", "The MFA code is invalid.", 400)
        user.mfa_enabled = True
        user.totp_last_step = step
        codes = self._replace_recovery_codes(user)
        self.audit.record("user.mfa_enabled", user_id=user.id, meta=meta)
        self.session.commit()
        return codes

    def mfa_disable(
        self, principal: Principal, password: str, code: str, meta: RequestMeta
    ) -> None:
        user = self._lock_user(principal.user_id)
        if not user.mfa_enabled:
            raise ConflictError("MFA is not enabled.", "mfa_not_enabled")
        self._require_password(user, password, meta, "Password is incorrect.")
        step = match_totp_step(
            self._totp_secret(user), code, now=self.clock(), last_step=user.totp_last_step
        )
        if step is None:
            self._register_failure(user, self.clock(), "bad_totp_reauth", meta)
            self.session.commit()
            raise AppError("mfa_invalid", "The MFA code is invalid.", 400)
        self._clear_mfa(user)
        self.audit.record("user.mfa_disabled", user_id=user.id, meta=meta)
        self.session.commit()

    def _clear_mfa(self, user: User) -> None:
        user.mfa_enabled = False
        user.totp_secret = None
        user.totp_last_step = None
        for old in self.session.execute(
            select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)
        ).scalars():
            self.session.delete(old)

    # ------------------------------------------------------------------ API keys

    def create_api_key(
        self,
        principal: Principal,
        name: str,
        scopes: list[str],
        expires_in_days: int | None,
        meta: RequestMeta,
    ) -> CreatedApiKey:
        if principal.auth_method != "jwt":
            raise ForbiddenError("API keys can only be created from an interactive login.")
        wanted = sorted(set(scopes or ["read"]))
        unknown = set(wanted) - API_KEY_SCOPES
        if unknown:
            raise AppError(
                "invalid_scope", "Unknown API key scope.", 422, details={"scopes": sorted(unknown)}
            )
        key = new_api_key()
        now = self.clock()
        row = ApiKey(
            user_id=principal.user_id,
            name=name,
            key_hash=sha256_hex(key),
            key_prefix=key[:12],
            scopes=wanted,
            expires_at=now + timedelta(days=expires_in_days) if expires_in_days else None,
        )
        self.session.add(row)
        self.session.flush()
        self.audit.record(
            "user.api_key_created",
            user_id=principal.user_id,
            meta=meta,
            object_type="api_key",
            object_id=row.id,
            detail={"scopes": wanted, "name": name},
        )
        self.session.commit()
        return CreatedApiKey(record=row, key=key)

    def list_api_keys(self, principal: Principal) -> list[ApiKey]:
        return list(
            self.session.execute(
                select(ApiKey)
                .where(ApiKey.user_id == principal.user_id)
                .order_by(ApiKey.created_at.desc())
            ).scalars()
        )

    def revoke_api_key(self, principal: Principal, key_id: uuid.UUID, meta: RequestMeta) -> None:
        row = self.session.get(ApiKey, key_id)
        if row is None or row.user_id != principal.user_id:
            raise NotFoundError("API key not found.")
        if row.revoked_at is None:
            row.revoked_at = self.clock()
            self.audit.record(
                "user.api_key_revoked",
                user_id=principal.user_id,
                meta=meta,
                object_type="api_key",
                object_id=row.id,
            )
        self.session.commit()

    # ------------------------------------------------------------------ administration

    def _create_user(self, email: str, display_name: str, role: UserRole, password: str) -> User:
        user = User(email=normalize_email(email), display_name=display_name.strip(), role=role)
        self._check_password(user, password)
        user.password_hash = hash_password(self.hasher, password)
        self.session.add(user)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError("A user with this e-mail already exists.", "email_taken") from exc
        return user

    def bootstrap_admin(self, email: str, display_name: str, password: str) -> User:
        """CLI bootstrap (no principal): create an admin, or return the existing admin account."""
        existing = self._user_by_email(email)
        if existing is not None:
            if existing.role is not UserRole.admin:
                raise ConflictError("User exists and is not an admin.", "email_taken")
            return existing
        user = self._create_user(email, display_name, UserRole.admin, password)
        self.audit.record(
            "user.created",
            user_id=None,
            object_type="user",
            object_id=user.id,
            detail={"via": "cli"},
        )
        self.session.commit()
        return user

    def list_users(self, principal: Principal) -> list[User]:
        require_global(principal, Permission.USERS_MANAGE)
        return list(self.session.execute(select(User).order_by(User.created_at)).scalars())

    def create_user(
        self,
        principal: Principal,
        *,
        email: str,
        display_name: str,
        role: UserRole,
        password: str,
        meta: RequestMeta,
    ) -> User:
        require_global(principal, Permission.USERS_MANAGE)
        user = self._create_user(email, display_name, role, password)
        self.audit.record(
            "user.created",
            user_id=principal.user_id,
            meta=meta,
            object_type="user",
            object_id=user.id,
            detail={"role": role.value},
        )
        self.session.commit()
        return user

    def _reauth(self, principal: Principal, admin_password: str | None, meta: RequestMeta) -> None:
        actor = self._lock_user(principal.user_id)
        self._require_password(
            actor,
            admin_password,
            meta,
            "Re-enter your password (admin_password) to confirm this change.",
        )

    def _lock_for_user_change(self, actor_id: uuid.UUID, target_id: uuid.UUID) -> User:
        """Lock the acting admin, the target and every active admin, in id order, in one statement.

        Two admins changing each other, or two changes racing for the last active admin, then
        queue on the same rows in the same order (no deadlock), and the last-admin count below is
        read while those rows are locked (Phase 10; BACKLOG Phase 1).
        """
        rows = self.session.execute(
            select(User)
            .where(
                or_(
                    User.id.in_([actor_id, target_id]),
                    and_(User.role == UserRole.admin, User.is_active.is_(True)),
                )
            )
            .order_by(User.id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        ).scalars()
        target = next((u for u in rows if u.id == target_id), None)
        if target is None:
            raise NotFoundError("User not found.")
        return target

    def _active_admins(self) -> int:
        return int(
            self.session.execute(
                select(func.count())
                .select_from(User)
                .where(User.role == UserRole.admin, User.is_active.is_(True))
            ).scalar_one()
        )

    def update_user(
        self,
        principal: Principal,
        user_id: uuid.UUID,
        *,
        meta: RequestMeta,
        display_name: str | None = None,
        role: UserRole | None = None,
        is_active: bool | None = None,
        reset_mfa: bool = False,
        unlock: bool = False,
        admin_password: str | None = None,
    ) -> User:
        require_global(principal, Permission.USERS_MANAGE)
        user = self._lock_for_user_change(principal.user_id, user_id)
        sensitive = (
            (role is not None and role is not user.role)
            or (is_active is not None and is_active != user.is_active)
            or reset_mfa
        )
        if sensitive:
            self._reauth(principal, admin_password, meta)
        changes: dict[str, Any] = {}
        losing_admin = (
            user.role is UserRole.admin
            and user.is_active
            and ((role is not None and role is not UserRole.admin) or is_active is False)
        )
        if losing_admin and self._active_admins() <= 1:
            raise ConflictError("Cannot remove the last active admin.", "last_admin")
        if display_name is not None and display_name.strip() != user.display_name:
            user.display_name = display_name.strip()
            changes["display_name"] = user.display_name
        if role is not None and role is not user.role:
            changes["role"] = {"from": user.role.value, "to": role.value}
            user.role = role
        if is_active is not None and is_active != user.is_active:
            user.is_active = is_active
            changes["is_active"] = is_active
            if not is_active:
                self._revoke_families(user.id, "deactivated", None)
        if reset_mfa and (user.mfa_enabled or user.totp_secret is not None):
            self._clear_mfa(user)
            changes["mfa_reset"] = True
        if unlock and (user.locked_until is not None or user.failed_logins):
            user.locked_until = None
            user.failed_logins = 0
            changes["unlocked"] = True
        if changes:
            action = "user.role_changed" if "role" in changes else "user.updated"
            self.audit.record(
                action,
                user_id=principal.user_id,
                meta=meta,
                object_type="user",
                object_id=user.id,
                detail=changes,
            )
        self.session.commit()
        return user
