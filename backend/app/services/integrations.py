"""Integration configuration (guide 15.2 ``/integrations``, 19.3). Admin only (``users:manage``).

* ``config`` is validated per type (``schemas/integrations.py``); URLs must pass the outbound
  policy's shape checks when they are saved (the address check happens at send time, against the
  address actually connected to).
* Secrets are write-only: they are envelope-encrypted before they reach the row
  (:mod:`app.integrations.crypto`), never returned, and never written to the audit log (audit
  rows say which *names* changed and whether the secret changed).
* Rows are locked ``FOR UPDATE`` for every change and are never deleted (delivery logs reference
  them): an integration is disabled instead.
* An integration can only be enabled when it is complete (required secret present, ingest
  sources bound to an existing case).
"""

from __future__ import annotations

import contextlib
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, ConflictError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import (
    Case,
    InboundDelivery,
    Integration,
    OutboundDelivery,
    OutboundEvent,
)
from app.integrations import messages as M  # noqa: N812
from app.integrations.crypto import (
    Keyring,
    SealedSecret,
    SecretDecryptError,
    SecretsUnavailableError,
    integration_aad,
)
from app.integrations.inbound import validate_field_map
from app.integrations.outbound import (
    OutboundBlockedError,
    OutboundError,
    OutboundPolicy,
    check_url,
    resolve_target,
    valid_address,
)
from app.schemas.integrations import CONFIG_MODELS, SECRET_FIELDS
from app.services.audit import AuditService, RequestMeta
from app.services.authz import require_global
from app.services.outbox import DELIVERY_KINDS, emit_event

log = structlog.stdlib.get_logger("dfirbench.integrations")

MAX_SECRET_CHARS = 4096
MAX_LOG_ROWS = 100


def utcnow() -> datetime:
    return datetime.now(UTC)


def _invalid(message: str, **details: Any) -> AppError:
    return AppError("invalid_integration", message, 422, details)


def _no_literal_resolver(host: str, port: int) -> list[str]:
    raise OSError("names are resolved when a request is sent")


class IntegrationService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        keyring: Keyring | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.session = session
        self.settings = settings
        self._keyring = keyring
        self.clock = clock
        self.policy = OutboundPolicy.from_settings(settings)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers

    def secrets_available(self) -> bool:
        try:
            self.keyring()
        except SecretsUnavailableError:
            return False
        return True

    def keyring(self) -> Keyring:
        if self._keyring is None:
            self._keyring = Keyring.from_settings(self.settings)
        return self._keyring

    def _check_url(self, url: str, what: str) -> None:
        try:
            target = check_url(url, self.policy)
            # An IP literal is judged now; a host name is resolved (once) at send time.
            with contextlib.suppress(OutboundError):
                resolve_target(target.host, target.port, self.policy, _no_literal_resolver)
        except OutboundBlockedError as exc:
            raise _invalid(
                f"{what} is not allowed by the outbound policy ({exc.reason}).", reason=exc.reason
            ) from exc

    def _clean_config(self, kind: str, config: Mapping[str, Any]) -> dict[str, Any]:
        model = CONFIG_MODELS[kind]
        try:
            parsed = model.model_validate(dict(config))
        except ValidationError as exc:
            errors = [
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"[:200]
                for e in exc.errors(include_url=False, include_input=False)[:20]
            ]
            raise _invalid("The configuration is not valid for this type.", errors=errors) from exc
        clean = parsed.model_dump(mode="json")
        if kind == "webhook_out":
            self._check_url(clean["url"], "The webhook URL")
        elif kind == "virustotal":
            self._check_url(clean["base_url"], "The base URL")
        elif kind == "misp":
            self._check_url(clean["url"], "The MISP URL")
        elif kind == "webhook_in":
            try:
                clean["field_map"] = validate_field_map(clean["field_map"])
            except ValueError as exc:
                raise _invalid(str(exc)) from exc
        elif kind == "email":
            addresses = [clean["sender"], *clean["recipients"]]
            if not all(valid_address(a) for a in addresses):
                raise _invalid("Sender and recipients must be plain e-mail addresses.")
            if clean["security"] == "none" and not self.policy.allow_http:
                raise _invalid("SMTP without TLS needs OUTBOUND_ALLOW_HTTP (development only).")
        return clean

    def _clean_secret(self, kind: str, secret: Mapping[str, SecretStr]) -> dict[str, str]:
        allowed = {name: minimum for name, _, minimum in SECRET_FIELDS[kind]}
        out: dict[str, str] = {}
        for name, value in secret.items():
            if name not in allowed:
                raise _invalid(
                    "Unknown secret field for this type.", allowed=sorted(allowed), field=name[:40]
                )
            text = value.get_secret_value()
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in text) or not (
                allowed[name] <= len(text) <= MAX_SECRET_CHARS
            ):
                raise _invalid(
                    f"Secret '{name}' must be {allowed[name]}-{MAX_SECRET_CHARS} characters "
                    "without control characters."
                )
            out[name] = text
        if kind in ("slack", "teams") and "webhook_url" in out:
            self._check_url(out["webhook_url"], "The webhook URL")
        return out

    def _seal(self, row: Integration, secret: Mapping[str, str]) -> None:
        try:
            keyring = self.keyring()
        except SecretsUnavailableError as exc:
            raise AppError(
                "secrets_unavailable",
                "No key-encryption key is configured (INTEGRATION_KEK); secrets cannot be saved.",
                503,
            ) from exc
        sealed = keyring.seal(secret, integration_aad(row.id))
        row.config_encrypted = sealed.ciphertext
        row.secret_wrapped_key = sealed.wrapped_key
        row.secret_key_id = sealed.key_id
        row.secret_fingerprint = keyring.fingerprint(secret)

    def _require_complete(self, row: Integration) -> None:
        required = [name for name, needed, _ in SECRET_FIELDS[row.type] if needed]
        if required and row.config_encrypted is None:
            raise _invalid(f"Set the secret ({', '.join(required)}) before enabling.")
        if row.type == "webhook_in" and row.case_id is None:
            raise _invalid("An ingest source needs the case its alerts go to.")
        if row.type in DELIVERY_KINDS and not (row.config or {}).get("events"):
            raise _invalid("Choose at least one event before enabling.")
        self._clean_config(row.type, row.config or {})  # e.g. empty after a schema downgrade

    def _check_case(self, case_id: uuid.UUID | None) -> None:
        if case_id is not None and self.session.get(Case, case_id) is None:
            raise NotFoundError("Case not found.")

    def _lock(self, integration_id: uuid.UUID) -> Integration:
        row = self.session.execute(
            select(Integration)
            .where(Integration.id == integration_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if row is None:
            self.session.rollback()
            raise NotFoundError("Integration not found.")
        return row

    def _audit(
        self, action: str, principal: Principal, meta: RequestMeta, row: Integration, **detail: Any
    ) -> None:
        self.audit.record(
            action,
            user_id=principal.user_id,
            meta=meta,
            object_type="integration",
            object_id=row.id,
            detail={"type": row.type, "name": row.name, **detail},
        )

    # ------------------------------------------------------------------ read

    def list_all(self, principal: Principal) -> list[Integration]:
        require_global(principal, Permission.USERS_MANAGE)
        rows = list(self.session.execute(select(Integration).order_by(Integration.name)).scalars())
        self.session.commit()
        return rows

    def get(self, principal: Principal, integration_id: uuid.UUID) -> Integration:
        require_global(principal, Permission.USERS_MANAGE)
        row = self.session.get(Integration, integration_id)
        if row is None:
            raise NotFoundError("Integration not found.")
        return row

    def deliveries(
        self, principal: Principal, integration_id: uuid.UUID
    ) -> tuple[list[OutboundDelivery], list[InboundDelivery]]:
        self.get(principal, integration_id)
        outbound = list(
            self.session.execute(
                select(OutboundDelivery)
                .where(OutboundDelivery.integration_id == integration_id)
                .order_by(OutboundDelivery.created_at.desc(), OutboundDelivery.id)
                .limit(MAX_LOG_ROWS)
            ).scalars()
        )
        inbound = list(
            self.session.execute(
                select(InboundDelivery)
                .where(InboundDelivery.integration_id == integration_id)
                .order_by(InboundDelivery.id.desc())
                .limit(MAX_LOG_ROWS)
            ).scalars()
        )
        self.session.commit()
        return outbound, inbound

    # ------------------------------------------------------------------ write

    def create(
        self,
        principal: Principal,
        meta: RequestMeta,
        *,
        kind: str,
        name: str,
        config: Mapping[str, Any],
        secret: Mapping[str, SecretStr] | None,
        enabled: bool,
        case_id: uuid.UUID | None,
    ) -> Integration:
        require_global(principal, Permission.USERS_MANAGE)
        if kind not in CONFIG_MODELS:
            raise _invalid("Unknown integration type.", allowed=sorted(CONFIG_MODELS))
        if case_id is not None and kind != "webhook_in":
            raise _invalid("Only an ingest source (webhook_in) is bound to a case.")
        clean = self._clean_config(kind, config)
        clean_secret = self._clean_secret(kind, secret) if secret else None
        self._check_case(case_id)
        now = self.clock()
        row = Integration(
            id=uuid.uuid4(),
            type=kind,
            name=name.strip(),
            config=clean,
            enabled=False,
            case_id=case_id,
            created_by=principal.user_id,
            updated_by=principal.user_id,
            created_at=now,
            updated_at=now,
        )
        if clean_secret:
            self._seal(row, clean_secret)
        if enabled:
            self._require_complete(row)
            row.enabled = True
        self.session.add(row)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError("An integration with this name exists.", "name_taken") from exc
        self._audit(
            "integration.created",
            principal,
            meta,
            row,
            enabled=row.enabled,
            has_secret=row.config_encrypted is not None,
            config_keys=sorted(clean),
        )
        self.session.commit()
        return row

    def update(
        self,
        principal: Principal,
        integration_id: uuid.UUID,
        meta: RequestMeta,
        *,
        name: str | None = None,
        config: Mapping[str, Any] | None = None,
        secret: Mapping[str, SecretStr] | None = None,
        enabled: bool | None = None,
        case_id: uuid.UUID | None = None,
    ) -> Integration:
        require_global(principal, Permission.USERS_MANAGE)
        row = self._lock(integration_id)
        changed: list[str] = []
        try:
            if name is not None and name.strip() != row.name:
                row.name = name.strip()
                changed.append("name")
            if config is not None:
                clean = self._clean_config(row.type, config)
                if clean != row.config:
                    row.config = clean
                    changed.append("config")
            if case_id is not None and case_id != row.case_id:
                if row.type != "webhook_in":
                    raise _invalid("Only an ingest source (webhook_in) is bound to a case.")
                self._check_case(case_id)
                row.case_id = case_id
                changed.append("case_id")
            if secret:
                self._seal(row, self._clean_secret(row.type, secret))
                changed.append("secret")
            if enabled is not None and enabled != row.enabled:
                changed.append("enabled")
            target_enabled = row.enabled if enabled is None else enabled
            if target_enabled:
                self._require_complete(row)
            row.enabled = target_enabled
        except Exception:
            self.session.rollback()  # release the row lock
            raise
        if changed:
            row.updated_at = self.clock()
            row.updated_by = principal.user_id
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError("An integration with this name exists.", "name_taken") from exc
        self._audit(
            "integration.updated",
            principal,
            meta,
            row,
            changed=changed,
            enabled=row.enabled,
            secret_changed="secret" in changed,
        )
        self.session.commit()
        return row

    def test(self, principal: Principal, integration_id: uuid.UUID, meta: RequestMeta) -> uuid.UUID:
        """Queue one ``integration.test`` event for this integration only."""
        require_global(principal, Permission.USERS_MANAGE)
        row = self._lock(integration_id)
        if row.type not in DELIVERY_KINDS:
            self.session.rollback()
            raise _invalid("Only webhooks and notification channels can be tested this way.")
        if not row.enabled:
            self.session.rollback()
            raise AppError("integration_disabled", "Enable the integration first.", 409)
        key = f"{M.EVENT_TEST}:{row.id}:{uuid.uuid4()}"
        if (
            emit_event(
                self.session,
                M.EVENT_TEST,
                case_id=None,
                payload={},
                dedup_key=key,
                only_integration_id=row.id,
            )
            != "created"
        ):
            self.session.rollback()
            raise AppError("event_not_queued", "The test event could not be queued.", 503)
        event_id = self.session.execute(
            select(OutboundEvent.id).where(OutboundEvent.dedup_key == key)
        ).scalar_one()
        self._audit("integration.tested", principal, meta, row, event_id=str(event_id))
        self.session.commit()
        return event_id

    # ------------------------------------------------------------------ key rotation

    def rewrap_all(self) -> dict[str, int]:
        """Re-wrap every data key under the current KEK (operator CLI; commits)."""
        keyring = self.keyring()
        counts = {"rewrapped": 0, "current": 0, "failed": 0}
        rows = self.session.execute(
            select(Integration)
            .where(Integration.config_encrypted.is_not(None))
            .order_by(Integration.id)
            .with_for_update()
        ).scalars()
        for row in rows:
            if row.config_encrypted is None or not row.secret_wrapped_key or not row.secret_key_id:
                continue
            sealed = SealedSecret(
                bytes(row.config_encrypted), bytes(row.secret_wrapped_key), row.secret_key_id
            )
            if not keyring.needs_rewrap(sealed):
                counts["current"] += 1
                continue
            try:
                new = keyring.rewrap(sealed, integration_aad(row.id))
            except SecretDecryptError:
                log.error("integration_rewrap_failed", integration_id=str(row.id))
                counts["failed"] += 1
                continue
            row.secret_wrapped_key = new.wrapped_key
            row.secret_key_id = new.key_id
            row.secret_fingerprint = keyring.fingerprint(keyring.open(new, integration_aad(row.id)))
            counts["rewrapped"] += 1
        self.audit.record("integration.rewrapped", detail=dict(counts))
        self.session.commit()
        return counts
