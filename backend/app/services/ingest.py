"""SIEM/EDR webhook ingest (guide 15.2 ``POST /ingest/webhook/{integration}``, 19.3).

Order of checks (the router has already capped the body size while reading it):

1. A per-client-address rate limit (before anything is looked up).
2. Authentication: HMAC-SHA256 over ``timestamp + "." + raw body`` with the integration's secret,
   compared in constant time, timestamp inside the window. An unknown or disabled source, a bad
   signature and a stale timestamp all raise the same :class:`WebhookAuthError`; an HMAC is
   computed in every case (with a throwaway key when there is no source), so neither the answer
   nor its timing says which check failed.
3. A per-source rate limit.
4. Replay protection: the signed digest is the nonce, UNIQUE per integration in the append-only
   ``inbound_deliveries``. A delivery seen before is answered with its stored counts and changes
   nothing (ingest is idempotent).
5. The case comes from the integration row, never from the payload. ``FOR SHARE`` on the case
   row; a closed case refuses ingest.
6. Items are mapped by :mod:`app.integrations.inbound` (length caps, the pipeline's cleaning
   helpers). A malformed item is one counted error. Each good item is upserted into ``alerts``
   on ``(case, ext:<integration>:<sha256(external id)>)``, so a re-sent alert updates its row.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, InvalidStateError
from app.core.ratelimit import (
    RateLimitedError,
    RateLimiterUnavailableError,
    WindowLimiter,
)
from app.db.models import (
    Alert,
    AlertHistory,
    AlertStatus,
    Case,
    CaseStatus,
    InboundDelivery,
    Integration,
    Severity,
)
from app.detection.scoring import alert_risk
from app.integrations import messages as M  # noqa: N812
from app.integrations import webhooks
from app.integrations.crypto import (
    Keyring,
    SealedSecret,
    SecretDecryptError,
    SecretsUnavailableError,
    integration_aad,
)
from app.integrations.inbound import ExternalAlert, ItemError, PayloadError, map_item, parse_items
from app.services.audit import AuditService, clean_ip
from app.services.outbox import emit_event

log = structlog.stdlib.get_logger("dfirbench.ingest")

EXTERNAL_CONFIDENCE = 0.5
ADDRESS_LIMIT_FACTOR = 4  # per-address limit = factor x the per-source limit
# Used when there is no such source, so the HMAC work (and its timing) is the same.
_DUMMY_SECRET = secrets.token_hex(32)


def utcnow() -> datetime:
    return datetime.now(UTC)


class WebhookAuthError(AppError):
    """One answer for every authentication failure (no oracle)."""

    def __init__(self) -> None:
        super().__init__("webhook_unauthenticated", "Webhook authentication failed.", 401)


@dataclass
class IngestOutcome:
    duplicate: bool = False
    items: int = 0
    created: int = 0
    updated: int = 0
    errors: int = 0
    error_reasons: dict[str, int] = field(default_factory=dict)


class WebhookIngestService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        limiter: WindowLimiter,
        keyring: Keyring | None = None,
        clock: Callable[[], datetime] = utcnow,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.session = session
        self.settings = settings
        self.limiter = limiter
        self._keyring = keyring
        self.clock = clock
        self.wall_clock = wall_clock
        self.audit = AuditService(session)

    def _hit(self, key: str, limit: int) -> None:
        try:
            self.limiter.hit(key, limit, 60)
        except RateLimitedError as exc:
            raise AppError(
                "rate_limited",
                "Too many deliveries; try again later.",
                429,
                headers={"Retry-After": str(exc.retry_after_s)},
            ) from exc
        except RateLimiterUnavailableError as exc:
            raise AppError("ingest_unavailable", "Ingest is temporarily unavailable.", 503) from exc

    def _source(self, integration_ref: str) -> tuple[Integration | None, str]:
        """The enabled ingest source and its signing secret, or (None, a throwaway secret)."""
        try:
            integration_id = uuid.UUID(integration_ref)
        except ValueError:
            return None, _DUMMY_SECRET
        row = self.session.get(Integration, integration_id)
        if (
            row is None
            or row.type != "webhook_in"
            or not row.enabled
            or row.case_id is None
            or row.config_encrypted is None
            or not row.secret_wrapped_key
            or not row.secret_key_id
        ):
            return None, _DUMMY_SECRET
        try:
            if self._keyring is None:
                self._keyring = Keyring.from_settings(self.settings)
            sealed = SealedSecret(
                bytes(row.config_encrypted), bytes(row.secret_wrapped_key), row.secret_key_id
            )
            secret = self._keyring.open(sealed, integration_aad(row.id)).get("signing_secret")
        except (SecretsUnavailableError, SecretDecryptError):
            log.error("ingest_secret_unavailable", integration_id=str(row.id))
            return None, _DUMMY_SECRET
        if not isinstance(secret, str) or not secret:
            return None, _DUMMY_SECRET
        return row, secret

    def ingest(
        self,
        integration_ref: str,
        *,
        timestamp: str | None,
        signature: str | None,
        body: bytes,
        ip: str | None,
    ) -> IngestOutcome:
        per_source = self.settings.ingest_rate_limit_per_minute
        self._hit(f"ingest:ip:{clean_ip(ip) or 'unknown'}", per_source * ADDRESS_LIMIT_FACTOR)
        source, secret = self._source(integration_ref)
        nonce = webhooks.verify(
            secret,
            timestamp,
            body,
            signature,
            now=self.wall_clock(),
            window_s=self.settings.ingest_timestamp_window_s,
        )
        if source is None or nonce is None:
            self.session.rollback()
            raise WebhookAuthError()
        self._hit(f"ingest:src:{source.id}", per_source)
        if source.case_id is None:  # checked in _source; narrows the type
            raise WebhookAuthError()
        case_id: uuid.UUID = source.case_id
        seen = self._seen(source.id, nonce)
        if seen is not None:
            self.session.commit()
            return seen
        try:
            items = parse_items(body, self.settings.ingest_max_items)
        except PayloadError as exc:
            self.session.rollback()
            raise AppError(exc.code, str(exc), 422) from exc

        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case of this source is closed; ingest is refused.")
        outcome = IngestOutcome(items=len(items))
        reasons: Counter[str] = Counter()
        now = self.clock()
        field_map = dict((source.config or {}).get("field_map") or {})
        created_alerts: list[tuple[uuid.UUID, ExternalAlert]] = []
        for item in items:
            try:
                alert = map_item(item, field_map, now)
            except ItemError as exc:
                reasons[exc.reason] += 1
                continue
            alert_id, created = self._upsert(source, case_id, alert, now)
            if created:
                outcome.created += 1
                created_alerts.append((alert_id, alert))
            else:
                outcome.updated += 1
        outcome.errors = sum(reasons.values())
        outcome.error_reasons = dict(sorted(reasons.items()))
        try:
            with self.session.begin_nested():
                self.session.add(
                    InboundDelivery(
                        integration_id=source.id,
                        case_id=case_id,
                        nonce=nonce,
                        source_ip=clean_ip(ip),
                        body_sha256=hashlib.sha256(body).hexdigest(),
                        items=outcome.items,
                        created=outcome.created,
                        updated=outcome.updated,
                        errors=outcome.errors,
                        error_reasons=outcome.error_reasons,
                    )
                )
                self.session.flush()
        except IntegrityError:
            # The same delivery was accepted concurrently: undo our copy and answer like it.
            self.session.rollback()
            seen = self._seen(source.id, nonce)
            self.session.commit()
            return seen or IngestOutcome(duplicate=True)
        for alert_id, alert in created_alerts:
            emit_event(
                self.session,
                M.EVENT_ALERT_CREATED,
                case_id=case_id,
                payload={
                    "alert_id": str(alert_id),
                    "severity": alert.severity,
                    "source": "ingest",
                    "event_count": 1,
                    "attack": list(alert.attack),
                },
                details={"title": alert.title, "host": alert.host},
                dedup_key=f"{M.EVENT_ALERT_CREATED}:{alert_id}",
            )
        source.last_status = "ok" if not outcome.errors else f"{outcome.errors} item errors"
        source.last_status_at = now
        self.audit.record(
            "ingest.webhook",
            object_type="integration",
            object_id=source.id,
            detail={
                "case_id": str(case_id),
                "items": outcome.items,
                "created": outcome.created,
                "updated": outcome.updated,
                "errors": outcome.errors,
                "error_reasons": outcome.error_reasons,
                "source_ip": clean_ip(ip),
            },
        )
        self.session.commit()
        return outcome

    def _seen(self, integration_id: uuid.UUID, nonce: str) -> IngestOutcome | None:
        row = self.session.execute(
            select(InboundDelivery).where(
                InboundDelivery.integration_id == integration_id, InboundDelivery.nonce == nonce
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        return IngestOutcome(
            duplicate=True,
            items=row.items,
            created=row.created,
            updated=row.updated,
            errors=row.errors,
            error_reasons={str(k): int(v) for k, v in (row.error_reasons or {}).items()},
        )

    def _upsert(
        self, source: Integration, case_id: uuid.UUID, alert: ExternalAlert, now: datetime
    ) -> tuple[uuid.UUID, bool]:
        severity = Severity(alert.severity)
        details: dict[str, Any] = {
            "source": "webhook_ingest",
            "integration_id": str(source.id),
            "integration": source.name,
            "external_id": alert.external_id,
            "ts_original": alert.ts_original,
            "ts_source": alert.ts_source,
            "description": alert.description,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "raw": alert.raw,
        }
        insert = pg_insert(Alert).values(
            case_id=case_id,
            rule_id=None,
            title=alert.title[:500],
            severity=severity,
            confidence=EXTERNAL_CONFIDENCE,
            risk_score=alert_risk(severity.value, EXTERNAL_CONFIDENCE),
            host=alert.host,
            user=alert.user,
            attack_tags=list(alert.attack),
            dedup_key=f"ext:{source.id}:{alert.id_sha256}",
            first_seen=alert.ts,
            last_seen=alert.ts,
            event_count=1,
            details=details,
            stale=False,
        )
        ex = insert.excluded
        stmt: Any = insert.on_conflict_do_update(
            constraint="uq_alerts_case_id_dedup_key",
            set_={
                "title": ex["title"],
                "severity": ex["severity"],
                "risk_score": ex["risk_score"],
                "host": ex["host"],
                "user": ex["user"],
                "attack_tags": ex["attack_tags"],
                "first_seen": func.least(Alert.first_seen, ex["first_seen"]),
                "last_seen": func.greatest(Alert.last_seen, ex["last_seen"]),
                "details": ex["details"],
                "updated_at": func.now(),
            },
        ).returning(Alert.id, literal_column("(xmax = 0)").label("inserted"))
        row = self.session.execute(stmt).one()
        if row.inserted:
            self.session.add(
                AlertHistory(
                    alert_id=row.id,
                    action="created",
                    to_status=AlertStatus.new,
                    reason=f"webhook ingest: {source.name}"[:200],
                )
            )
        return row.id, bool(row.inserted)
