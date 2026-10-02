"""Outbox for outbound webhooks and notifications (guide 15.6, 19.4).

Emitting (business services)
    :func:`emit_event` inserts one ``outbound_events`` row inside a SAVEPOINT of the caller's
    transaction and never raises: a failure is logged and the business transaction goes on. The
    payload holds identifiers and enumerated values (text from evidence goes under ``details``).
    After the transaction commits, a session hook asks the dispatcher found in ``session.info``
    (set only by the process-wide session factory, so tests are inert unless they opt in) to run
    the worker task; a dispatch failure is logged and swallowed. The task takes no arguments, so
    nothing secret or case-specific ever travels through the broker.

Delivering (worker, :class:`OutboundService`)
    * Fan-out, serialized by an advisory lock: each new event gets one ``outbound_deliveries`` row
      per enabled integration that subscribes to it, and in-app notifications per the rules.
      Notifications to people (Slack, Teams, e-mail, in-app) are deduplicated within
      ``NOTIFY_DEDUP_WINDOW_S`` and rate-limited per channel per hour; what is dropped is
      recorded as ``suppressed``.
    * Delivery: an attempt is claimed under ``FOR UPDATE SKIP LOCKED`` with a lease, sent with no
      transaction open, and recorded under the row lock: ``delivered``, back to ``pending`` with
      exponential backoff, or ``failed`` for good after ``max_attempts`` or a permanent error.
      ``last_error`` stores an error category only (never a URL, header, body or secret).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import event as sa_event
from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.core.permissions import Permission, effective_case_permissions
from app.db.models import (
    Case,
    CaseMember,
    Integration,
    Notification,
    OutboundDelivery,
    OutboundEvent,
    Setting,
    User,
    UserRole,
)
from app.integrations import messages as M  # noqa: N812
from app.integrations import webhooks
from app.integrations.crypto import (
    Keyring,
    SealedSecret,
    SecretDecryptError,
    SecretsUnavailableError,
    integration_aad,
)
from app.integrations.outbound import (
    HttpResponse,
    MailServer,
    OutboundBlockedError,
    OutboundError,
    OutboundHttp,
    OutboundMailer,
    OutboundPolicy,
)

log = structlog.stdlib.get_logger("dfirbench.outbox")

DISPATCH_KEY = "outbound_dispatch"  # session.info: callable run after a commit with new events
PENDING_KEY = "outbound_pending"
FANOUT_LOCK = int.from_bytes(
    hashlib.sha256(b"dfir_outbound_fanout").digest()[:8], "big", signed=True
)
DELIVERY_KINDS = ("webhook_out", "slack", "teams", "email")
PEOPLE_KINDS = ("slack", "teams", "email")  # deduplicated; webhooks get every event
RULES_KEY = "notification_rules"
RECIPIENTS = ("admins", "case_lead", "case_members", "case_approvers")
MAX_BACKOFF_S = 3600
FANOUT_BATCH = 100
SEVERITY_RANK = {name: rank for rank, name in enumerate(M.SEVERITIES)}

DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {
        "event": M.EVENT_ALERT_CREATED,
        "min_severity": "high",
        "recipients": ["case_lead"],
        "enabled": True,
    },
    {"event": M.EVENT_EVIDENCE_FAILED, "recipients": ["admins"], "enabled": True},
    {"event": M.EVENT_REPORT_SIGNED, "recipients": ["case_members"], "enabled": True},
    {"event": M.EVENT_APPROVAL_REQUESTED, "recipients": ["case_approvers"], "enabled": True},
)


def utcnow() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------------------ emitting


def emit_event(
    session: Session,
    event_type: str,
    *,
    case_id: uuid.UUID | None,
    payload: Mapping[str, Any],
    dedup_key: str | None = None,
    details: Mapping[str, Any] | None = None,
    only_integration_id: uuid.UUID | None = None,
) -> str:
    """Queue an event in the caller's transaction. Returns ``created``, ``duplicate`` or
    ``error``; never raises and never breaks the surrounding transaction."""
    try:
        with session.begin_nested():
            body: dict[str, Any] = {"event": event_type, **dict(payload)}
            if case_id is not None:
                body["case_id"] = str(case_id)
                number = session.execute(
                    select(Case.case_number).where(Case.id == case_id)
                ).scalar_one_or_none()
                if number:
                    body["case_number"] = number
            if details:
                body["details"] = {
                    str(k)[:32]: M.plain(v) for k, v in details.items() if v is not None
                }
            stmt = (
                pg_insert(OutboundEvent)
                .values(
                    id=uuid.uuid4(),
                    event_type=event_type,
                    case_id=case_id,
                    payload=body,
                    dedup_key=dedup_key[:300] if dedup_key else None,
                    only_integration_id=only_integration_id,
                )
                .on_conflict_do_nothing(index_elements=["dedup_key"])
                .returning(OutboundEvent.id)
            )
            created = session.execute(stmt).scalar_one_or_none()
        if created is None:
            return "duplicate"
        session.info[PENDING_KEY] = True
        return "created"
    except Exception as exc:  # noqa: BLE001 - an event must never fail the business transaction
        log.error("outbound_emit_failed", event_type=event_type, exc_type=type(exc).__name__)
        return "error"


def emit_verification_failed(
    session: Session,
    case_id: uuid.UUID | None,
    evidence_id: uuid.UUID | None,
    stage: str,
    label: str | None = None,
) -> str:
    """``evidence.verification_failed`` (at most one event per evidence item and hour)."""
    bucket = utcnow().strftime("%Y%m%d%H")
    return emit_event(
        session,
        M.EVENT_EVIDENCE_FAILED,
        case_id=case_id,
        payload={"evidence_id": str(evidence_id), "stage": stage},
        details={"label": label} if label else None,
        dedup_key=f"{M.EVENT_EVIDENCE_FAILED}:{evidence_id}:{bucket}",
    )


@sa_event.listens_for(Session, "after_commit")
def _dispatch_after_commit(session: Session) -> None:
    if not session.info.pop(PENDING_KEY, False):
        return
    dispatch = session.info.get(DISPATCH_KEY)
    if dispatch is None:
        return
    try:
        dispatch()
    except Exception as exc:  # noqa: BLE001 - the worker also picks events up on its next run
        log.warning("outbound_dispatch_failed", exc_type=type(exc).__name__)


@sa_event.listens_for(Session, "after_soft_rollback")
def _forget_after_rollback(session: Session, previous_transaction: Any) -> None:
    # Only the root transaction: a rolled-back SAVEPOINT leaves events emitted before it in the
    # outer transaction, and they still need their dispatch after commit.
    if previous_transaction.parent is None:
        session.info.pop(PENDING_KEY, None)


# ------------------------------------------------------------------------------ rules


def clean_rules(value: Any) -> list[dict[str, Any]]:
    """Validated in-app notification rules (raises ValueError)."""
    if not isinstance(value, list) or len(value) > 50:
        raise ValueError("rules must be a list of at most 50 items")
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {
            "event",
            "min_severity",
            "recipients",
            "enabled",
        }:
            raise ValueError("a rule has: event, recipients, min_severity, enabled")
        if item.get("event") not in M.SUBSCRIBABLE_EVENTS:
            raise ValueError(f"event must be one of {', '.join(M.SUBSCRIBABLE_EVENTS)}")
        recipients = item.get("recipients")
        if (
            not isinstance(recipients, list)
            or not recipients
            or any(r not in RECIPIENTS for r in recipients)
        ):
            raise ValueError(f"recipients must be a non-empty subset of {', '.join(RECIPIENTS)}")
        severity = item.get("min_severity")
        if severity is not None and severity not in M.SEVERITIES:
            raise ValueError(f"min_severity must be one of {', '.join(M.SEVERITIES)}")
        out.append(
            {
                "event": item["event"],
                "min_severity": severity,
                "recipients": sorted(set(recipients)),
                "enabled": item.get("enabled", True) is not False,
            }
        )
    return out


def load_rules(session: Session) -> list[dict[str, Any]]:
    row = session.get(Setting, RULES_KEY)
    if row is None:
        return clean_rules([dict(r) for r in DEFAULT_RULES])
    try:
        return clean_rules(row.value)
    except ValueError:
        log.error("notification_rules_invalid")
        return []


def _severity_ok(payload: Mapping[str, Any], minimum: str | None) -> bool:
    if not minimum:
        return True
    rank = SEVERITY_RANK.get(str(payload.get("severity")))
    return rank is None or rank >= SEVERITY_RANK[minimum]


def notification_key(event: OutboundEvent) -> str:
    """Events that say the same thing to a person share a key (deduplicated in the window)."""
    p = event.payload or {}
    if event.event_type == M.EVENT_ALERT_CREATED:
        return f"alert:{event.case_id}:{p.get('rule_id') or 'external'}:{p.get('severity')}"[:300]
    if event.event_type == M.EVENT_EVIDENCE_FAILED:
        return f"evidence:{p.get('evidence_id')}"[:300]
    return f"{event.event_type}:{event.id}"


# ------------------------------------------------------------------------------ delivering


class _PermanentError(Exception):
    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass
class ProcessResult:
    events: int = 0
    deliveries: int = 0
    notifications: int = 0
    suppressed: int = 0
    attempted: int = 0
    delivered: int = 0
    retried: int = 0
    failed: int = 0
    more: bool = False
    retry_in_s: int | None = None  # soonest retry this run scheduled

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Attempt:
    delivery_id: uuid.UUID
    attempts: int
    kind: str
    send: Callable[[], HttpResponse | None]


class OutboundService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        settings: Settings,
        *,
        http: OutboundHttp | None = None,
        mailer: OutboundMailer | None = None,
        keyring: Keyring | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.sessions = sessions
        self.settings = settings
        policy = OutboundPolicy.from_settings(settings)
        self.http = http or OutboundHttp(policy)
        self.mailer = mailer or OutboundMailer(policy)
        self._keyring = keyring
        self.clock = clock

    def keyring(self) -> Keyring:
        if self._keyring is None:
            self._keyring = Keyring.from_settings(self.settings)
        return self._keyring

    def process(self) -> ProcessResult:
        result = ProcessResult()
        self.fan_out(result)
        self.deliver_due(result)
        return result

    # ------------------------------------------------------------------ fan-out

    def fan_out(self, result: ProcessResult) -> None:
        while True:
            with self.sessions() as session:
                session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": FANOUT_LOCK})
                events = list(
                    session.execute(
                        select(OutboundEvent)
                        .where(OutboundEvent.fanned_out_at.is_(None))
                        .order_by(OutboundEvent.created_at, OutboundEvent.id)
                        .limit(FANOUT_BATCH)
                        .with_for_update(skip_locked=True)
                    ).scalars()
                )
                if not events:
                    session.commit()
                    return
                integrations = list(
                    session.execute(
                        select(Integration)
                        .where(Integration.enabled.is_(True), Integration.type.in_(DELIVERY_KINDS))
                        .order_by(Integration.name)
                    ).scalars()
                )
                rules = [r for r in load_rules(session) if r["enabled"]]
                now = self.clock()
                for event in events:
                    self._fan_out_one(session, event, integrations, rules, now, result)
                    event.fanned_out_at = now
                    result.events += 1
                session.commit()

    def _fan_out_one(
        self,
        session: Session,
        event: OutboundEvent,
        integrations: Sequence[Integration],
        rules: Sequence[Mapping[str, Any]],
        now: datetime,
        result: ProcessResult,
    ) -> None:
        payload = event.payload or {}
        key = notification_key(event)
        playbook_channels = payload.get("notify_channels")
        for integ in integrations:
            config = integ.config or {}
            if event.only_integration_id is not None:
                if integ.id != event.only_integration_id:
                    continue
            else:
                if event.event_type not in (config.get("events") or []):
                    continue
                if not _severity_ok(payload, config.get("min_severity")):
                    continue
                cases = config.get("case_ids") or []
                if cases and str(event.case_id) not in cases:
                    continue
                channel = "webhook" if integ.type == "webhook_out" else integ.type
                if isinstance(playbook_channels, list) and channel not in playbook_channels:
                    continue
            status, error = "pending", None
            people = integ.type in PEOPLE_KINDS
            if event.only_integration_id is None:
                if people and self._recent_duplicate(session, integ.id, key, now):
                    status, error = "suppressed", "duplicate"
                elif self._over_limit(session, integ, now):
                    status, error = "suppressed", "rate_limited"
            inserted = session.execute(
                pg_insert(OutboundDelivery)
                .values(
                    id=uuid.uuid4(),
                    event_id=event.id,
                    integration_id=integ.id,
                    kind=integ.type,
                    event_type=event.event_type,
                    status=status,
                    max_attempts=self.settings.outbound_max_attempts,
                    next_attempt_at=now if status == "pending" else None,
                    last_error=error,
                    dedup_key=key if people else None,
                    created_at=now,
                    updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["event_id", "integration_id"])
                .returning(OutboundDelivery.id)
            ).scalar_one_or_none()
            if inserted is None:
                continue
            if status == "pending":
                result.deliveries += 1
            else:
                result.suppressed += 1
        if event.only_integration_id is None:
            result.notifications += self._notify_in_app(session, event, rules, key, now)

    def _recent_duplicate(
        self, session: Session, integration_id: uuid.UUID, key: str, now: datetime
    ) -> bool:
        window = self.settings.notify_dedup_window_s
        if window <= 0:
            return False
        return (
            session.execute(
                select(OutboundDelivery.id)
                .where(
                    OutboundDelivery.integration_id == integration_id,
                    OutboundDelivery.dedup_key == key,
                    OutboundDelivery.status != "suppressed",
                    OutboundDelivery.created_at > now - timedelta(seconds=window),
                )
                .limit(1)
            ).scalar_one_or_none()
            is not None
        )

    def _over_limit(self, session: Session, integ: Integration, now: datetime) -> bool:
        limit = (
            self.settings.webhook_rate_limit_per_hour
            if integ.type == "webhook_out"
            else self.settings.notify_rate_limit_per_hour
        )
        sent = session.execute(
            select(func.count())
            .select_from(OutboundDelivery)
            .where(
                OutboundDelivery.integration_id == integ.id,
                OutboundDelivery.status != "suppressed",
                OutboundDelivery.created_at > now - timedelta(hours=1),
            )
        ).scalar_one()
        return int(sent) >= limit

    def _recipients(
        self, session: Session, case_id: uuid.UUID | None, groups: Sequence[str]
    ) -> set[uuid.UUID]:
        users: set[uuid.UUID] = set()
        if "admins" in groups:
            users |= set(
                session.execute(
                    select(User.id).where(User.role == UserRole.admin, User.is_active.is_(True))
                ).scalars()
            )
        if case_id is None:
            return users
        if "case_lead" in groups:
            lead = session.execute(
                select(Case.lead_id).where(Case.id == case_id)
            ).scalar_one_or_none()
            if lead is not None:
                users.add(lead)
        if "case_members" in groups or "case_approvers" in groups:
            rows = session.execute(
                select(User.id, User.role, CaseMember.role)
                .join(CaseMember, CaseMember.user_id == User.id)
                .where(CaseMember.case_id == case_id, User.is_active.is_(True))
            ).all()
            for user_id, global_role, case_role in rows:
                if "case_members" in groups or Permission.APPROVE in effective_case_permissions(
                    global_role, case_role, self.settings.auditor_all_cases
                ):
                    users.add(user_id)
        return users

    def _notify_in_app(
        self,
        session: Session,
        event: OutboundEvent,
        rules: Sequence[Mapping[str, Any]],
        key: str,
        now: datetime,
    ) -> int:
        payload = event.payload or {}
        groups: set[str] = set()
        for rule in rules:
            if rule["event"] == event.event_type and _severity_ok(payload, rule["min_severity"]):
                groups |= set(rule["recipients"])
        channels = payload.get("notify_channels")
        if isinstance(channels, list):  # a playbook names its own audience
            groups = set()
            roles = payload.get("notify_roles") if "in_app" in channels else []
            mapping = {"admin": "admins", "lead": "case_approvers", "analyst": "case_members"}
            groups |= {mapping[r] for r in roles or [] if r in mapping}
        if not groups:
            return 0
        users = self._recipients(session, event.case_id, sorted(groups))
        actor = payload.get("actor_id")
        window = self.settings.notify_dedup_window_s
        bucket = int(now.timestamp() // window) if window > 0 else str(event.id)
        body = M.in_app_payload(payload)
        count = 0
        for user_id in sorted(users, key=str):
            if actor is not None and str(user_id) == str(actor):
                continue
            recent = session.execute(
                select(func.count())
                .select_from(Notification)
                .where(
                    Notification.user_id == user_id,
                    Notification.created_at > now - timedelta(hours=1),
                )
            ).scalar_one()
            if int(recent) >= self.settings.notify_rate_limit_per_hour:
                continue
            created = session.execute(
                pg_insert(Notification)
                .values(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    kind=event.event_type,
                    payload=body,
                    case_id=event.case_id,
                    dedup_key=f"{key}:{bucket}"[:400],
                    created_at=now,
                )
                .on_conflict_do_nothing(
                    index_elements=["user_id", "dedup_key"],
                    index_where=text("dedup_key IS NOT NULL"),
                )
                .returning(Notification.id)
            ).scalar_one_or_none()
            count += created is not None
        return count

    # ------------------------------------------------------------------ deliveries

    def backoff_s(self, attempts: int) -> int:
        return int(
            min(self.settings.outbound_backoff_base_s * 2 ** max(attempts - 1, 0), MAX_BACKOFF_S)
        )

    def deliver_due(self, result: ProcessResult) -> None:
        for _ in range(self.settings.outbound_batch_size):
            attempt = self._claim()
            if attempt is None:
                self._note_next_due(result)
                return
            result.attempted += 1
            status: int | None = None
            error: str | None = None
            transient = False
            try:
                response = attempt.send()
                if response is not None:
                    status = response.status
                    if not response.ok:
                        error = f"http_{response.status}"
                        transient = response.status in (408, 425, 429) or response.status >= 500
            except OutboundBlockedError as exc:
                error = exc.category
            except OutboundError as exc:
                error, transient = exc.category, exc.transient
            except _PermanentError as exc:
                error = exc.category
            self._record(attempt, status, error, transient, result)
        result.more = True

    def _note_next_due(self, result: ProcessResult) -> None:
        """Set ``retry_in_s`` to when the next pending delivery falls due (or its lease ends).

        A follow-up run can start a little before its delivery is due (timer slack, clock
        steps); without this it would find nothing to do, schedule nothing, and the retry would
        wait for the next event.
        """
        now = self.clock()
        with self.sessions() as session:
            due = session.execute(
                select(
                    func.min(
                        func.greatest(
                            OutboundDelivery.next_attempt_at,
                            func.coalesce(
                                OutboundDelivery.locked_until, OutboundDelivery.next_attempt_at
                            ),
                        )
                    )
                ).where(OutboundDelivery.status == "pending")
            ).scalar_one_or_none()
            session.commit()
        if due is None:
            return
        wait = max(int((due - now).total_seconds()) + 1, 1)
        result.retry_in_s = min(result.retry_in_s or wait, wait)

    def _claim(self) -> _Attempt | None:
        """Take the next due delivery: count the attempt, set a lease, build what to send."""
        now = self.clock()
        policy = self.http.policy
        lease = timedelta(seconds=policy.total_timeout_s + policy.connect_timeout_s + 30)
        while True:
            with self.sessions() as session:
                row = session.execute(
                    select(OutboundDelivery)
                    .where(
                        OutboundDelivery.status == "pending",
                        OutboundDelivery.next_attempt_at <= now,
                        or_(
                            OutboundDelivery.locked_until.is_(None),
                            OutboundDelivery.locked_until < now,
                        ),
                    )
                    .order_by(OutboundDelivery.next_attempt_at, OutboundDelivery.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).scalar_one_or_none()
                if row is None:
                    session.commit()
                    return None
                if row.attempts >= row.max_attempts:  # a crashed final attempt (lease ran out)
                    self._finish(row, "failed", now, error="attempts_exhausted")
                    session.commit()
                    continue
                row.attempts += 1
                row.locked_until = now + lease
                row.updated_at = now
                integ = session.get(Integration, row.integration_id)
                event = session.get(OutboundEvent, row.event_id)
                send = self._build_send(row, integ, event, now)
                attempt = _Attempt(row.id, row.attempts, row.kind, send)
                session.commit()
                return attempt

    def _secret(self, integ: Integration) -> dict[str, Any]:
        if (
            integ.config_encrypted is None
            or not integ.secret_wrapped_key
            or not integ.secret_key_id
        ):
            return {}
        try:
            sealed = SealedSecret(
                bytes(integ.config_encrypted), bytes(integ.secret_wrapped_key), integ.secret_key_id
            )
            return self.keyring().open(sealed, integration_aad(integ.id))
        except (SecretsUnavailableError, SecretDecryptError) as exc:
            raise _PermanentError("secret_unavailable") from exc

    def _build_send(
        self,
        row: OutboundDelivery,
        integ: Integration | None,
        event: OutboundEvent | None,
        now: datetime,
    ) -> Callable[[], HttpResponse | None]:
        """Everything read from the database now; the returned callable only talks to the
        network. Problems found here are raised when it is called (and recorded like any other
        failed attempt)."""
        try:
            if integ is None or event is None:
                raise _PermanentError("missing_integration")
            if not integ.enabled:
                raise _PermanentError("integration_disabled")
            config = dict(integ.config or {})
            secret = self._secret(integ)
            payload = dict(event.payload or {})
            include = bool(config.get("include_details"))
            if event.event_type == M.EVENT_TEST:
                payload["integration"] = str(integ.id)
            if row.kind == "webhook_out":
                return self._webhook(row, event, config, secret, payload, include, now)
            message = M.build_message(
                payload, include_details=include, base_url=self.settings.public_base_url
            )
            if row.kind == "email":
                return self._email(config, secret, message)
            url = str(secret.get("webhook_url") or "")
            if not url:
                raise _PermanentError("secret_unavailable")
            body = M.render_slack(message) if row.kind == "slack" else M.render_teams(message)
            headers = {"Content-Type": "application/json"}
            return lambda: self.http.request("POST", url, headers=headers, body=body)
        except _PermanentError as exc:
            error = exc

            def fail() -> HttpResponse | None:
                raise error

            return fail
        except ValueError:

            def bad() -> HttpResponse | None:
                raise _PermanentError("invalid_event")

            return bad

    def _webhook(
        self,
        row: OutboundDelivery,
        event: OutboundEvent,
        config: Mapping[str, Any],
        secret: Mapping[str, Any],
        payload: Mapping[str, Any],
        include: bool,
        now: datetime,
    ) -> Callable[[], HttpResponse | None]:
        signing = str(secret.get("signing_secret") or "")
        url = str(config.get("url") or "")
        if not signing or not url:
            raise _PermanentError("secret_unavailable" if not signing else "invalid_config")
        created = event.created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = M.render_webhook(event.id, created, payload, include_details=include)
        timestamp = int(now.timestamp())
        headers = {
            "Content-Type": "application/json",
            webhooks.HEADER_TIMESTAMP: str(timestamp),
            webhooks.HEADER_SIGNATURE: webhooks.sign(signing, timestamp, body),
            webhooks.HEADER_EVENT: event.event_type,
            webhooks.HEADER_DELIVERY: str(row.id),
        }
        return lambda: self.http.request("POST", url, headers=headers, body=body)

    def _email(
        self, config: Mapping[str, Any], secret: Mapping[str, Any], message: M.Message
    ) -> Callable[[], HttpResponse | None]:
        subject, body = M.render_email(message)
        server = MailServer(
            host=str(config.get("host") or ""),
            port=int(config.get("port") or 587),
            security=str(config.get("security") or "starttls"),
            username=config.get("username"),
            password=secret.get("password"),
        )
        sender = str(config.get("sender") or "")
        recipients = [str(r) for r in config.get("recipients") or []]

        def send() -> HttpResponse | None:
            self.mailer.send(
                server, sender=sender, recipients=recipients, subject=subject, body=body
            )
            return None

        return send

    @staticmethod
    def _finish(
        row: OutboundDelivery,
        status: str,
        now: datetime,
        *,
        error: str | None = None,
        response_status: int | None = None,
    ) -> None:
        row.status = status
        row.last_error = error
        row.response_status = response_status
        row.locked_until = None
        row.updated_at = now
        row.next_attempt_at = None
        if status == "delivered":
            row.delivered_at = now

    def _record(
        self,
        attempt: _Attempt,
        status: int | None,
        error: str | None,
        transient: bool,
        result: ProcessResult,
    ) -> None:
        now = self.clock()
        with self.sessions() as session:
            row = session.execute(
                select(OutboundDelivery)
                .where(OutboundDelivery.id == attempt.delivery_id)
                .with_for_update()
            ).scalar_one()
            # Re-check under the lock: another worker may have taken over after our lease ran out.
            if row.status != "pending" or row.attempts != attempt.attempts:
                session.rollback()
                return
            if error is None:
                self._finish(row, "delivered", now, response_status=status)
                result.delivered += 1
                outcome = "ok"
            elif transient and row.attempts < row.max_attempts:
                delay = self.backoff_s(row.attempts)
                row.next_attempt_at = now + timedelta(seconds=delay)
                row.locked_until = None
                row.last_error = error[:100]
                row.response_status = status
                row.updated_at = now
                result.retried += 1
                result.retry_in_s = min(result.retry_in_s or delay, delay)
                outcome = error
            else:
                self._finish(row, "failed", now, error=error[:100], response_status=status)
                result.failed += 1
                outcome = error
            integ = session.execute(
                select(Integration).where(Integration.id == row.integration_id).with_for_update()
            ).scalar_one_or_none()
            if integ is not None:
                integ.last_status = outcome[:100]
                integ.last_status_at = now
            session.commit()
        log.info(
            "outbound_delivery",
            delivery_id=str(attempt.delivery_id),
            kind=attempt.kind,
            attempt=attempt.attempts,
            outcome=outcome,
        )
