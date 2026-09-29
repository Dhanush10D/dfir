"""AlertService (guide 11.7, 15.2): list, detail, lifecycle updates, linked events, ATT&CK view,
risk summary. Case-scoped: an alert in a case the caller cannot read is *not found*.

Lifecycle (every change is written to ``alert_history`` (append-only) and ``audit_log``)::

    new -> triaged | investigating | false_positive
    triaged -> investigating | true_positive | false_positive
    investigating -> true_positive | false_positive | triaged
    true_positive | false_positive -> closed | investigating (reconsider)
    closed -> investigating (reopen)

Moving to ``true_positive``, ``false_positive`` or ``closed`` (and reopening) needs a reason.

Concurrency: an update takes ``FOR SHARE`` on the case row (close takes ``FOR UPDATE``), then
``FOR NO KEY UPDATE`` on the alert row, and validates the transition against the status read
*under the lock*; an optional ``expected_status`` turns a lost race into a 409.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal, effective_case_permissions
from app.db.models import (
    Alert,
    AlertEvent,
    AlertHistory,
    AlertStatus,
    Case,
    CaseStatus,
    Event,
    Severity,
    User,
)
from app.detection.attack import tactics_of
from app.detection.scoring import RiskSummary, ScoredAlert, summarize
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, case_role_of, load_case_access

S = AlertStatus
TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    S.new: frozenset({S.triaged, S.investigating, S.false_positive}),
    S.triaged: frozenset({S.investigating, S.true_positive, S.false_positive}),
    S.investigating: frozenset({S.true_positive, S.false_positive, S.triaged}),
    S.true_positive: frozenset({S.closed, S.investigating}),
    S.false_positive: frozenset({S.closed, S.investigating}),
    S.closed: frozenset({S.investigating}),
}
NEEDS_REASON = frozenset({S.true_positive, S.false_positive, S.closed})
SEVERITY_ORDER = [s for s in Severity]
MAX_LIMIT = 500
UNSET: Any = object()


def transition_allowed(current: AlertStatus, target: AlertStatus) -> bool:
    return target in TRANSITIONS[current]


@dataclass(frozen=True)
class AlertFilter:
    status: AlertStatus | None = None
    min_severity: Severity | None = None
    host: str | None = None
    rule_id: str | None = None
    technique: str | None = None
    assignee_id: uuid.UUID | None = None
    include_stale: bool = True


@dataclass(frozen=True)
class LinkedEvent:
    event_id: uuid.UUID
    event_ts: Any
    event: Event | None


class AlertService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.audit = AuditService(session)

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _load(self, principal: Principal, alert_id: uuid.UUID) -> tuple[Alert, CaseAccess]:
        alert = self.session.get(Alert, alert_id)
        if alert is None:
            raise NotFoundError("Alert not found.")
        try:
            access = self._access(principal, alert.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Alert not found.") from exc
        return alert, access

    # ------------------------------------------------------------------ read

    def list_alerts(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        flt: AlertFilter,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Alert], int]:
        self._access(principal, case_id)
        if not 1 <= limit <= MAX_LIMIT or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIMIT}.", 422)
        conds = [Alert.case_id == case_id]
        if flt.status is not None:
            conds.append(Alert.status == flt.status)
        if flt.min_severity is not None:
            allowed = SEVERITY_ORDER[SEVERITY_ORDER.index(flt.min_severity) :]
            conds.append(Alert.severity.in_(allowed))
        if flt.host:
            conds.append(Alert.host == flt.host)
        if flt.rule_id:
            conds.append(Alert.rule_id == flt.rule_id)
        if flt.technique:
            conds.append(Alert.attack_tags.any(flt.technique))  # type: ignore[arg-type]
        if flt.assignee_id is not None:
            conds.append(Alert.assignee_id == flt.assignee_id)
        if not flt.include_stale:
            conds.append(Alert.stale.is_(False))
        total = self.session.execute(
            select(func.count()).select_from(Alert).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(Alert)
                .where(*conds)
                .order_by(Alert.risk_score.desc(), Alert.last_seen.desc(), Alert.id)
                .limit(limit)
                .offset(offset)
            ).scalars()
        )
        self.session.commit()
        return rows, int(total)

    def get(self, principal: Principal, alert_id: uuid.UUID) -> tuple[Alert, list[AlertHistory]]:
        alert, _ = self._load(principal, alert_id)
        history = list(
            self.session.execute(
                select(AlertHistory)
                .where(AlertHistory.alert_id == alert_id)
                .order_by(AlertHistory.id)
            ).scalars()
        )
        self.session.commit()
        return alert, history

    def events(
        self, principal: Principal, alert_id: uuid.UUID, *, limit: int = 100, offset: int = 0
    ) -> tuple[list[LinkedEvent], int]:
        alert, _ = self._load(principal, alert_id)
        if not 1 <= limit <= MAX_LIMIT or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIMIT}.", 422)
        total = self.session.execute(
            select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert_id)
        ).scalar_one()
        links = self.session.execute(
            select(AlertEvent.event_id, AlertEvent.event_ts)
            .where(AlertEvent.alert_id == alert_id)
            .order_by(AlertEvent.event_ts, AlertEvent.event_id)
            .limit(limit)
            .offset(offset)
        ).all()
        ids = [link.event_id for link in links]
        found = {
            e.id: e
            for e in self.session.execute(
                select(Event).where(Event.case_id == alert.case_id, Event.id.in_(ids))
            ).scalars()
        } if ids else {}  # fmt: skip
        self.session.commit()
        return [LinkedEvent(l.event_id, l.event_ts, found.get(l.event_id)) for l in links], int(  # noqa: E741
            total
        )

    def attack_matrix(self, principal: Principal, case_id: uuid.UUID) -> list[dict[str, Any]]:
        """Technique -> alert counts (false positives and stale alerts excluded)."""
        self._access(principal, case_id)
        rows = self.session.execute(
            text(
                "SELECT t.technique, count(*) AS alerts, max(a.severity) AS max_sev "
                "FROM alerts a CROSS JOIN LATERAL unnest(a.attack_tags) AS t(technique) "
                "WHERE a.case_id = :case_id AND a.status <> 'false_positive' AND NOT a.stale "
                "GROUP BY t.technique ORDER BY t.technique"
            ),
            {"case_id": case_id},
        ).all()
        self.session.commit()
        return [
            {
                "technique": r.technique,
                "tactics": list(tactics_of(r.technique)),
                "alerts": int(r.alerts),
                "max_severity": r.max_sev,
            }
            for r in rows
        ]

    def risk(self, principal: Principal, case_id: uuid.UUID) -> RiskSummary:
        self._access(principal, case_id)
        rows = self.session.execute(
            select(Alert.id, Alert.host, Alert.risk_score, Alert.attack_tags, Alert.title).where(
                Alert.case_id == case_id,
                Alert.status != AlertStatus.false_positive,
                Alert.stale.is_(False),
            )
        ).all()
        self.session.commit()
        return summarize(
            ScoredAlert(str(r.id), r.host, float(r.risk_score), tuple(r.attack_tags), r.title)
            for r in rows
        )

    # ------------------------------------------------------------------ write

    def update(
        self,
        principal: Principal,
        alert_id: uuid.UUID,
        meta: RequestMeta,
        *,
        status: AlertStatus | None = None,
        assignee_id: uuid.UUID | None = UNSET,
        reason: str | None = None,
        expected_status: AlertStatus | None = None,
    ) -> Alert:
        alert, access = self._load(principal, alert_id)
        access.require(Permission.ALERT_UPDATE)
        if status is None and assignee_id is UNSET:
            raise AppError("nothing_to_update", "Give 'status' and/or 'assignee_id'.", 422)
        # Closed cases are read-only: FOR SHARE on the case row (close takes FOR UPDATE).
        case_status = self.session.execute(
            select(Case.status).where(Case.id == alert.case_id).with_for_update(read=True)
        ).scalar_one()
        if case_status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed.")
        locked = self.session.execute(
            select(Alert)
            .where(Alert.id == alert_id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        ).scalar_one()
        current = locked.status
        if expected_status is not None and current is not expected_status:
            self.session.rollback()
            raise ConflictError(
                "The alert changed since you read it.", "stale_state", status=current.value
            )
        history: list[AlertHistory] = []
        if status is not None and status is not current:
            if not transition_allowed(current, status):
                self.session.rollback()
                raise InvalidStateError(
                    f"Cannot move an alert from {current.value} to {status.value}.",
                    status=current.value,
                    allowed=sorted(s.value for s in TRANSITIONS[current]),
                )
            needs_reason = status in NEEDS_REASON or current is S.closed
            if needs_reason and not (reason and reason.strip()):
                self.session.rollback()
                raise AppError("reason_required", "A reason is required for this change.", 422)
            locked.status = status
            locked.status_reason = reason
            history.append(
                AlertHistory(
                    alert_id=alert_id,
                    action="status",
                    user_id=principal.user_id,
                    from_status=current,
                    to_status=status,
                    reason=reason,
                )
            )
            self.audit.record(
                "alert.status_changed",
                user_id=principal.user_id,
                meta=meta,
                object_type="alert",
                object_id=alert_id,
                detail={
                    "case_id": str(locked.case_id),
                    "from": current.value,
                    "to": status.value,
                    "reason": reason,
                },
            )
        if assignee_id is not UNSET and assignee_id != locked.assignee_id:
            if assignee_id is not None:
                self._check_assignee(locked.case_id, assignee_id)
            history.append(
                AlertHistory(
                    alert_id=alert_id,
                    action="assign",
                    user_id=principal.user_id,
                    from_assignee=locked.assignee_id,
                    to_assignee=assignee_id,
                    reason=reason,
                )
            )
            self.audit.record(
                "alert.assigned",
                user_id=principal.user_id,
                meta=meta,
                object_type="alert",
                object_id=alert_id,
                detail={
                    "case_id": str(locked.case_id),
                    "from": str(locked.assignee_id) if locked.assignee_id else None,
                    "to": str(assignee_id) if assignee_id else None,
                },
            )
            locked.assignee_id = assignee_id
        if history:
            locked.updated_at = func.now()
            self.session.add_all(history)
        self.session.commit()
        self.session.refresh(locked)
        return locked

    def _check_assignee(self, case_id: uuid.UUID, user_id: uuid.UUID) -> None:
        user = self.session.get(User, user_id)
        if user is None or not user.is_active:
            raise AppError("invalid_assignee", "Assignee must be an active user.", 422)
        role = case_role_of(self.session, case_id, user_id)
        perms = effective_case_permissions(user.role, role, self.settings.auditor_all_cases)
        if Permission.ALERT_UPDATE not in perms:
            raise AppError("invalid_assignee", "Assignee cannot work alerts in this case.", 422)
