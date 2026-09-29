"""Process tree per host (guide 12.6) and the case summary (guide 17.2 "Case overview").

The tree query reads process-create events (``event_category='process' AND action='create'``,
e.g. Sysmon 1 / Security 4688) and other events that carry a pid on the host, bounded by ``limit``
and an optional time range, then hands them to the pure builder in ``app.analysis.proctree``.
Nodes whose event is linked to an alert carry the alert count.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, literal, select
from sqlalchemy.orm import Session

from app.analysis.proctree import MAX_DEPTH, MAX_NODES, ProcessTree, ProcEvent, build_tree
from app.config import Settings
from app.core.exceptions import AppError
from app.core.permissions import Permission, Principal
from app.db.models import (
    Alert,
    AlertEvent,
    AlertStatus,
    Entity,
    Event,
    Evidence,
    Job,
    JobStatus,
    Note,
)
from app.services.alerts import AlertService
from app.services.authz import load_case_access

TOP_N = 5


class ProcessTreeService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def tree(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        host: str,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 2000,
        max_depth: int = 64,
    ) -> tuple[ProcessTree, dict[str, int]]:
        access = load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.CASE_READ)
        if not host.strip() or len(host) > 255:
            raise AppError("invalid_filter", "'host' is required (1-255 characters).", 422)
        if not 1 <= limit <= MAX_NODES or not 1 <= max_depth <= MAX_DEPTH:
            raise AppError(
                "invalid_filter", f"'limit' 1-{MAX_NODES}, 'max_depth' 1-{MAX_DEPTH}.", 422
            )
        for value in (start, end):
            if value is not None and value.utcoffset() is None:
                raise AppError("invalid_filter", "Time bounds need a timezone.", 422)
        created = and_(Event.event_category == "process", Event.action == "create")
        conds: list[Any] = [
            Event.case_id == case_id,
            func.lower(Event.host) == func.lower(literal(host)),
            Event.pid.is_not(None),
        ]
        if start is not None:
            conds.append(Event.ts >= start)
        if end is not None:
            conds.append(Event.ts <= end)
        ed = Event.raw["event_data"]
        stmt = (
            select(
                Event.id,
                Event.ts,
                Event.pid,
                Event.ppid,
                Event.process_name,
                Event.file_path,
                Event.cmdline,
                Event.user,
                created.label("created"),
                ed["ProcessGuid"].astext.label("guid"),
                ed["ParentProcessGuid"].astext.label("parent_guid"),
                func.coalesce(
                    Event.raw["normalized"]["parent_process"].astext,
                    ed["ParentImage"].astext,
                    ed["ParentProcessName"].astext,
                ).label("parent_name"),
            )
            .where(*conds)
            .order_by(created.desc(), Event.ts, Event.id)
            .limit(limit)
        )
        rows = self.session.execute(stmt).all()
        events = [
            ProcEvent(
                event_id=str(r.id),
                ts=r.ts,
                pid=r.pid,
                ppid=r.ppid,
                name=r.process_name,
                image=r.file_path,
                cmdline=r.cmdline,
                user=r.user,
                guid=r.guid,
                parent_guid=r.parent_guid,
                parent_name=r.parent_name,
                created=bool(r.created),
            )
            for r in rows
        ]
        tree = build_tree(events, max_nodes=limit, max_depth=max_depth)
        if len(rows) >= limit:
            tree.truncated = True
        ids = [uuid.UUID(n.event_id) for n in tree.nodes if n.event_id]
        alerts: dict[str, int] = {}
        if ids:
            for event_id, count in self.session.execute(
                select(AlertEvent.event_id, func.count(func.distinct(AlertEvent.alert_id)))
                .join(Alert, Alert.id == AlertEvent.alert_id)
                .where(
                    Alert.case_id == case_id,
                    AlertEvent.event_id.in_(ids),
                    Alert.status != AlertStatus.false_positive,
                )
                .group_by(AlertEvent.event_id)
            ).all():
                alerts[str(event_id)] = int(count)
        self.session.commit()
        return tree, alerts


class SummaryService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def summary(self, principal: Principal, case_id: uuid.UUID) -> dict[str, Any]:
        access = load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.CASE_READ)
        s = self.session

        def count(model: Any, *conds: Any) -> int:
            return int(
                s.execute(
                    select(func.count()).select_from(model).where(model.case_id == case_id, *conds)
                ).scalar_one()
            )

        span = s.execute(
            select(func.min(Event.ts), func.max(Event.ts)).where(Event.case_id == case_id)
        ).one()
        by_status = {
            str(k.value): int(v)
            for k, v in s.execute(
                select(Alert.status, func.count())
                .where(Alert.case_id == case_id, Alert.stale.is_(False))
                .group_by(Alert.status)
            ).all()
        }
        by_severity = {
            str(k.value): int(v)
            for k, v in s.execute(
                select(Alert.severity, func.count())
                .where(
                    Alert.case_id == case_id,
                    Alert.stale.is_(False),
                    Alert.status != AlertStatus.false_positive,
                )
                .group_by(Alert.severity)
            ).all()
        }

        def top(column: Any) -> list[dict[str, Any]]:
            rows = s.execute(
                select(column, func.count().label("n"))
                .where(Event.case_id == case_id, column.is_not(None))
                .group_by(column)
                .order_by(func.count().desc(), column)
                .limit(TOP_N)
            ).all()
            return [{"value": str(r[0]), "count": int(r.n)} for r in rows]

        result = {
            "case_id": str(case_id),
            "events": count(Event),
            "evidence": count(Evidence),
            "entities": count(Entity),
            "notes": count(Note, Note.retracted_at.is_(None)),
            "jobs_active": count(Job, Job.status.in_((JobStatus.queued, JobStatus.running))),
            "first_event": span[0],
            "last_event": span[1],
            "alerts_by_status": by_status,
            "alerts_by_severity": by_severity,
            "top_hosts": top(Event.host),
            "top_users": top(Event.user),
        }
        s.commit()
        risk = AlertService(s, self.settings).risk(principal, case_id)
        result["risk"] = {"case_risk": risk.case_risk, "tactics": list(risk.tactics)}
        return result
