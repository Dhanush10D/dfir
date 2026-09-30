"""Report data snapshot (guide 18.3 step 1): everything a report renders, read once, then frozen.

The snapshot only reads (evidence bytes are never touched; custody chains are verified read-only
with trust anchors outside the database). It contains JSON strings, integers, booleans and nulls
only (no floats), so its canonical hash is stable through a JSONB round trip. Each part is capped
and truncation is recorded; ``input_hashes`` fingerprint the evidence, custody, alerts, key events,
IOCs, runs and AI outputs included, for provenance.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.db.models import (
    AiInteraction,
    Alert,
    AlertEvent,
    AlertStatus,
    Bookmark,
    Case,
    Event,
    Evidence,
    Ioc,
    Job,
    User,
)
from app.reports.seal import canonical_json, json_sha256
from app.services.custody import ChainEntry, CustodyService, verify_chain

SNAPSHOT_SCHEMA = 1
MAX_EVIDENCE = 1000
MAX_CUSTODY_ENTRIES_PER_ITEM = 200
MAX_RUNS = 300
MAX_AI_OUTPUTS = 200
MAX_TEXT = 1000
SUMMARY_CHARS = 500


@dataclass(frozen=True)
class SnapshotLimits:
    key_events: int = 500
    alerts: int = 500
    iocs: int = 1000
    max_bytes: int = 8 * 1024 * 1024


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _s(value: Any, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _num(value: Any) -> str | None:
    """Floats as short strings (JSONB would change their representation)."""
    if value is None:
        return None
    return f"{float(value):.4g}"


def user_label(user: User | None) -> str | None:
    return f"{user.display_name} <{user.email}>" if user is not None else None


def event_summary(ev: Event) -> str:
    parts = [ev.action, ev.message or ev.cmdline or ev.file_path or ev.registry_key]
    text = " - ".join(str(p) for p in parts if p)
    return _s(text or ev.event_code or ev.source_type, SUMMARY_CHARS) or ""


class SnapshotBuilder:
    def __init__(
        self,
        session: Session,
        custody: CustodyService,
        limits: SnapshotLimits,
        *,
        org: str,
        clock: Callable[[], datetime],
    ) -> None:
        self.session = session
        self.custody = custody
        self.limits = limits
        self.org = org
        self.clock = clock
        self._users: dict[uuid.UUID, str | None] = {}

    def _user(self, user_id: uuid.UUID | None) -> str | None:
        if user_id is None:
            return None
        if user_id not in self._users:
            self._users[user_id] = user_label(self.session.get(User, user_id))
        return self._users[user_id]

    # ------------------------------------------------------------------ parts

    def _case(self, case: Case) -> dict[str, Any]:
        return {
            "id": str(case.id),
            "case_number": case.case_number,
            "title": _s(case.title, 500),
            "description": _s(case.description, 5000),
            "status": case.status.value,
            "severity": case.severity.value,
            "classification": case.classification,
            "opened_at": iso(case.opened_at),
            "closed_at": iso(case.closed_at),
            "lead": self._user(case.lead_id),
        }

    def _evidence_and_custody(
        self, case_id: uuid.UUID
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
        items = list(
            self.session.execute(
                select(Evidence)
                .where(Evidence.case_id == case_id)
                .order_by(Evidence.created_at, Evidence.id)
                .limit(MAX_EVIDENCE + 1)
            ).scalars()
        )
        truncated = len(items) > MAX_EVIDENCE
        items = items[:MAX_EVIDENCE]
        labels = {ev.id: ev.label for ev in items}
        trusted = self.custody.trusted_keys()
        published = self.custody.public_keys()
        evidence, custody = [], []
        for ev in items:
            rows = self.custody.entries(ev.id)
            report = verify_chain(
                [ChainEntry.from_row(r) for r in rows],
                trusted,
                published_keys=published,
                evidence_id=str(ev.id),
            )
            evidence.append(
                {
                    "id": str(ev.id),
                    "label": ev.label,
                    "kind": ev.kind,
                    "original_name": _s(ev.original_name, 500),
                    "source_host": _s(ev.source_host, 255),
                    "size_bytes": ev.size_bytes,
                    "sha256": ev.sha256,
                    "md5": ev.md5,
                    "acquired_at": iso(ev.acquired_at),
                    "acquired_by": _s(ev.acquired_by, 255),
                    "acquisition_tool": _s(ev.acquisition_tool, 255),
                    "acquisition_notes": _s(ev.acquisition_notes, 2000),
                    "status": ev.status,
                    "parent_label": labels.get(ev.parent_evidence_id)
                    if ev.parent_evidence_id
                    else None,
                    "received_at": iso(ev.created_at),
                    "custody_ok": report.ok,
                    "custody_entries": len(rows),
                }
            )
            custody.append(
                {
                    "evidence_id": str(ev.id),
                    "label": ev.label,
                    "ok": report.ok,
                    "entries_total": len(rows),
                    "head_seq": report.head_seq,
                    "head_hash": report.head_hash,
                    "problems": [p.as_dict() for p in report.problems[:50]],
                    "entries": [
                        {
                            "seq": r.seq,
                            "ts": iso(r.ts),
                            "actor": _s(r.actor_label, 255),
                            "action": r.action,
                            "detail": _s(canonical_json(r.detail or {}).decode(), 600),
                            "entry_hash": r.entry_hash,
                            "key_id": r.key_id,
                        }
                        for r in rows[:MAX_CUSTODY_ENTRIES_PER_ITEM]
                    ],
                    "entries_truncated": len(rows) > MAX_CUSTODY_ENTRIES_PER_ITEM,
                }
            )
        return evidence, custody, truncated

    def _alerts(self, case_id: uuid.UUID) -> tuple[list[Alert], int]:
        conds = [Alert.case_id == case_id, Alert.stale.is_(False)]
        total = self.session.execute(
            select(func.count()).select_from(Alert).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(Alert)
                .where(*conds)
                .order_by(Alert.risk_score.desc(), Alert.first_seen, Alert.id)
                .limit(self.limits.alerts)
            ).scalars()
        )
        return rows, int(total)

    def _key_events(
        self, case_id: uuid.UUID, alerts: Iterable[Alert], labels: Mapping[str, str]
    ) -> tuple[list[dict[str, Any]], int]:
        reasons: dict[uuid.UUID, set[str]] = {}
        for target in self.session.execute(
            select(Bookmark.target_id).where(
                Bookmark.case_id == case_id, Bookmark.target_type == "event"
            )
        ).scalars():
            try:
                reasons.setdefault(uuid.UUID(str(target)), set()).add("bookmark")
            except ValueError:
                continue
        alert_ids = [a.id for a in alerts if a.status is not AlertStatus.false_positive]
        if alert_ids:
            for event_id in self.session.execute(
                select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(alert_ids)).distinct()
            ).scalars():
                reasons.setdefault(event_id, set()).add("alert")
        total = len(reasons)
        if not reasons:
            return [], 0
        rows: list[Event] = []
        ids = list(reasons)
        for start in range(0, len(ids), 1000):
            rows += list(
                self.session.execute(
                    select(Event).where(
                        Event.case_id == case_id, Event.id.in_(ids[start : start + 1000])
                    )
                ).scalars()
            )
        rows.sort(key=lambda e: (e.ts, str(e.id)))
        out = []
        for ev in rows[: self.limits.key_events]:
            out.append(
                {
                    "id": str(ev.id),
                    "ts": iso(ev.ts),
                    "ts_original": _s(ev.ts_original, 100),
                    "host": _s(ev.host, 255),
                    "user": _s(ev.user, 255),
                    "source_type": ev.source_type,
                    "event_code": _s(ev.event_code, 100),
                    "summary": event_summary(ev),
                    "process_name": _s(ev.process_name, 255),
                    "cmdline": _s(ev.cmdline),
                    "file_path": _s(ev.file_path),
                    "src_ip": str(ev.src_ip) if ev.src_ip else None,
                    "dst_ip": str(ev.dst_ip) if ev.dst_ip else None,
                    "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
                    "evidence_label": labels.get(str(ev.evidence_id)) if ev.evidence_id else None,
                    "reasons": sorted(reasons.get(ev.id, set())),
                }
            )
        return out, max(total, len(rows))

    def _iocs(self, case_id: uuid.UUID) -> tuple[list[dict[str, Any]], int]:
        conds = [Ioc.case_id == case_id, Ioc.active.is_(True)]
        total = self.session.execute(
            select(func.count()).select_from(Ioc).where(*conds)
        ).scalar_one()
        rows = self.session.execute(
            select(Ioc).where(*conds).order_by(Ioc.type, Ioc.value, Ioc.id).limit(self.limits.iocs)
        ).scalars()
        return [
            {
                "id": str(i.id),
                "type": i.type,
                "value": _s(i.value, 2000),
                "source": _s(i.source, 255),
                "tlp": i.tlp,
                "confidence": _num(i.confidence),
                "first_seen": iso(i.first_seen),
                "active": i.active,
                "global": False,
            }
            for i in rows
        ], int(total)

    def _attack(self, case_id: uuid.UUID, alerts: Iterable[Alert]) -> list[dict[str, Any]]:
        by_alert: dict[str, int] = {}
        for a in alerts:
            for t in a.attack_tags or []:
                by_alert[t] = by_alert.get(t, 0) + 1
        tag = func.unnest(Event.attack_tags).label("t")
        sub = select(tag).where(Event.case_id == case_id).subquery()
        by_event = {
            str(t): int(n)
            for t, n in self.session.execute(
                select(sub.c.t, func.count()).group_by(sub.c.t).limit(500)
            ).all()
        }
        names = sorted(set(by_alert) | set(by_event))
        return [
            {"technique": n, "alerts": by_alert.get(n, 0), "events": by_event.get(n, 0)}
            for n in names
        ]

    def _runs(self, case_id: uuid.UUID, labels: Mapping[str, str]) -> tuple[list[Any], int]:
        conds = [Job.case_id == case_id, Job.run_manifest.is_not(None)]
        total = self.session.execute(
            select(func.count()).select_from(Job).where(*conds)
        ).scalar_one()
        rows = self.session.execute(
            select(Job).where(*conds).order_by(Job.queued_at, Job.id).limit(MAX_RUNS)
        ).scalars()
        out = []
        for job in rows:
            m = job.run_manifest or {}
            counts = m.get("counts") or {}
            tools = m.get("tools") or {}
            out.append(
                {
                    "job_id": str(job.id),
                    "kind": job.kind,
                    "parser": job.parser,
                    "parser_version": _s(m.get("parser_version"), 50),
                    "outcome": _s(m.get("outcome") or job.status.value, 30),
                    "evidence_label": labels.get(str(job.evidence_id)) if job.evidence_id else None,
                    "finished_at": iso(job.finished_at),
                    "records_read": counts.get("records_read"),
                    "events_emitted": counts.get("events_emitted"),
                    "tools": _s("; ".join(f"{k}={v}" for k, v in sorted(tools.items()) if v), 600)
                    or "",
                }
            )
        return out, int(total)

    def _ai_outputs(self, case_id: uuid.UUID) -> list[dict[str, Any]]:
        rows = self.session.execute(
            select(AiInteraction)
            .where(AiInteraction.case_id == case_id, AiInteraction.accepted.is_(True))
            .order_by(AiInteraction.created_at, AiInteraction.id)
            .limit(MAX_AI_OUTPUTS)
        ).scalars()
        return [
            {
                "id": str(r.id),
                "feature": r.feature,
                "model": r.model_served or r.model,
                "prompt_version": r.prompt_version,
                "reviewed_by": self._user(r.reviewed_by),
                "reviewed_at": iso(r.reviewed_at),
                "output_sha256": r.output_sha256,
            }
            for r in rows
        ]

    # ------------------------------------------------------------------ build

    def build(self, case: Case, generated_by: str) -> dict[str, Any]:
        evidence, custody, ev_truncated = self._evidence_and_custody(case.id)
        labels = {e["id"]: e["label"] for e in evidence}
        alerts, alerts_total = self._alerts(case.id)
        key_events, key_total = self._key_events(case.id, alerts, labels)
        iocs, iocs_total = self._iocs(case.id)
        runs, runs_total = self._runs(case.id, labels)
        events_total = self.session.execute(
            select(func.count()).select_from(Event).where(Event.case_id == case.id)
        ).scalar_one()
        severity: dict[str, int] = {}
        for a in alerts:
            severity[a.severity.value] = severity.get(a.severity.value, 0) + 1
        alert_rows = [
            {
                "id": str(a.id),
                "title": _s(a.title, 500),
                "rule_id": a.rule_id,
                "severity": a.severity.value,
                "status": a.status.value,
                "host": _s(a.host, 255),
                "user": _s(a.user, 255),
                "attack": list(a.attack_tags or []),
                "first_seen": iso(a.first_seen),
                "last_seen": iso(a.last_seen),
                "event_count": a.event_count,
                "risk_score": _num(a.risk_score),
            }
            for a in alerts
        ]
        ai_outputs = self._ai_outputs(case.id)
        ctx: dict[str, Any] = {
            "schema": SNAPSHOT_SCHEMA,
            "generated_at": iso(self.clock()),
            "generated_by": generated_by,
            "org": self.org,
            "case": self._case(case),
            "evidence": evidence,
            "custody": custody,
            "alerts": alert_rows,
            "key_events": key_events,
            "iocs": iocs,
            "attack": self._attack(case.id, alerts),
            "runs": runs,
            "ai_outputs": ai_outputs,
            "counts": {
                "evidence": len(evidence),
                "events": int(events_total),
                "alerts": alerts_total,
                "alerts_by_severity": severity,
                "iocs": iocs_total,
                "key_events": key_total,
                "custody_ok": sum(1 for c in custody if c["ok"]),
                "runs": runs_total,
            },
            "truncated": {
                "evidence": ev_truncated,
                "alerts": alerts_total > len(alert_rows),
                "key_events": key_total > len(key_events),
                "iocs": iocs_total > len(iocs),
                "runs": runs_total > len(runs),
            },
        }
        ctx["input_hashes"] = {
            name: json_sha256(ctx[name])
            for name in ("evidence", "custody", "alerts", "key_events", "iocs", "runs")
        } | {"ai_outputs": json_sha256(ai_outputs)}
        size = len(canonical_json(ctx))
        if size > self.limits.max_bytes:
            raise AppError(
                "report_too_large",
                "The case data exceeds the report snapshot size limit.",
                413,
                {"bytes": size, "limit": self.limits.max_bytes},
            )
        return ctx
