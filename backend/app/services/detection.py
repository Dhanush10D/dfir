"""Detection jobs (guide 11.3, 14.5): submission (API / after parsing) and the worker run.

Submission (:class:`DetectionJobs`)
    A detection job is a ``jobs`` row with ``kind='detect'``. ``uq_jobs_queued_detect`` allows at
    most one *queued* detection job per case: a second request inserts with ``ON CONFLICT DO
    NOTHING`` and merges its rule subset into the queued job under ``FOR NO KEY UPDATE``. Like
    parse jobs, submission holds ``FOR SHARE`` on the case row and re-checks it is open; case
    close takes ``FOR UPDATE`` and refuses while jobs are queued/running, so nothing is ever
    detected into a closed case.

Run (:class:`DetectionService`)
    1. Claim with the same lease + fencing-token scheme as parse jobs (``attempts``).
    2. Sync the built-in rule pack, compile the enabled rules (or the requested subset), load the
       case's active IOCs (plus global ones).
    3. Pass 1: stream the case's events ordered by ``(ts, id)`` through the pure engine, selecting
       only columns + the ``raw`` paths the rules use. Pass 2 (only if source detectors are
       enabled): per evidence item, stream events in record order. Every batch heartbeats and
       re-checks ``(status, attempts)`` under the job row lock, so cancel and fencing work.
    4. Flush drafts in dedup-key order (deterministic lock order between concurrent runs):
       ``INSERT ... ON CONFLICT (case_id, dedup_key) DO UPDATE ... WHERE last_detected_at <=
       excluded.last_detected_at`` (an older run never overwrites a newer one), link events
       (``ON CONFLICT`` refreshes ``event_ts``), tag matched events with the rule's ATT&CK ids,
       append ``alert_history`` rows for created alerts. Analyst-owned fields (status, assignee,
       reason) are never touched by detection.
    5. A complete run marks alerts of the evaluated rules that it did not reproduce (and that no
       newer run produced) as ``stale``; they keep their links and triage history.
    6. Finish: run manifest (rule ids + versions + sha256, IOC count, counts, limits, warnings),
       job status, audit row.

Reprocess: a reprocess deletes and re-inserts the evidence's events with the same deterministic
ids, so ``alert_events`` rows keep pointing at valid events; the detection run queued after the
reprocess refreshes ``event_ts`` (if timestamps moved), re-tags events, and marks alerts that no
longer match as stale. Between the reprocess and that run, a linked event may be briefly missing
(the alert-events API reports it as ``missing``).
"""

from __future__ import annotations

import itertools
import platform
import socket
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import (
    BigInteger,
    Row,
    and_,
    case,
    cast,
    func,
    literal_column,
    or_,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.config import Settings
from app.core.exceptions import AppError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import (
    Alert,
    AlertEvent,
    AlertHistory,
    AlertStatus,
    Case,
    CaseStatus,
    Event,
    Evidence,
    Ioc,
    Job,
    JobStatus,
    Rule,
)
from app.detection import fields as F  # noqa: N812
from app.detection.detectors import SourceInfo
from app.detection.engine import AlertDraft, DetectionEngine, EngineLimits
from app.detection.ioc import IocEntry, IocIndex
from app.detection.scoring import alert_risk
from app.services.audit import AuditService, RequestMeta
from app.services.authz import load_case_access
from app.services.processing import (
    JobCancelledError,
    JobFencedError,
    ProcessingService,
    RunResult,
    TransientJobError,
)
from app.services.rules import RuleService

log = structlog.stdlib.get_logger("dfirbench.detection")

DETECT = "detect"
MAX_RULE_IDS = 200
FLUSH_BATCH = 200
TAG_BATCH = 1000
Dispatcher = Callable[[uuid.UUID], None]
ENGINE_VERSION = "1.0.0"


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class DetectSubmitted:
    job: Job
    created: bool


class DetectionJobs:
    """Create (or coalesce into) the case's queued detection job, then dispatch it."""

    def __init__(
        self, session: Session, settings: Settings, *, dispatcher: Dispatcher | None = None
    ) -> None:
        self.session = session
        self.settings = settings
        self.dispatcher = dispatcher
        self.audit = AuditService(session)

    def submit(
        self,
        principal: Principal | None,
        case_id: uuid.UUID,
        *,
        rules: Sequence[str] | None,
        trigger: Mapping[str, Any],
        meta: RequestMeta | None = None,
    ) -> DetectSubmitted:
        if principal is not None:
            access = load_case_access(
                self.session,
                principal,
                case_id,
                auditor_all_cases=self.settings.auditor_all_cases,
            )
            access.require(Permission.EVIDENCE_ADD)
            if access.case.status is CaseStatus.closed:
                raise InvalidStateError("The case is closed.")
        wanted = self._validate_rules(rules)
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one_or_none()
        if status is None or status is CaseStatus.closed:
            self.session.rollback()  # release the FOR SHARE lock before failing
            if status is None:
                raise NotFoundError("Case not found.")
            raise InvalidStateError("The case is closed.")
        user_id = principal.user_id if principal else None
        job_id: uuid.UUID | None = None
        created = False
        for _ in range(5):
            job_id = self.session.execute(
                pg_insert(Job)
                .values(
                    case_id=case_id,
                    kind=DETECT,
                    params={"rules": wanted, "trigger": dict(trigger)},
                    status=JobStatus.queued,
                    created_by=user_id,
                )
                .on_conflict_do_nothing(
                    index_elements=["case_id"],
                    index_where=text("kind = 'detect' AND status = 'queued'"),
                )
                .returning(Job.id)
            ).scalar_one_or_none()
            if job_id is not None:
                created = True
                break
            existing = self.session.execute(
                select(Job)
                .where(Job.case_id == case_id, Job.kind == DETECT, Job.status == JobStatus.queued)
                .with_for_update(key_share=True)
            ).scalar_one_or_none()
            if existing is None:  # claimed between our INSERT and SELECT: try again
                continue
            merged = self._merge(existing.params.get("rules"), wanted)
            params = dict(existing.params)
            params["rules"] = merged
            params["coalesced"] = int(params.get("coalesced", 0)) + 1
            existing.params = params
            job_id = existing.id
            break
        if job_id is None:
            raise AppError("detect_busy", "Could not queue detection; retry.", 409)
        self.audit.record(
            "detection.submitted",
            user_id=user_id,
            meta=meta,
            object_type="job",
            object_id=job_id,
            detail={
                "case_id": str(case_id),
                "created": created,
                "rules": wanted,
                "trigger": dict(trigger),
            },
        )
        self.session.commit()
        job = self.session.execute(select(Job).where(Job.id == job_id)).scalar_one()
        self.session.refresh(job)
        if created:
            self._dispatch(job)
        return DetectSubmitted(job, created)

    def _validate_rules(self, rules: Sequence[str] | None) -> list[str] | None:
        if not rules:
            return None
        ids = sorted(dict.fromkeys(str(r) for r in rules))
        if len(ids) > MAX_RULE_IDS:
            raise AppError("invalid_rules", f"At most {MAX_RULE_IDS} rule ids.", 422)
        found = set(self.session.execute(select(Rule.id).where(Rule.id.in_(ids))).scalars())
        missing = [r for r in ids if r not in found]
        if missing:
            raise AppError("unknown_rules", "Unknown rule ids.", 422, details={"rules": missing})
        return ids

    @staticmethod
    def _merge(current: Any, new: list[str] | None) -> list[str] | None:
        if current is None or new is None:
            return None  # "all rules" wins
        return sorted(set(current) | set(new))

    def _dispatch(self, job: Job) -> None:
        if self.dispatcher is None:
            return
        try:
            self.dispatcher(job.id)
        except Exception as exc:
            log.error("detect_dispatch_failed", job_id=str(job.id), exc_type=type(exc).__name__)
            self.session.execute(
                update(Job)
                .where(Job.id == job.id, Job.status == JobStatus.queued)
                .values(
                    status=JobStatus.failed,
                    error="Could not enqueue the job (queue unavailable); retry later.",
                    finished_at=func.now(),
                )
            )
            self.session.commit()
            raise AppError(
                "queue_unavailable",
                "The job was recorded but could not be queued; retry it later.",
                503,
                details={"job_id": str(job.id)},
            ) from exc


@dataclass
class _Claim:
    token: int
    case_id: uuid.UUID
    params: dict[str, Any]
    created_by: uuid.UUID | None
    started_at: datetime


@dataclass
class _FlushCounts:
    created: int = 0
    updated: int = 0
    skipped_older: int = 0
    links: int = 0
    tagged: int = 0
    stale: int = 0


class DetectionService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        settings: Settings,
        *,
        worker_name: str | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.sessions = sessions
        self.settings = settings
        self.worker = worker_name or socket.gethostname()
        self.clock = clock

    # ------------------------------------------------------------------ claim

    def _claim(self, session: Session, job_id: uuid.UUID) -> _Claim | None:
        lease = timedelta(seconds=self.settings.job_lease_s)
        row = session.execute(
            update(Job)
            .where(
                Job.id == job_id,
                Job.kind == DETECT,
                (Job.status == JobStatus.queued)
                | ((Job.status == JobStatus.running) & (Job.heartbeat_at < func.now() - lease)),
            )
            .values(
                status=JobStatus.running,
                attempts=Job.attempts + 1,
                started_at=func.now(),
                heartbeat_at=func.now(),
                finished_at=None,
                progress=0,
                error=None,
            )
            .returning(Job.attempts, Job.case_id, Job.params, Job.created_by, Job.started_at)
        ).one_or_none()
        session.commit()
        if row is None:
            return None
        return _Claim(row.attempts, row.case_id, dict(row.params), row.created_by, row.started_at)

    def _beat(self, session: Session, job_id: uuid.UUID, token: int, progress: float) -> None:
        try:
            ProcessingService.lock_running(session, job_id, token)
            session.execute(
                update(Job)
                .where(Job.id == job_id)
                .values(
                    progress=func.greatest(Job.progress, round(min(progress, 1.0) * 0.99, 4)),
                    heartbeat_at=func.now(),
                )
            )
            session.commit()
        except (JobCancelledError, JobFencedError):
            session.rollback()
            raise
        except OperationalError as exc:
            session.rollback()
            raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc

    # ------------------------------------------------------------------ entry point

    def run(
        self,
        job_id: uuid.UUID,
        *,
        allow_retry: bool = False,
        stop_exceptions: tuple[type[BaseException], ...] = (),
    ) -> RunResult:
        with self.sessions() as session:
            claim = self._claim(session, job_id)
            if claim is None:
                status = session.execute(select(Job.status).where(Job.id == job_id)).scalar()
                session.commit()
                return RunResult(job_id, "busy" if status is JobStatus.running else "skipped")
            return self._run_claimed(session, job_id, claim, allow_retry, stop_exceptions)

    def _run_claimed(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        allow_retry: bool,
        stop_exceptions: tuple[type[BaseException], ...],
    ) -> RunResult:
        started = self.clock()
        manifest: dict[str, Any] = {
            "job_id": str(job_id),
            "case_id": str(claim.case_id),
            "kind": DETECT,
            "attempt": claim.token,
            "worker": self.worker,
            "trigger": claim.params.get("trigger"),
            "requested_rules": claim.params.get("rules"),
            "started_at": _iso(started),
            "run_started_at": _iso(claim.started_at),
            "tools": {
                "python": platform.python_version(),
                "dfirbench": __version__,
                "detection_engine": ENGINE_VERSION,
            },
        }
        counts: dict[str, int] = {}
        engine: DetectionEngine | None = None
        flushed = _FlushCounts()
        outcome, error = "failed", None
        complete = False
        try:
            case_status = session.execute(
                select(Case.status).where(Case.id == claim.case_id)
            ).scalar_one()
            session.commit()
            if case_status is CaseStatus.closed:  # close refuses active jobs; defense in depth
                raise InvalidStateError("the case is closed")
            rule_service = RuleService(session)
            manifest["builtin_sync"] = rule_service.sync_builtin()
            loaded = rule_service.load_enabled(claim.params.get("rules"))
            rules = loaded.rules
            manifest["rules"] = [
                {"id": r.id, "version": r.version, "sha256": r.sha256, "kind": r.kind}
                for r in rules
            ]
            manifest["rule_warnings"] = loaded.warnings
            iocs = self._iocs(session, claim.case_id)
            manifest["iocs"] = len(iocs)
            limits = EngineLimits(
                max_alerts=self.settings.detect_max_alerts,
                max_links_per_alert=self.settings.detect_max_links_per_alert,
            )
            manifest["limits"] = {
                "max_alerts": limits.max_alerts,
                "max_links_per_alert": limits.max_links_per_alert,
                "max_groups_per_rule": limits.max_groups_per_rule,
                "max_runs_per_key": limits.max_runs_per_key,
                "max_events_per_group": limits.max_events_per_group,
            }
            engine = DetectionEngine(rules, iocs, limits)
            self._scan(session, job_id, claim, engine, rules)
            flushed = self._flush(session, job_id, claim, engine)
            complete = not engine.capped
            if complete:
                flushed.stale = self._mark_stale(session, job_id, claim, rules)
            outcome = "succeeded" if complete else "partial"
            if not complete:
                error = "engine limits reached; see run manifest warnings"
        except JobFencedError:
            log.warning("detect_fenced", job_id=str(job_id), attempt=claim.token)
            return RunResult(job_id, "fenced")
        except JobCancelledError:
            outcome, error = "cancelled", None
        except InvalidStateError as exc:
            session.rollback()
            outcome, error = "failed", str(exc)
        except TransientJobError as exc:
            session.rollback()
            if allow_retry and self._requeue(session, job_id, claim.token, str(exc)):
                return RunResult(job_id, "retry", retry=True, error=str(exc))
            outcome, error = "failed", f"transient error, retries exhausted: {exc}"
        except stop_exceptions as exc:
            session.rollback()
            outcome, error = "partial", f"stopped: {type(exc).__name__} (time limit)"
        except Exception as exc:
            session.rollback()
            log.exception("detect_crashed", job_id=str(job_id))
            outcome, error = "failed", f"internal error: {type(exc).__name__}"
        if engine is not None:
            counts = {
                "events_scanned": engine.events_seen,
                "source_events_scanned": engine.source_events_seen,
                "rules": len(engine.rules),
                "matches": sum(engine.matches.values()),
                "alerts": len(engine.drafts),
                "alerts_created": flushed.created,
                "alerts_updated": flushed.updated,
                "alerts_skipped_older_run": flushed.skipped_older,
                "alerts_marked_stale": flushed.stale,
                "links_written": flushed.links,
                "events_tagged": flushed.tagged,
            }
            manifest["matches_by_rule"] = dict(sorted(engine.matches.items()))
            manifest["warnings"] = dict(sorted(engine.warnings.items()))
        return self._finish(session, job_id, claim, manifest, counts, outcome, error)

    # ------------------------------------------------------------------ loading

    def _iocs(self, session: Session, case_id: uuid.UUID) -> IocIndex:
        rows = session.execute(
            select(Ioc).where(
                or_(Ioc.case_id == case_id, Ioc.case_id.is_(None)),
                Ioc.active.is_(True),
                or_(Ioc.expires_at.is_(None), Ioc.expires_at > func.now()),
            )
        ).scalars()
        index = IocIndex(
            IocEntry(
                str(r.id),
                r.type,
                r.value,
                float(r.confidence if r.confidence is not None else 0.5),
                r.tlp,
                r.source,
            )
            for r in rows
        )
        session.commit()
        return index

    @staticmethod
    def _raw_columns(paths: set[str]) -> list[Any]:
        cols = []
        for name in sorted(paths):
            parts = F.raw_path(name) or ()
            cols.append(func.jsonb_extract_path_text(Event.raw, *parts).label(name))
        return cols

    def _stream(self, stmt: Any) -> Iterator[dict[str, Any]]:
        """Server-side cursor on its own session (writes/heartbeats use the main session)."""
        with self.sessions() as reader:
            result = reader.execute(
                stmt, execution_options={"yield_per": self.settings.detect_batch_size}
            )
            for row in result:
                yield dict(row._mapping)
            reader.commit()

    def _scan(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        engine: DetectionEngine,
        rules: Sequence[Any],
    ) -> None:
        raw_paths = {f for r in rules for f in r.fields if f.startswith("raw.")}
        raw_paths |= {"raw.system.channel", "raw.system.provider"}
        base = [
            Event.id,
            Event.ts,
            Event.evidence_id,
            *(getattr(Event, name) for name in sorted(F.TEXT_FIELDS | F.INT_FIELDS | F.IP_FIELDS)),
        ]
        total = session.execute(
            select(func.count()).select_from(Event).where(Event.case_id == claim.case_id)
        ).scalar_one()
        session.commit()
        passes = 2 if engine.needs_sources else 1
        denominator = max(total * passes, 1)
        batch = self.settings.detect_batch_size
        stmt = (
            select(*base, *self._raw_columns(raw_paths))
            .where(Event.case_id == claim.case_id)
            .order_by(Event.ts, Event.id)
        )
        seen = 0
        for event in self._stream(stmt):
            engine.feed(event)
            seen += 1
            if seen % batch == 0:
                self._beat(session, job_id, claim.token, seen / denominator)
        self._beat(session, job_id, claim.token, seen / denominator)
        if not engine.needs_sources:
            return
        recno = case(
            (
                Event.source_record_id.regexp_match("^[0-9]{1,18}$"),
                cast(Event.source_record_id, BigInteger),
            ),
            else_=None,
        ).label("recno")
        evidence = session.execute(
            select(Evidence.id, Evidence.acquired_at)
            .where(Evidence.case_id == claim.case_id)
            .order_by(Evidence.id)
        ).all()
        session.commit()
        for ev_row in evidence:
            source_file = func.coalesce(Event.source_file, "")
            stmt2 = (
                select(
                    Event.id,
                    Event.ts,
                    Event.host,
                    Event.source_type,
                    source_file.label("source_file"),
                    recno,
                    *self._raw_columns({"raw.system.channel", "raw.system.provider"}),
                )
                .where(
                    Event.case_id == claim.case_id,
                    Event.evidence_id == ev_row.id,
                    Event.source_record_id.regexp_match("^[0-9]{1,18}$"),
                )
                .order_by(source_file, recno, Event.id)
            )
            stream = self._stream(stmt2)

            def counted(items: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
                nonlocal seen
                for item in items:
                    seen += 1
                    if seen % batch == 0:
                        self._beat(session, job_id, claim.token, seen / denominator)
                    yield item

            for name, group in itertools.groupby(counted(stream), key=lambda e: e["source_file"]):
                engine.feed_source(
                    SourceInfo(str(ev_row.id), name or None, ev_row.acquired_at), group
                )
        self._beat(session, job_id, claim.token, seen / denominator)

    # ------------------------------------------------------------------ writing

    def _flush(
        self, session: Session, job_id: uuid.UUID, claim: _Claim, engine: DetectionEngine
    ) -> _FlushCounts:
        counts = _FlushCounts()
        drafts = engine.results()  # sorted by dedup_key: same lock order in every run
        for start in range(0, len(drafts), FLUSH_BATCH):
            chunk = drafts[start : start + FLUSH_BATCH]
            try:
                ProcessingService.lock_running(session, job_id, claim.token)
                for draft in chunk:
                    self._upsert(session, job_id, claim, draft, counts)
                session.execute(update(Job).where(Job.id == job_id).values(heartbeat_at=func.now()))
                session.commit()
            except (JobCancelledError, JobFencedError):
                session.rollback()
                raise
            except OperationalError as exc:
                session.rollback()
                raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc
        return counts

    def _upsert(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        draft: AlertDraft,
        counts: _FlushCounts,
    ) -> None:
        rule = draft.rule
        if draft.first_seen is None or draft.last_seen is None:
            raise RuntimeError("internal: draft.first_seen missing")
        values = {
            "case_id": claim.case_id,
            "rule_id": rule.id,
            "rule_version": rule.version,
            "title": draft.title[:500],
            "severity": rule.level,
            "confidence": draft.confidence,
            "risk_score": alert_risk(rule.level, draft.confidence),
            "host": draft.host,
            "user": draft.user,
            "attack_tags": list(rule.attack),
            "dedup_key": draft.dedup_key,
            "first_seen": draft.first_seen,
            "last_seen": draft.last_seen,
            "event_count": draft.count,
            "details": draft.summary(),
            "last_detected_at": claim.started_at,
            "last_job_id": job_id,
            "stale": False,
        }
        insert = pg_insert(Alert).values(**values)
        excluded = insert.excluded
        refreshed = (
            "rule_version",
            "title",
            "severity",
            "confidence",
            "risk_score",
            "host",
            "user",
            "attack_tags",
            "first_seen",
            "last_seen",
            "event_count",
            "details",
            "last_detected_at",
            "last_job_id",
            "stale",
        )
        stmt: Any = insert.on_conflict_do_update(
            constraint="uq_alerts_case_id_dedup_key",
            set_={**{name: excluded[name] for name in refreshed}, "updated_at": func.now()},
            where=or_(
                Alert.last_detected_at.is_(None),
                Alert.last_detected_at <= excluded["last_detected_at"],
            ),
        ).returning(Alert.id, literal_column("(xmax = 0)").label("inserted"))
        row: Row[Any] | None = session.execute(stmt).one_or_none()
        if row is None:  # a newer run already wrote this alert: leave it alone
            counts.skipped_older += 1
            return
        alert_id = row.id
        if row.inserted:
            counts.created += 1
            session.add(
                AlertHistory(
                    alert_id=alert_id,
                    action="created",
                    job_id=job_id,
                    to_status=AlertStatus.new,
                    reason=f"rule {rule.id} v{rule.version}",
                )
            )
        else:
            counts.updated += 1
        if draft.refs:
            link = pg_insert(AlertEvent).values(
                [
                    {"alert_id": alert_id, "event_id": _uuid(event_id), "event_ts": ts}
                    for event_id, ts in draft.refs
                ]
            )
            written = session.execute(
                link.on_conflict_do_update(
                    index_elements=["alert_id", "event_id"],
                    set_={"event_ts": link.excluded["event_ts"]},
                    where=AlertEvent.event_ts != link.excluded["event_ts"],
                ).returning(AlertEvent.event_id)
            ).all()
            counts.links += len(written)
            if rule.attack:
                ids = [_uuid(event_id) for event_id, _ in draft.refs]
                for pos in range(0, len(ids), TAG_BATCH):
                    result = session.execute(
                        text(
                            "UPDATE events SET attack_tags = ARRAY(SELECT DISTINCT t FROM "
                            "unnest(events.attack_tags || CAST(:tags AS text[])) AS t ORDER BY t) "
                            "WHERE case_id = :case_id AND id = ANY(CAST(:ids AS uuid[])) "
                            "AND NOT (attack_tags @> CAST(:tags AS text[]))"
                        ),
                        {
                            "tags": list(rule.attack),
                            "case_id": claim.case_id,
                            "ids": ids[pos : pos + TAG_BATCH],
                        },
                    )
                    counts.tagged += int(result.rowcount or 0)  # type: ignore[attr-defined]

    def _mark_stale(
        self, session: Session, job_id: uuid.UUID, claim: _Claim, rules: Sequence[Any]
    ) -> int:
        rule_ids = [r.id for r in rules]
        if not rule_ids:
            return 0
        try:
            ProcessingService.lock_running(session, job_id, claim.token)
            result = session.execute(
                update(Alert)
                .where(
                    Alert.case_id == claim.case_id,
                    Alert.rule_id.in_(rule_ids),
                    Alert.stale.is_(False),
                    or_(
                        Alert.last_detected_at.is_(None),
                        Alert.last_detected_at < claim.started_at,
                    ),
                )
                .values(stale=True, updated_at=func.now())
                .returning(Alert.id)
            ).all()
            # Links of alerts this run did not touch (stale ones) may still carry the old
            # timestamp of an event that a reprocess moved: realign every link of the case.
            session.execute(
                text(
                    "UPDATE alert_events ae SET event_ts = e.ts FROM alerts a, events e "
                    "WHERE a.id = ae.alert_id AND a.case_id = :case_id AND e.case_id = :case_id "
                    "AND e.id = ae.event_id AND ae.event_ts <> e.ts"
                ),
                {"case_id": claim.case_id},
            )
            session.commit()
        except (JobCancelledError, JobFencedError):
            session.rollback()
            raise
        except OperationalError as exc:
            session.rollback()
            raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc
        return len(result)

    def _requeue(self, session: Session, job_id: uuid.UUID, token: int, error: str) -> bool:
        try:
            done = session.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == JobStatus.running, Job.attempts == token)
                .values(status=JobStatus.queued, error=f"retrying: {error}", heartbeat_at=None)
                .returning(Job.id)
            ).scalar_one_or_none()
            session.commit()
        except (IntegrityError, DBAPIError):
            # another detection job for the case is already queued: this one ends failed and
            # the queued one covers the retry
            session.rollback()
            return False
        return done is not None

    def _finish(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        manifest: dict[str, Any],
        counts: dict[str, int],
        outcome: str,
        error: str | None,
    ) -> RunResult:
        finished = self.clock()
        manifest.update(
            finished_at=_iso(finished),
            duration_ms=int(
                (
                    finished - datetime.fromisoformat(manifest["started_at"].replace("Z", "+00:00"))
                ).total_seconds()
                * 1000
            ),
            outcome=outcome,
            error=error,
            counts=counts,
        )
        try:
            row = session.execute(
                select(Job.status, Job.attempts)
                .where(Job.id == job_id)
                .with_for_update(key_share=True)
            ).one()
            if row.attempts != claim.token or row.status not in (
                JobStatus.running,
                JobStatus.cancelled,
            ):
                session.rollback()
                return RunResult(job_id, "fenced", counts=counts)
            if row.status is JobStatus.cancelled:
                outcome = manifest["outcome"] = "cancelled"
                values: dict[str, Any] = {"run_manifest": manifest}
            else:
                status = JobStatus(outcome)
                values = {
                    "status": status,
                    "finished_at": func.now(),
                    "run_manifest": manifest,
                    "error": error,
                    "progress": 1.0 if status is JobStatus.succeeded else Job.progress,
                    "heartbeat_at": func.now(),
                }
            session.execute(update(Job).where(Job.id == job_id).values(**values))
            AuditService(session).record(
                "detection.completed",
                user_id=None,
                object_type="job",
                object_id=job_id,
                detail={"case_id": str(claim.case_id), "outcome": outcome, **counts},
            )
            session.commit()
        except DBAPIError:
            session.rollback()
            log.exception("detect_finish_failed", job_id=str(job_id))
            raise
        log.info("detect_finished", job_id=str(job_id), outcome=outcome, **counts)
        return RunResult(job_id, outcome, counts=counts, error=error)


def _uuid(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


__all__ = ["DetectionJobs", "DetectionService", "and_"]
