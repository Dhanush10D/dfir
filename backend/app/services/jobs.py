"""JobService (guide 14.4, 10.6): submit (idempotent), cancel, retry, reprocess, read.

Concurrency rules (all state changes are atomic in the database):

* Creating a job for ``(evidence, parser)`` runs under a transaction-scoped advisory lock for that
  pair; every read after it sees all committed jobs. The partial unique index
  ``uq_jobs_active_parse`` is the backstop: never two queued/running parse jobs for one pair.
* Submitting the same ``(evidence, parser, parser_version, params)`` twice returns the existing job
  (``idempotency_key`` is UNIQUE; a concurrent duplicate insert resolves to the winner's row).
* A new job for a pair (other params, a new parser version, or an explicit reprocess) supersedes
  the pair's previous jobs: their ``idempotency_key`` moves to the new job and ``superseded_by``
  points at it. The new run replaces the pair's events.
* Cancel, retry and the worker's writes are single conditional ``UPDATE ... RETURNING``
  statements (or run under ``SELECT ... FOR NO KEY UPDATE``) and re-check the status they expect,
  so a job can never be both cancelled and completed, or retried twice.

Enqueueing happens after commit through an injected dispatcher (no queue import here).
"""

from __future__ import annotations

import hashlib
import uuid
import zoneinfo
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

import structlog
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Case, CaseStatus, Evidence, Job, JobStatus
from app.parsers.base import Parser
from app.parsers.registry import UnknownParserError, all_parsers, detect, get_parser
from app.repositories.vault import VaultStore
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access
from app.services.custody import canonical

log = structlog.stdlib.get_logger("dfirbench.jobs")

PARSE = "parse"
DETECT = "detect"
ACTIVE = (JobStatus.queued, JobStatus.running)
TERMINAL = (JobStatus.succeeded, JobStatus.partial, JobStatus.failed, JobStatus.cancelled)
RETRYABLE = (JobStatus.failed, JobStatus.partial, JobStatus.cancelled)
HEAD_BYTES = 8192
# Parameters each parser accepts (anything else is rejected with 422).
PARSER_PARAMS: dict[str, frozenset[str]] = {
    "linux_auth": frozenset({"timezone", "year"}),
    "evtx": frozenset(),
}
YEAR_RANGE = (1970, 2100)

Dispatcher = Callable[[uuid.UUID], None]


@lru_cache(maxsize=1)
def _zones() -> frozenset[str]:
    return frozenset(zoneinfo.available_timezones())


def validate_params(parser: str, params: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical params for ``parser``; raises 422 on unknown keys or bad values."""
    accepted = PARSER_PARAMS.get(parser, frozenset())
    clean: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        if key not in accepted:
            raise AppError(
                "invalid_params",
                f"Parser {parser!r} does not accept parameter {key!r}.",
                422,
                details={"parser": parser, "accepted": sorted(accepted)},
            )
        if key == "timezone":
            if not isinstance(value, str) or value not in _zones():
                raise AppError("invalid_params", "timezone must be an IANA zone name.", 422)
            clean[key] = value
        elif key == "year":
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not YEAR_RANGE[0] <= value <= YEAR_RANGE[1]
            ):
                raise AppError("invalid_params", "year must be an integer 1970-2100.", 422)
            clean[key] = value
    if "timezone" in accepted:
        clean.setdefault("timezone", "UTC")
    return clean


def idempotency_key(
    evidence_id: uuid.UUID, parser: str, parser_version: str, params: Mapping[str, Any]
) -> str:
    body = {
        "evidence_id": str(evidence_id),
        "parser": parser,
        "parser_version": parser_version,
        "params": dict(params),
    }
    return hashlib.sha256(canonical(body)).hexdigest()


def pair_lock_key(evidence_id: uuid.UUID, parser: str) -> int:
    digest = hashlib.sha256(f"dfir_job:{evidence_id}:{parser}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Submitted:
    job: Job
    created: bool


class JobService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        vault: VaultStore | None = None,
        dispatcher: Dispatcher | None = None,
        detect_dispatcher: Dispatcher | None = None,
    ) -> None:
        self.session = session
        self.settings = settings
        self.vault = vault
        self.dispatcher = dispatcher
        self.detect_dispatcher = detect_dispatcher
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ access helpers

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _load_job(self, principal: Principal, job_id: uuid.UUID) -> tuple[Job, CaseAccess]:
        job = self.session.get(Job, job_id)
        if job is None:
            raise NotFoundError("Job not found.")
        access = self._access(principal, job.case_id)  # 404 for unreadable cases
        return job, access

    def _load_evidence(
        self, principal: Principal, evidence_id: uuid.UUID
    ) -> tuple[Evidence, CaseAccess]:
        ev = self.session.get(Evidence, evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        return ev, self._access(principal, ev.case_id)

    @staticmethod
    def _require_open(access: CaseAccess) -> None:
        if access.case.status is CaseStatus.closed:
            raise InvalidStateError("The case is closed.")

    def _lock_case_open(self, case_id: uuid.UUID) -> None:
        """``FOR SHARE`` on the case row, then re-check it is open.

        ``CaseService.close`` takes ``FOR UPDATE`` on the same row and refuses while jobs are
        queued/running, so a job can never be queued in a case that is closed or being closed.
        """
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            raise InvalidStateError("The case is closed.")

    @staticmethod
    def _require_stored(ev: Evidence) -> None:
        if ev.status != "stored":
            raise InvalidStateError(
                "Only finalized (stored) evidence can be processed.", status=ev.status
            )

    # ------------------------------------------------------------------ read

    def parsers(self) -> list[Parser]:
        return list(all_parsers().values())

    def get(self, principal: Principal, job_id: uuid.UUID) -> Job:
        job, _ = self._load_job(principal, job_id)
        return job

    def list_for_case(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        status: JobStatus | None = None,
        evidence_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> list[Job]:
        self._access(principal, case_id)
        stmt = select(Job).where(Job.case_id == case_id)
        if status is not None:
            stmt = stmt.where(Job.status == status)
        if evidence_id is not None:
            stmt = stmt.where(Job.evidence_id == evidence_id)
        stmt = stmt.order_by(Job.queued_at.desc(), Job.id.desc()).limit(limit)
        return list(self.session.execute(stmt).scalars())

    # ------------------------------------------------------------------ submit

    def _select_parsers(self, ev: Evidence, requested: list[str] | None) -> list[str]:
        if requested:
            names = list(dict.fromkeys(requested))
            for name in names:
                try:
                    get_parser(name)
                except UnknownParserError as exc:
                    raise AppError(
                        "unknown_parser",
                        f"Unknown parser {name!r}.",
                        422,
                        details={"available": sorted(all_parsers())},
                    ) from exc
            return names
        head = self._head(ev)
        found = [name for name, _ in detect(head, ev.original_name)]
        if not found:
            raise AppError(
                "no_parser",
                "No parser recognizes this evidence; name one explicitly.",
                422,
                details={"available": sorted(all_parsers())},
            )
        return found[:1]

    def _head(self, ev: Evidence) -> bytes:
        if self.vault is None:
            raise AppError("vault_unavailable", "The evidence vault is not available.", 503)
        prefix = f"s3://{self.vault.bucket}/"
        if not ev.storage_uri.startswith(prefix):
            raise AppError("storage_mismatch", "Evidence is stored in another vault.", 500)
        chunks = self.vault.iter_object(
            ev.storage_uri[len(prefix) :], ev.storage_version_id, HEAD_BYTES
        )
        try:
            return next(iter(chunks), b"")[:HEAD_BYTES]
        finally:
            close = getattr(chunks, "close", None)
            if close is not None:
                close()

    def submit(
        self,
        principal: Principal,
        evidence_id: uuid.UUID,
        *,
        parsers: list[str] | None,
        params: Mapping[str, Any],
        meta: RequestMeta,
    ) -> list[Submitted]:
        """``parsers=None`` means auto-detect. Returns one entry per parser."""
        ev, access = self._load_evidence(principal, evidence_id)
        access.require(Permission.EVIDENCE_ADD)
        self._require_open(access)
        self._require_stored(ev)
        names = self._select_parsers(ev, parsers)
        given = {k: v for k, v in params.items() if v is not None}
        if not parsers:  # auto: each detected parser takes the parameters it understands
            allowed: set[str] = set()
            for name in names:
                allowed |= PARSER_PARAMS.get(name, frozenset())
            if set(given) - allowed:
                raise AppError(
                    "invalid_params",
                    "Parameters not accepted by the detected parser.",
                    422,
                    details={"parsers": names, "accepted": sorted(allowed)},
                )
        prepared = []
        for name in names:
            accepted = PARSER_PARAMS.get(name, frozenset())
            relevant = {k: v for k, v in given.items() if k in accepted} if not parsers else given
            prepared.append((name, validate_params(name, relevant)))
        self._lock_case_open(ev.case_id)
        results = [
            self._create(principal, ev, name, canon, force=False) for name, canon in prepared
        ]
        for result in results:
            self.audit.record(
                "job.submitted",
                user_id=principal.user_id,
                meta=meta,
                object_type="job",
                object_id=result.job.id,
                detail={
                    "evidence_id": str(ev.id),
                    "parser": result.job.parser,
                    "created": result.created,
                },
            )
        self.session.commit()
        for result in results:
            if result.created:
                self._dispatch(result.job)
        return results

    def _create(
        self,
        principal: Principal,
        ev: Evidence,
        parser_name: str,
        params: dict[str, Any],
        *,
        force: bool,
    ) -> Submitted:
        parser = get_parser(parser_name)
        key = idempotency_key(ev.id, parser_name, parser.version, params)
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(:k)"), {"k": pair_lock_key(ev.id, parser_name)}
        )
        if not force:
            existing = self.session.execute(
                select(Job).where(Job.idempotency_key == key)
            ).scalar_one_or_none()
            if existing is not None:
                return Submitted(existing, False)
        current = list(
            self.session.execute(
                select(Job)
                .where(
                    Job.evidence_id == ev.id,
                    Job.parser == parser_name,
                    Job.kind == PARSE,
                    Job.superseded_by.is_(None),
                )
                .with_for_update(key_share=True)
            ).scalars()
        )
        active = [j for j in current if j.status in ACTIVE]
        if active:
            raise ConflictError(
                "A job for this evidence and parser is already queued or running.",
                "job_active",
                job_id=str(active[0].id),
            )
        ids = [j.id for j in current]
        if ids:
            self.session.execute(
                update(Job)
                .where(Job.id.in_(ids), Job.idempotency_key.is_not(None))
                .values(idempotency_key=None)
            )
        new_id = uuid.uuid4()
        try:
            with self.session.begin_nested():
                self.session.execute(
                    pg_insert(Job).values(
                        id=new_id,
                        case_id=ev.case_id,
                        evidence_id=ev.id,
                        kind=PARSE,
                        parser=parser_name,
                        params=params,
                        idempotency_key=key,
                        status=JobStatus.queued,
                        created_by=principal.user_id,
                    )
                )
        except IntegrityError as exc:  # backstop: uq_jobs_active_parse / idempotency_key
            raise ConflictError(
                "A job for this evidence and parser is already queued or running.", "job_active"
            ) from exc
        if ids:
            self.session.execute(update(Job).where(Job.id.in_(ids)).values(superseded_by=new_id))
        job = self.session.execute(select(Job).where(Job.id == new_id)).scalar_one()
        return Submitted(job, True)

    def _dispatch(self, job: Job) -> None:
        dispatcher = self.detect_dispatcher if job.kind == DETECT else self.dispatcher
        if dispatcher is None:
            return
        try:
            dispatcher(job.id)
        except Exception as exc:
            log.error("job_dispatch_failed", job_id=str(job.id), exc_type=type(exc).__name__)
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

    # ------------------------------------------------------------------ control

    def cancel(self, principal: Principal, job_id: uuid.UUID, meta: RequestMeta) -> Job:
        _, access = self._load_job(principal, job_id)
        access.require(Permission.EVIDENCE_ADD)
        done = self.session.execute(
            update(Job)
            .where(Job.id == job_id, Job.status.in_(ACTIVE))
            .values(
                status=JobStatus.cancelled,
                finished_at=func.now(),
                error=f"Cancelled by {principal.label}",
            )
            .returning(Job.id)
        ).scalar_one_or_none()
        if done is None:
            self.session.rollback()
            current = self.session.execute(select(Job.status).where(Job.id == job_id)).scalar_one()
            raise InvalidStateError("Only queued or running jobs can be cancelled.", status=current)
        self.audit.record(
            "job.cancelled",
            user_id=principal.user_id,
            meta=meta,
            object_type="job",
            object_id=job_id,
        )
        self.session.commit()
        return self._reload(job_id)

    def retry(self, principal: Principal, job_id: uuid.UUID, meta: RequestMeta) -> Job:
        job, access = self._load_job(principal, job_id)
        access.require(Permission.EVIDENCE_ADD)
        self._require_open(access)
        if job.kind == DETECT:
            return self._retry_detect(principal, job, meta)
        if job.kind != PARSE or job.evidence_id is None or job.parser is None:
            raise InvalidStateError("Only parse and detection jobs can be retried.")
        ev = self.session.get(Evidence, job.evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        self._require_stored(ev)
        self._lock_case_open(job.case_id)
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(:k)"),
            {"k": pair_lock_key(job.evidence_id, job.parser)},
        )
        try:
            with self.session.begin_nested():
                done = self.session.execute(
                    update(Job)
                    .where(
                        Job.id == job_id,
                        Job.status.in_(RETRYABLE),
                        Job.superseded_by.is_(None),
                    )
                    .values(
                        status=JobStatus.queued,
                        progress=0,
                        error=None,
                        started_at=None,
                        finished_at=None,
                        heartbeat_at=None,
                        run_manifest=None,
                        queued_at=func.now(),
                    )
                    .returning(Job.id)
                ).scalar_one_or_none()
        except IntegrityError as exc:
            raise ConflictError(
                "Another job for this evidence and parser is queued or running.", "job_active"
            ) from exc
        if done is None:
            self.session.rollback()
            current = self.session.execute(select(Job).where(Job.id == job_id)).scalar_one()
            raise InvalidStateError(
                "Only failed, partial or cancelled jobs that were not superseded can be retried.",
                status=current.status,
                superseded_by=str(current.superseded_by) if current.superseded_by else None,
            )
        self.audit.record(
            "job.retried", user_id=principal.user_id, meta=meta, object_type="job", object_id=job_id
        )
        self.session.commit()
        job = self._reload(job_id)
        self._dispatch(job)
        return job

    def _retry_detect(self, principal: Principal, job: Job, meta: RequestMeta) -> Job:
        """Re-queue a failed/partial/cancelled detection job; 409 while another is queued."""
        self._lock_case_open(job.case_id)
        try:
            with self.session.begin_nested():
                done = self.session.execute(
                    update(Job)
                    .where(Job.id == job.id, Job.status.in_(RETRYABLE))
                    .values(
                        status=JobStatus.queued,
                        progress=0,
                        error=None,
                        started_at=None,
                        finished_at=None,
                        heartbeat_at=None,
                        run_manifest=None,
                        queued_at=func.now(),
                    )
                    .returning(Job.id)
                ).scalar_one_or_none()
        except IntegrityError as exc:  # uq_jobs_queued_detect
            raise ConflictError(
                "A detection job for this case is already queued.", "job_active"
            ) from exc
        if done is None:
            self.session.rollback()
            current = self.session.execute(select(Job.status).where(Job.id == job.id)).scalar_one()
            raise InvalidStateError(
                "Only failed, partial or cancelled jobs can be retried.", status=current
            )
        self.audit.record(
            "job.retried", user_id=principal.user_id, meta=meta, object_type="job", object_id=job.id
        )
        self.session.commit()
        reloaded = self._reload(job.id)
        self._dispatch(reloaded)
        return reloaded

    def reprocess(
        self,
        principal: Principal,
        job_id: uuid.UUID,
        meta: RequestMeta,
        params: Mapping[str, Any] | None = None,
    ) -> Job:
        """New run of the job's parser (current version) that replaces its events."""
        job, access = self._load_job(principal, job_id)
        access.require(Permission.EVIDENCE_ADD)
        self._require_open(access)
        if job.kind != PARSE or job.evidence_id is None or job.parser is None:
            raise InvalidStateError("Only parse jobs can be reprocessed.")
        ev = self.session.get(Evidence, job.evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        self._require_stored(ev)
        try:
            get_parser(job.parser)
        except UnknownParserError as exc:
            raise InvalidStateError("The job's parser is no longer available.") from exc
        canon = validate_params(job.parser, dict(job.params) if params is None else params)
        self._lock_case_open(job.case_id)
        # _create locks and re-checks (advisory pair lock + FOR NO KEY UPDATE on the rows).
        result = self._create(principal, ev, job.parser, canon, force=True)
        self.audit.record(
            "job.reprocessed",
            user_id=principal.user_id,
            meta=meta,
            object_type="job",
            object_id=result.job.id,
            detail={"replaces": str(job_id), "parser": job.parser},
        )
        self.session.commit()
        self._dispatch(result.job)
        return result.job

    def _reload(self, job_id: uuid.UUID) -> Job:
        job = self.session.execute(select(Job).where(Job.id == job_id)).scalar_one()
        self.session.refresh(job)
        return job
