"""Worker-side processing of one parse job (guide 10.1, 10.6, 4.3).

``ProcessingService.run(job_id)``:

1. **Claim** atomically: ``UPDATE jobs SET status='running', attempts=attempts+1 ... WHERE
   status='queued' OR (status='running' AND heartbeat_at < now() - lease) RETURNING attempts``.
   The returned ``attempts`` is this run's fencing token.
2. **Integrity first**: the evidence must be ``stored``; its custody chain must verify against the
   trusted keys (running signer + trust file, never DB rows); the bytes are streamed from the
   recorded vault version into a private scratch file while hashing, and the SHA-256/size must
   equal the value in the *signed* ``ingested`` custody entry (and ``evidence.sha256``). A
   mismatch fails the job, writes ``verification_failed`` custody and notifies admins.
3. The scratch copy is made read-only (0400) and handed to the pure parser.
4. **Replace**: under the job row lock (token re-checked) the previous events of this
   ``(evidence, parser)`` are deleted; the new rows use deterministic ids + ``ON CONFLICT DO
   NOTHING``, so retries and reprocessing never duplicate.
5. **Batches**: before inserting, ``dfir_ensure_events_partition`` runs in its own short
   transaction for each new month; then one transaction locks the job row (``FOR NO KEY
   UPDATE``), re-checks ``status='running' AND attempts=token``, inserts the batch and advances
   progress/heartbeat. A cancel (which updates the same row) therefore either lands before a
   batch (the batch is not written) or after it; no event is written after a cancel commits.
6. **Finish** under the same lock: status, run manifest and a signed ``processed`` custody entry
   (with the manifest's SHA-256) commit together.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import platform
import shutil
import socket
import stat
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.config import Settings
from app.core.hashing import MultiHasher
from app.core.signing import CustodySigner
from app.db.models import Case, CaseStatus, Evidence, Job, JobStatus
from app.db.models import Event as EventRow
from app.parsers.base import ParseContext, ParseLimits, ParserInputError, ParseStats, ToolConfig
from app.parsers.normalize import NormalizationError, to_row
from app.parsers.registry import UnknownParserError, get_parser
from app.repositories.vault import VaultObjectMissingError, VaultStore
from app.services.custody import Actor, CustodyService, canonical
from app.services.evidence import safe_filename
from app.services.notifications import notify_admins
from app.services.outbox import emit_verification_failed

log = structlog.stdlib.get_logger("dfirbench.processing")

PARTITION_MIN = datetime(1970, 1, 1, tzinfo=UTC)
PARTITION_AHEAD = timedelta(days=366)
READ_CHUNK = 1024 * 1024


class JobCancelledError(Exception):
    """The job was cancelled while running (seen under the row lock)."""


class JobFencedError(Exception):
    """Another worker owns the job now (attempt token changed); stop without writing."""


class TransientJobError(Exception):
    """I/O or database trouble worth retrying."""


class IntegrityFailureError(Exception):
    """``bytes_mismatch``: the stored object is missing or its bytes differ (custody
    ``hash_failed``, evidence -> ``failed``, as in ``EvidenceService.verify``); otherwise the
    custody record itself does not verify (``verification_failed``)."""

    def __init__(self, message: str, detail: dict[str, Any], *, bytes_mismatch: bool) -> None:
        super().__init__(message)
        self.detail = detail
        self.bytes_mismatch = bytes_mismatch


class OutputLimitError(Exception):
    pass


@dataclass
class RunResult:
    job_id: uuid.UUID
    outcome: str  # succeeded|partial|failed|cancelled|skipped|busy|fenced|retry
    retry: bool = False
    counts: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": str(self.job_id),
            "outcome": self.outcome,
            "counts": self.counts,
            "error": self.error,
        }


@dataclass
class _Claim:
    token: int
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    parser: str
    params: dict[str, Any]
    created_by: uuid.UUID | None


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _version(dist: str) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


def manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(dict(manifest))).hexdigest()


def parse_limits(settings: Settings) -> ParseLimits:
    mib = 1024 * 1024
    return ParseLimits(
        max_line_bytes=settings.parser_max_line_kb * 1024,
        max_decompressed_bytes=settings.parser_max_decompressed_mb * mib,
        max_decompression_ratio=settings.parser_max_decompression_ratio,
        max_structured_bytes=settings.parser_max_structured_mb * mib,
        max_records=settings.parser_max_records,
    )


def tool_config(settings: Settings) -> ToolConfig:
    """Trusted engine/rule configuration for parsers (never taken from job params)."""
    mib = 1024 * 1024
    return ToolConfig(
        search_path=settings.tool_search_path or None,
        timeout_s=settings.tool_timeout_s,
        max_output_bytes=settings.tool_max_output_mb * mib,
        yara_rules_dirs=(settings.yara_rules_dir,) if settings.yara_rules_dir else (),
        yara_timeout_s=settings.yara_timeout_s,
        yara_max_file_bytes=settings.yara_max_file_mb * mib,
        volatility_symbols_dir=settings.volatility_symbols_dir or None,
        sqlite_timeout_s=settings.parser_sqlite_timeout_s,
    )


class EventSink:
    """Buffers normalized rows and flushes them in fenced, lock-protected batches."""

    def __init__(
        self,
        service: ProcessingService,
        session: Session,
        job_id: uuid.UUID,
        token: int,
        stats: ParseStats,
    ) -> None:
        self.svc = service
        self.session = session
        self.job_id = job_id
        self.token = token
        self.stats = stats
        self.pending: list[dict[str, Any]] = []
        self.months: set[tuple[int, int]] = set()
        self.partitions: list[str] = []
        self.outside_window = 0
        self.inserted = 0
        self.output_bytes = 0
        self.progress = 0.0
        self.last_flush = time.monotonic()
        settings = service.settings
        self.batch = settings.ingest_batch_size
        self.interval = settings.ingest_flush_interval_s
        self.max_output = settings.parser_max_output_mb * 1024 * 1024
        self.max_partitions = settings.max_new_partitions_per_job

    def add(self, row: dict[str, Any], size: int) -> None:
        self.output_bytes += size
        if self.output_bytes > self.max_output:
            raise OutputLimitError("PARSER_MAX_OUTPUT_MB exceeded")
        self.pending.append(row)
        if len(self.pending) >= self.batch:
            self.flush()

    def tick(self, fraction: float) -> None:
        self.progress = max(self.progress, min(max(fraction, 0.0), 1.0))
        if time.monotonic() - self.last_flush >= self.interval:
            self.flush()

    def _ensure_partitions(self, rows: list[dict[str, Any]]) -> None:
        now = self.svc.clock()
        for row in rows:
            ts: datetime = row["ts"]
            inside = PARTITION_MIN <= ts <= now + PARTITION_AHEAD
            if not inside:
                self.outside_window += 1
            month = (ts.year, ts.month)
            if month in self.months:
                continue
            self.months.add(month)
            if not inside:
                self.stats.warn("timestamp_outside_partition_window", detail=f"{month}")
                continue
            if len(self.partitions) >= self.max_partitions:
                self.stats.warn("partition_cap_reached", detail=f"{month}")
                continue
            # Own short transaction: CREATE/ATTACH must not wait while we hold other locks.
            name: str = self.session.execute(
                text("SELECT dfir_ensure_events_partition(:ts)"), {"ts": ts}
            ).scalar_one()
            self.session.commit()
            self.partitions.append(str(name))

    def flush(self) -> None:
        rows = self.pending
        try:
            if rows:
                self._ensure_partitions(rows)
            self.svc.lock_running(self.session, self.job_id, self.token)
            if rows:
                # RETURNING counts the rows really inserted (rowcount is -1 for multi-VALUES).
                inserted = len(
                    self.session.execute(
                        pg_insert(EventRow)
                        .values(rows)
                        .on_conflict_do_nothing(index_elements=["id", "ts"])
                        .returning(EventRow.id)
                    ).all()
                )
                self.inserted += inserted
                if inserted < len(rows):
                    self.stats.warn("duplicate_event_id", detail=str(len(rows) - inserted))
            self.session.execute(
                update(Job)
                .where(Job.id == self.job_id)
                .values(
                    progress=func.greatest(Job.progress, round(self.progress * 0.99, 4)),
                    heartbeat_at=func.now(),
                )
            )
            self.session.commit()
        except (JobCancelledError, JobFencedError):
            self.session.rollback()
            raise
        except OperationalError as exc:
            self.session.rollback()
            raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc
        self.pending = []
        self.last_flush = time.monotonic()


class ProcessingService:
    #: ``jobs.kind`` this service claims (the bundle ingest subclass claims ``bundle`` jobs).
    job_kind = "parse"

    def __init__(
        self,
        sessions: sessionmaker[Session],
        settings: Settings,
        *,
        vault: VaultStore | None,
        signer: CustodySigner | None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
        clock: Callable[[], datetime] = utcnow,
        worker_name: str | None = None,
    ) -> None:
        self.sessions = sessions
        self.settings = settings
        self.vault = vault
        self.signer = signer
        self.trusted_keys = dict(trusted_keys or {})
        self.clock = clock
        self.worker = worker_name or socket.gethostname()
        self.actor = Actor(user_id=None, label=f"system:worker <{self.worker}>")

    # ------------------------------------------------------------------ fencing helpers

    @staticmethod
    def lock_running(session: Session, job_id: uuid.UUID, token: int) -> None:
        """Lock the job row and re-check that this run still owns it."""
        row = session.execute(
            select(Job.status, Job.attempts).where(Job.id == job_id).with_for_update(key_share=True)
        ).one()
        if row.attempts != token:
            raise JobFencedError(str(job_id))
        if row.status is JobStatus.cancelled:
            raise JobCancelledError(str(job_id))
        if row.status is not JobStatus.running:
            raise JobFencedError(str(job_id))

    def _claim(self, session: Session, job_id: uuid.UUID) -> _Claim | None:
        lease = timedelta(seconds=self.settings.job_lease_s)
        row = session.execute(
            update(Job)
            .where(
                Job.id == job_id,
                Job.kind == self.job_kind,
                Job.superseded_by.is_(None),
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
            .returning(
                Job.attempts, Job.evidence_id, Job.case_id, Job.parser, Job.params, Job.created_by
            )
        ).one_or_none()
        session.commit()
        if row is None or row.evidence_id is None or row.parser is None:
            return None
        return _Claim(
            row.attempts, row.evidence_id, row.case_id, row.parser, dict(row.params), row.created_by
        )

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
                log.info("job_not_claimed", job_id=str(job_id), status=str(status))
                # "busy": another worker holds a live lease (or a crashed one has not expired yet);
                # the task retries after the lease so a lost worker's job is picked up again.
                outcome = "busy" if status is JobStatus.running else "skipped"
                return RunResult(job_id, outcome)
            scratch = self._scratch_dir(job_id)
            try:
                return self._run_claimed(
                    session, job_id, claim, scratch, allow_retry, stop_exceptions
                )
            finally:
                shutil.rmtree(scratch, ignore_errors=True)

    def _scratch_dir(self, job_id: uuid.UUID) -> Path:
        root = Path(self.settings.scratch_dir or Path(tempfile.gettempdir()) / "dfirbench-scratch")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f"job-{job_id}-", dir=root))

    def _run_claimed(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        scratch: Path,
        allow_retry: bool,
        stop_exceptions: tuple[type[BaseException], ...],
    ) -> RunResult:
        started = self.clock()
        stats = ParseStats()
        manifest: dict[str, Any] = {
            "job_id": str(job_id),
            "evidence_id": str(claim.evidence_id),
            "case_id": str(claim.case_id),
            "parser": claim.parser,
            "params": claim.params,
            "attempt": claim.token,
            "worker": self.worker,
            "started_at": _iso(started),
            "container_image_digest": os.environ.get("DFIR_IMAGE_DIGEST") or None,
        }
        read_evidence = False
        sink: EventSink | None = None
        outcome = "failed"
        error: str | None = None
        try:
            if self.signer is None:
                raise ParserInputError("custody signer unavailable: cannot record processing")
            try:
                parser = get_parser(claim.parser)
            except UnknownParserError as exc:
                raise ParserInputError(f"unknown parser {claim.parser!r}") from exc
            manifest["parser_version"] = parser.version
            manifest["tools"] = {
                "python": platform.python_version(),
                "dfirbench": __version__,
                "tzdata": _version("tzdata"),
                **parser.tool_versions(),
            }
            ev = session.execute(
                select(Evidence).where(Evidence.id == claim.evidence_id)
            ).scalar_one()
            session.commit()
            if ev.status != "stored":
                raise ParserInputError(f"evidence is {ev.status!r}, not 'stored'")
            case_status = session.execute(
                select(Case.status).where(Case.id == claim.case_id)
            ).scalar_one()
            session.commit()
            if case_status is CaseStatus.closed:  # close refuses active jobs; defense in depth
                raise ParserInputError("the case is closed")
            source_file = safe_filename(ev.original_name)
            manifest["source_file"] = source_file
            path = scratch / "evidence.bin"  # fixed name: evidence content never names a path
            digest = self._fetch_verified(session, ev, path)
            read_evidence = True
            manifest.update(
                evidence_sha256=digest["sha256"],
                evidence_size=digest["size"],
                evidence_version_id=ev.storage_version_id,
            )
            os.chmod(path, stat.S_IRUSR)  # read-only for the parser
            deleted = self._replace_previous(session, job_id, claim)
            manifest["replaced_previous_events"] = deleted
            reference, ref_source = (
                (ev.acquired_at, "acquired_at")
                if ev.acquired_at
                else (ev.created_at, "uploaded_at")
            )
            sink = EventSink(self, session, job_id, claim.token, stats)
            work_dir = scratch / "work"  # external engines write only here (0700, removed after)
            work_dir.mkdir(mode=0o700)
            ctx = ParseContext(
                path=path,
                evidence_id=str(ev.id),
                case_id=str(ev.case_id),
                source_file=source_file,
                host_hint=ev.source_host,
                timezone=str(claim.params.get("timezone", "UTC")),
                year=claim.params.get("year"),
                reference_time=reference,
                reference_source=ref_source,
                params=claim.params,
                stats=stats,
                limits=parse_limits(self.settings),
                tools=tool_config(self.settings),
                work_dir=work_dir,
                progress=sink.tick,
            )
            manifest["limits"] = {
                "max_line_bytes": ctx.limits.max_line_bytes,
                "max_decompressed_bytes": ctx.limits.max_decompressed_bytes,
                "max_decompression_ratio": ctx.limits.max_decompression_ratio,
                "max_structured_bytes": ctx.limits.max_structured_bytes,
                "max_records": ctx.limits.max_records,
                "max_output_bytes": sink.max_output,
                "tool_timeout_s": ctx.tools.timeout_s,
                "tool_max_output_bytes": ctx.tools.max_output_bytes,
            }
            for event in parser.parse(ctx):
                try:
                    row, size = to_row(
                        event,
                        case_id=str(ev.case_id),
                        evidence_id=str(ev.id),
                        job_id=str(job_id),
                        parser_name=parser.name,
                        parser_version=parser.version,
                    )
                except NormalizationError as exc:
                    stats.error(event.record_key or "?", "normalize_failed", str(exc))
                    continue
                if row["raw"].get("_truncated") is True:
                    stats.warn("raw_truncated", event.record_key)
                stats.events_emitted += 1
                sink.add(row, size)
            sink.flush()
            incomplete = stats.assumptions.get("incomplete")
            if incomplete:
                outcome, error = "partial", f"input not fully readable: {incomplete}"
            else:
                outcome = "succeeded"
        except JobFencedError:
            log.warning("job_fenced", job_id=str(job_id), attempt=claim.token)
            return RunResult(job_id, "fenced", counts=stats.counts())
        except JobCancelledError:
            outcome, error = "cancelled", None
        except IntegrityFailureError as exc:
            self._integrity_failure(session, claim, job_id, exc)
            outcome, error = "failed", f"integrity check failed: {exc}"
        except ParserInputError as exc:
            outcome, error = "failed", f"unusable input: {exc}"
        except OutputLimitError as exc:
            self._flush_quietly(sink)
            outcome, error = "partial", str(exc)
        except TransientJobError as exc:
            session.rollback()
            if allow_retry and self._requeue(session, job_id, claim.token, str(exc)):
                return RunResult(job_id, "retry", retry=True, error=str(exc))
            outcome, error = "failed", f"transient error, retries exhausted: {exc}"
        except stop_exceptions as exc:  # e.g. Celery SoftTimeLimitExceeded
            self._flush_quietly(sink)
            outcome, error = "partial", f"stopped: {type(exc).__name__} (time limit)"
        except Exception as exc:
            session.rollback()
            log.exception("job_crashed", job_id=str(job_id))
            outcome, error = "failed", f"internal error: {type(exc).__name__}"
        if outcome == "partial" and stats.events_emitted == 0:
            outcome = "failed"
        return self._finish(
            session, job_id, claim, manifest, stats, sink, outcome, error, read_evidence
        )

    # ------------------------------------------------------------------ steps

    def _fetch_verified(self, session: Session, ev: Evidence, path: Path) -> dict[str, Any]:
        custody = CustodyService(session, self.signer, self.clock, self.trusted_keys)
        chain = custody.verify(ev.id)
        signed_sha = custody.signed_value(ev.id, "ingested", "sha256")
        signed_size = custody.signed_value(ev.id, "ingested", "size_bytes")
        session.commit()
        if not chain.ok:
            raise IntegrityFailureError(
                "custody chain does not verify",
                {"chain_ok": False, "broken_seqs": chain.broken_seqs},
                bytes_mismatch=False,
            )
        if signed_sha is None or signed_sha != ev.sha256 or signed_size != ev.size_bytes:
            raise IntegrityFailureError(
                "evidence hash/size differ from the signed ingest entry",
                {"signed_sha256": signed_sha, "recorded_sha256": ev.sha256},
                bytes_mismatch=False,
            )
        if self.vault is None:
            raise TransientJobError("vault unavailable")
        prefix = f"s3://{self.vault.bucket}/"
        if not ev.storage_uri.startswith(prefix):
            raise ParserInputError("evidence is stored in another vault")
        key = ev.storage_uri[len(prefix) :]
        hasher = MultiHasher()
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600
            )
            with os.fdopen(fd, "wb") as out:
                for chunk in self.vault.iter_object(key, ev.storage_version_id, READ_CHUNK):
                    hasher.update(chunk)
                    out.write(chunk)
        except VaultObjectMissingError as exc:
            raise IntegrityFailureError(
                "original object missing from the vault", {}, bytes_mismatch=True
            ) from exc
        except OSError as exc:
            raise TransientJobError(f"scratch/vault I/O error: {type(exc).__name__}") from exc
        except Exception as exc:
            raise TransientJobError(f"vault read failed: {type(exc).__name__}") from exc
        digests = hasher.digests()
        if digests.sha256 != signed_sha or digests.size != signed_size:
            raise IntegrityFailureError(
                "stored bytes do not match the signed SHA-256",
                {"expected_sha256": signed_sha, "actual_sha256": digests.sha256},
                bytes_mismatch=True,
            )
        return {"sha256": digests.sha256, "size": digests.size}

    def _replace_previous(self, session: Session, job_id: uuid.UUID, claim: _Claim) -> int:
        try:
            self.lock_running(session, job_id, claim.token)
            result = session.execute(
                delete(EventRow).where(
                    EventRow.evidence_id == claim.evidence_id,
                    EventRow.parser_name == claim.parser,
                )
            )
            session.commit()
        except (JobCancelledError, JobFencedError):
            session.rollback()
            raise
        except OperationalError as exc:
            session.rollback()
            raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    def _requeue(self, session: Session, job_id: uuid.UUID, token: int, error: str) -> bool:
        try:
            done = session.execute(
                update(Job)
                .where(Job.id == job_id, Job.status == JobStatus.running, Job.attempts == token)
                .values(status=JobStatus.queued, error=f"retrying: {error}", heartbeat_at=None)
                .returning(Job.id)
            ).scalar_one_or_none()
            session.commit()
        except DBAPIError:
            session.rollback()
            return False
        return done is not None

    @staticmethod
    def _flush_quietly(sink: EventSink | None) -> None:
        """Keep what was parsed before a stop (partial result), if the job still owns the row."""
        if sink is None:
            return
        try:
            sink.flush()
        except Exception:  # noqa: BLE001 - best effort; the outcome is recorded either way
            sink.session.rollback()

    def _integrity_failure(
        self, session: Session, claim: _Claim, job_id: uuid.UUID, exc: IntegrityFailureError
    ) -> None:
        session.rollback()
        try:
            custody = CustodyService(session, self.signer, self.clock, self.trusted_keys)
            # append() locks the evidence row (FOR UPDATE) before the status change below.
            custody.append(
                claim.evidence_id,
                "hash_failed" if exc.bytes_mismatch else "verification_failed",
                self.actor,
                {"source": "processing", "job_id": str(job_id), "reason": str(exc), **exc.detail},
            )
            if exc.bytes_mismatch:
                session.execute(
                    update(Evidence)
                    .where(Evidence.id == claim.evidence_id, Evidence.status == "stored")
                    .values(status="failed")
                )
            notify_admins(
                session,
                "evidence.integrity_failure",
                {
                    "evidence_id": str(claim.evidence_id),
                    "job_id": str(job_id),
                    "stage": "processing",
                },
            )
            emit_verification_failed(session, claim.case_id, claim.evidence_id, "processing")
            session.commit()
        except Exception:
            session.rollback()
            log.exception("integrity_failure_not_recorded", job_id=str(job_id))

    def _finish(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        manifest: dict[str, Any],
        stats: ParseStats,
        sink: EventSink | None,
        outcome: str,
        error: str | None,
        read_evidence: bool,
    ) -> RunResult:
        finished = self.clock()
        if not stats.balanced:
            stats.warn(
                "record_accounting_mismatch",
                detail=f"read={stats.records_read} emitted={stats.events_emitted} "
                f"skipped={stats.skipped} errors={stats.errors}",
            )
            if outcome == "succeeded":
                outcome, error = "partial", "record accounting mismatch (parser bug)"
        if outcome == "succeeded" and stats.warnings.get("duplicate_event_id"):
            outcome, error = "partial", "duplicate event ids: fewer events inserted than emitted"
        counts = stats.counts()
        manifest.update(
            finished_at=_iso(finished),
            duration_ms=int(
                (finished - self._parse_iso(manifest["started_at"])).total_seconds() * 1000
            ),
            outcome=outcome,
            error=error,
            counts={
                **counts,
                "inserted": sink.inserted if sink else 0,
                "outside_partition_window": sink.outside_window if sink else 0,
            },
            warnings=dict(sorted(stats.warnings.items())),
            warning_samples=stats.warning_samples,
            error_samples=stats.error_samples,
            assumptions=stats.assumptions,
            partitions=sorted(set(sink.partitions)) if sink else [],
            bytes_read=stats.bytes_read,
        )
        digest = manifest_sha256(manifest)
        status = JobStatus(outcome)
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
                status, outcome = JobStatus.cancelled, "cancelled"
                manifest["outcome"] = "cancelled"
                digest = manifest_sha256(manifest)
                values: dict[str, Any] = {"run_manifest": manifest}
            else:
                values = {
                    "status": status,
                    "finished_at": func.now(),
                    "run_manifest": manifest,
                    "error": error,
                    "progress": 1.0 if status is JobStatus.succeeded else Job.progress,
                    "heartbeat_at": func.now(),
                }
            session.execute(update(Job).where(Job.id == job_id).values(**values))
            if read_evidence:
                CustodyService(session, self.signer, self.clock, self.trusted_keys).append(
                    claim.evidence_id,
                    "processed",
                    self.actor,
                    {
                        "job_id": str(job_id),
                        "parser": claim.parser,
                        "parser_version": manifest.get("parser_version"),
                        "outcome": outcome,
                        "attempt": claim.token,
                        "sha256": manifest.get("evidence_sha256"),
                        "version_id": manifest.get("evidence_version_id"),
                        "requested_by": str(claim.created_by) if claim.created_by else None,
                        "manifest_sha256": digest,
                        "replaced_previous_events": manifest.get("replaced_previous_events", 0),
                        **counts,
                    },
                )
            session.commit()
        except DBAPIError:
            session.rollback()
            log.exception("job_finish_failed", job_id=str(job_id))
            raise
        log.info("job_finished", job_id=str(job_id), outcome=outcome, **counts)
        return RunResult(job_id, outcome, counts=counts, error=error)

    @staticmethod
    def _parse_iso(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
