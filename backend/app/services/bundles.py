"""Triage bundle ingest (Phase 5; guide 9.2, 8.5 "Triage bundle") and its read API.

``BundleIngestService.run(job_id)`` (worker, ``bundle`` jobs) reuses the parse-job machinery of
:class:`~app.services.processing.ProcessingService` (atomic claim with a fencing token, custody +
signed-hash verification of the stored bundle before any byte is read, lease/heartbeat, retry and
cancel semantics) and then:

1. inspects the archive and reads the manifest (``app.collection.bundle``: hostile-archive checks;
   an unsafe bundle is rejected as a whole and nothing is extracted);
2. extracts every member into the job's scratch dir under fixed names while hashing, and verifies
   each against the manifest (SHA-256 + size). Only ``verified`` members may be ingested; the
   others are quarantined and recorded (``bundle_members``), the run ends ``partial`` and admins
   are notified;
3. for each verified member a registered parser recognizes, creates *derived evidence*: the bytes
   go to the WORM vault under ``{case}/{bundle}/derived/{id}/{name}`` (outside any transaction),
   then, in ONE transaction under the job row lock (token re-checked) with the case re-checked
   open (``FOR SHARE``), the evidence row (``parent_evidence_id`` = bundle, status ``stored``), its
   signed custody chain (``created`` with provenance, ``ingested``, ``hash_verified``,
   ``locked``), a ``bundle_members`` row and a normal parse job are written. The parse job is
   dispatched after commit, so the existing pipeline re-verifies and parses it. A member already
   derived by an earlier run (same path + SHA-256, evidence ``stored``) is reused;
4. finishes under the job lock: status, run manifest, remaining ``bundle_members`` rows and a
   signed ``processed`` custody entry on the bundle.

The original bundle object is never modified: it is only read from its recorded vault version.
"""

from __future__ import annotations

import os
import platform
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, insert, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.collection import INGESTER, INGESTER_VERSION
from app.collection.bundle import (
    BundleLimits,
    BundleReader,
    BundleRejectedError,
    BundleResult,
    MemberResult,
)
from app.collection.manifest import TriageManifest
from app.collection.trust import collector_trust, load_trusted_collectors
from app.config import Settings
from app.core.exceptions import AppError, NotFoundError
from app.core.hashing import HashingReader
from app.core.permissions import Permission, Principal
from app.core.signing import CustodySigner
from app.db.models import BundleMember, Case, CaseStatus, Evidence, Job, JobStatus
from app.parsers.base import ParserInputError
from app.parsers.normalize import clean_text
from app.parsers.registry import detect
from app.repositories.vault import MIB, RetentionInfo, storage_uri
from app.services.authz import load_case_access
from app.services.custody import CustodyService
from app.services.evidence import safe_filename
from app.services.jobs import BUNDLE, PARSER_PARAMS, JobService, Submitted, validate_params
from app.services.notifications import notify_admins
from app.services.processing import (
    IntegrityFailureError,
    JobCancelledError,
    JobFencedError,
    ProcessingService,
    RunResult,
    TransientJobError,
    _Claim,
    _iso,
    manifest_sha256,
    utcnow,
)

log = structlog.stdlib.get_logger("dfirbench.bundles")

HEAD_BYTES = 8192
MAX_FLAGGED_IN_MANIFEST = 200
MAX_CUSTODY_LIST = 50
DERIVED_KIND = {"evtx": "evtx", "linux_auth": "log"}
Dispatcher = Callable[[uuid.UUID], None]


def limits_from(settings: Settings) -> BundleLimits:
    return BundleLimits(
        max_members=settings.bundle_max_members,
        max_total_bytes=settings.bundle_max_total_mb * MIB,
        max_member_bytes=settings.bundle_max_member_mb * MIB,
        max_ratio=settings.bundle_max_ratio,
    )


def _sane_time(value: datetime | None, now: datetime) -> datetime | None:
    """Collector-reported times are untrusted: keep them only when plausible."""
    if value is None:
        return None
    value = value.astimezone(UTC)
    if datetime(1990, 1, 1, tzinfo=UTC) <= value <= now + timedelta(days=1):
        return value
    return None


@dataclass
class _RunState:
    manifest: TriageManifest | None = None
    manifest_sha: str | None = None
    trust: dict[str, Any] = field(default_factory=dict)
    result: BundleResult | None = None
    rows: list[dict[str, Any]] = field(default_factory=list)  # bundle_members still to insert
    derived: list[dict[str, Any]] = field(default_factory=list)
    dispatch_failed: list[str] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    derived_capped: int = 0


class BundleIngestService(ProcessingService):
    job_kind = BUNDLE

    def __init__(
        self,
        sessions: sessionmaker[Session],
        settings: Settings,
        *,
        vault: Any,
        signer: CustodySigner | None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
        clock: Callable[[], datetime] = utcnow,
        worker_name: str | None = None,
        parse_dispatcher: Dispatcher | None = None,
        trusted_collectors: dict[str, dict[str, str]] | None = None,
    ) -> None:
        super().__init__(
            sessions,
            settings,
            vault=vault,
            signer=signer,
            trusted_keys=trusted_keys,
            clock=clock,
            worker_name=worker_name,
        )
        self.parse_dispatcher = parse_dispatcher
        self.trusted_collectors = (
            trusted_collectors
            if trusted_collectors is not None
            else load_trusted_collectors(settings.collector_trusted_hashes_path)
        )

    # ------------------------------------------------------------------ run

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
        limits = limits_from(self.settings)
        manifest: dict[str, Any] = {
            "job_id": str(job_id),
            "evidence_id": str(claim.evidence_id),
            "case_id": str(claim.case_id),
            "kind": BUNDLE,
            "ingester": INGESTER,
            "ingester_version": INGESTER_VERSION,
            "attempt": claim.token,
            "worker": self.worker,
            "started_at": _iso(started),
            "container_image_digest": os.environ.get("DFIR_IMAGE_DIGEST") or None,
            "tools": {"python": platform.python_version(), "dfirbench": __version__},
            "limits": limits.as_dict(),
        }
        state = _RunState()
        read_evidence = False
        outcome, error = "failed", None
        bundle: Evidence | None = None
        try:
            if self.signer is None:
                raise ParserInputError("custody signer unavailable: cannot record ingest")
            bundle = session.execute(
                select(Evidence).where(Evidence.id == claim.evidence_id)
            ).scalar_one()
            session.commit()
            if bundle.status != "stored":
                raise ParserInputError(f"evidence is {bundle.status!r}, not 'stored'")
            if bundle.kind != "triage_bundle":
                raise ParserInputError("evidence is not a triage bundle")
            self._require_case_open(session, claim.case_id, lock=False)
            session.commit()
            path = scratch / "bundle.zip"  # fixed name: evidence content never names a path
            digest = self._fetch_verified(session, bundle, path)
            read_evidence = True
            os.chmod(path, 0o400)
            manifest.update(
                evidence_sha256=digest["sha256"],
                evidence_size=digest["size"],
                evidence_version_id=bundle.storage_version_id,
            )
            with BundleReader(path, limits) as reader:
                tm, tm_sha = reader.read_manifest()
                state.manifest, state.manifest_sha = tm, tm_sha
                state.trust = collector_trust(tm, self.trusted_collectors)
                manifest["bundle"] = self._summary(tm, tm_sha, state.trust)
                tick = self._ticker(session, job_id, claim.token, 0.0, 0.5)
                state.result = reader.extract(scratch / "members", tm, progress=tick)
            self._derive_all(session, job_id, claim, bundle, state)
            flagged = state.result.flagged
            if flagged:
                outcome = "partial"
                error = f"{len(flagged)} member(s) failed manifest verification (quarantined)"
            else:
                outcome = "succeeded"
        except BundleRejectedError as exc:
            state.rejected = exc.reasons
            outcome, error = "failed", f"bundle rejected: {', '.join(exc.codes)}"
        except JobFencedError:
            log.warning("job_fenced", job_id=str(job_id), attempt=claim.token)
            return RunResult(job_id, "fenced")
        except JobCancelledError:
            outcome, error = "cancelled", None
        except IntegrityFailureError as exc:
            self._integrity_failure(session, claim, job_id, exc)
            outcome, error = "failed", f"integrity check failed: {exc}"
        except ParserInputError as exc:
            outcome, error = "failed", f"unusable input: {exc}"
        except TransientJobError as exc:
            session.rollback()
            if allow_retry and self._requeue(session, job_id, claim.token, str(exc)):
                return RunResult(job_id, "retry", retry=True, error=str(exc))
            outcome, error = "failed", f"transient error, retries exhausted: {exc}"
        except stop_exceptions as exc:  # e.g. Celery SoftTimeLimitExceeded
            session.rollback()
            outcome, error = "partial", f"stopped: {type(exc).__name__} (time limit)"
        except Exception as exc:
            session.rollback()
            log.exception("bundle_job_crashed", job_id=str(job_id))
            outcome, error = "failed", f"internal error: {type(exc).__name__}"
        return self._finish_bundle(
            session, job_id, claim, bundle, manifest, state, outcome, error, read_evidence
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _require_case_open(session: Session, case_id: uuid.UUID, *, lock: bool = True) -> None:
        stmt = select(Case.status).where(Case.id == case_id)
        if lock:
            stmt = stmt.with_for_update(read=True)
        if session.execute(stmt).scalar_one() is CaseStatus.closed:
            raise ParserInputError("the case is closed")

    def _ticker(
        self, session: Session, job_id: uuid.UUID, token: int, low: float, high: float
    ) -> Callable[[float], None]:
        """Progress callback: heartbeat + cancel/fence check at most every flush interval."""
        last = [time.monotonic()]

        def tick(fraction: float) -> None:
            if time.monotonic() - last[0] < self.settings.ingest_flush_interval_s:
                return
            self._touch(session, job_id, token, low + (high - low) * min(max(fraction, 0.0), 1.0))
            last[0] = time.monotonic()

        return tick

    def _touch(self, session: Session, job_id: uuid.UUID, token: int, progress: float) -> None:
        try:
            self.lock_running(session, job_id, token)
            session.execute(
                update(Job)
                .where(Job.id == job_id)
                .values(
                    progress=func.greatest(Job.progress, round(progress, 4)),
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

    @staticmethod
    def _summary(tm: TriageManifest, tm_sha: str, trust: dict[str, Any]) -> dict[str, Any]:
        return {
            "manifest_sha256": tm_sha,
            "schema": tm.schema_id,
            "collector": tm.collector.model_dump(mode="json"),
            "collector_trust": trust,
            "host": tm.host.model_dump(mode="json"),
            "operator": tm.operator,
            "case_ref": tm.case_ref,
            "mode": tm.mode,
            "elevated": tm.elevated,
            "started_at": _iso(tm.started_at),
            "finished_at": _iso(tm.finished_at) if tm.finished_at else None,
            "clock": tm.clock.model_dump(mode="json") if tm.clock else None,
            "files_listed": len(tm.files),
            "collector_errors": len(tm.errors),
            "collector_error_samples": [e.model_dump(mode="json") for e in tm.errors[:50]],
            "collector_skipped": len(tm.skipped),
        }

    def _parse_params(self, parser: str, tm: TriageManifest) -> dict[str, Any]:
        tz = tm.host.timezone
        if tz and "timezone" in PARSER_PARAMS.get(parser, frozenset()):
            try:
                return validate_params(parser, {"timezone": tz})
            except AppError:
                return {}
        return {}

    # ------------------------------------------------------------------ derive

    def _derive_all(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        bundle: Evidence,
        state: _RunState,
    ) -> None:
        result, tm = state.result, state.manifest
        if result is None or tm is None:  # set by the caller; explicit instead of assert
            raise ParserInputError("bundle was not extracted")
        candidates: list[tuple[MemberResult, str]] = []
        for member in result.members:
            parser = None
            if member.status == "verified" and member.file is not None:
                with member.file.open("rb") as fh:
                    head = fh.read(HEAD_BYTES)
                found = detect(head, member.path.rsplit("/", 1)[-1])
                parser = found[0][0] if found else None
            if parser is None:
                state.rows.append(self._row(bundle, job_id, claim.token, member, None))
            else:
                candidates.append((member, parser))
        cap = self.settings.bundle_max_derived
        if len(candidates) > cap:
            state.derived_capped = len(candidates) - cap
            for member, parser in candidates[cap:]:
                state.rows.append(
                    self._row(bundle, job_id, claim.token, member, parser, not_derived="cap")
                )
            candidates = candidates[:cap]
        tick = self._ticker(session, job_id, claim.token, 0.5, 0.99)
        for n, (member, parser) in enumerate(candidates, 1):
            self._derive_one(session, job_id, claim, bundle, state, member, parser)
            tick(n / max(len(candidates), 1))

    @staticmethod
    def _row(
        bundle: Evidence,
        job_id: uuid.UUID,
        attempt: int,
        member: MemberResult,
        parser: str | None,
        not_derived: str | None = None,
        derived_id: uuid.UUID | None = None,
        parse_job_id: uuid.UUID | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        extra = dict(detail or {})
        if member.detail:
            extra["error"] = member.detail
        if not_derived:
            extra["not_derived"] = not_derived
        return {
            "case_id": bundle.case_id,
            "bundle_evidence_id": bundle.id,
            "job_id": job_id,
            "attempt": attempt,
            "member_path": member.path,
            "member_index": member.index,
            "size_bytes": member.size,
            "sha256_manifest": member.sha256_manifest,
            "sha256_actual": member.sha256_actual,
            "status": "ingested" if derived_id is not None else member.status,
            "parser": parser,
            "derived_evidence_id": derived_id,
            "parse_job_id": parse_job_id,
            "detail": extra,
        }

    def _existing_derived(
        self, session: Session, bundle: Evidence, member: MemberResult, parser: str
    ) -> Evidence | None:
        row = session.execute(
            select(Evidence)
            .join(BundleMember, BundleMember.derived_evidence_id == Evidence.id)
            .where(
                BundleMember.bundle_evidence_id == bundle.id,
                BundleMember.member_path == member.path,
                BundleMember.sha256_actual == member.sha256_actual,
                BundleMember.parser == parser,
                Evidence.status == "stored",
                Evidence.parent_evidence_id == bundle.id,
            )
            .order_by(BundleMember.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        session.commit()
        return row

    def _derive_one(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        bundle: Evidence,
        state: _RunState,
        member: MemberResult,
        parser: str,
    ) -> None:
        tm = state.manifest
        if tm is None or member.file is None or member.sha256_actual is None:
            raise ParserInputError("member is not verified")
        existing = self._existing_derived(session, bundle, member, parser)
        upload: tuple[uuid.UUID, str, Any, Any, RetentionInfo] | None = None
        if existing is None:
            upload = self._upload(bundle, member)
        try:
            self.lock_running(session, job_id, claim.token)
            self._require_case_open(session, claim.case_id)
            if existing is None and upload is not None:
                derived = self._record_derived(
                    session, job_id, claim, bundle, state, member, parser, upload
                )
                reused = False
            elif existing is not None:
                derived, reused = existing, True
            else:  # pragma: no cover - one of the two is always set
                raise ParserInputError("nothing to derive")
            jobs = JobService(session, self.settings, dispatcher=self.parse_dispatcher)
            submitted = jobs.create_system_parse_job(
                derived, parser, self._parse_params(parser, tm), claim.created_by
            )
            session.execute(
                insert(BundleMember).values(
                    self._row(
                        bundle,
                        job_id,
                        claim.token,
                        member,
                        parser,
                        derived_id=derived.id,
                        parse_job_id=submitted.job.id,
                        detail={"reused": reused, "label": derived.label},
                    )
                )
            )
            session.commit()
        except (JobCancelledError, JobFencedError, ParserInputError):
            session.rollback()
            raise
        except OperationalError as exc:
            session.rollback()
            raise TransientJobError(f"database unavailable: {type(exc).__name__}") from exc
        state.derived.append(
            {
                "evidence_id": str(derived.id),
                "label": derived.label,
                "member": member.path,
                "parser": parser,
                "parse_job_id": str(submitted.job.id),
                "reused": reused,
            }
        )
        self._dispatch_parse(session, submitted, state)

    def _dispatch_parse(self, session: Session, submitted: Submitted, state: _RunState) -> None:
        if not submitted.created or self.parse_dispatcher is None:
            return
        try:
            JobService(session, self.settings, dispatcher=self.parse_dispatcher).dispatch(
                submitted.job
            )
        except AppError:  # queue down: the parse job is marked failed and can be retried
            state.dispatch_failed.append(str(submitted.job.id))

    def _upload(
        self, bundle: Evidence, member: MemberResult
    ) -> tuple[uuid.UUID, str, Any, Any, RetentionInfo]:
        """Copy the verified scratch file into the WORM vault (no DB transaction open)."""
        if self.vault is None:
            raise TransientJobError("vault unavailable")
        if member.file is None:
            raise ParserInputError("member is not verified")
        derived_id = uuid.uuid4()
        name = safe_filename(member.path.rsplit("/", 1)[-1])
        key = f"{bundle.case_id}/{bundle.id}/derived/{derived_id}/{name}"
        try:
            with member.file.open("rb") as fh:
                reader = HashingReader(fh, self.settings.max_upload_bytes)
                put = self.vault.put_stream(
                    key, reader, self.settings.upload_part_size_mb * MIB, "application/octet-stream"
                )
            retention = self.vault.retention(key, put.version_id)
        except OSError as exc:
            raise TransientJobError(f"scratch/vault I/O error: {type(exc).__name__}") from exc
        except Exception as exc:
            raise TransientJobError(f"vault write failed: {type(exc).__name__}") from exc
        digests = reader.hasher.digests()
        if digests.sha256 != member.sha256_actual or digests.size != member.size:
            raise ParserInputError("scratch copy changed while it was uploaded")
        if retention is None or retention.mode is None:
            raise ParserInputError("the vault did not apply Object Lock retention (not WORM)")
        return derived_id, key, put, digests, retention

    def _record_derived(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        bundle: Evidence,
        state: _RunState,
        member: MemberResult,
        parser: str,
        upload: tuple[uuid.UUID, str, Any, Any, RetentionInfo],
    ) -> Evidence:
        """Evidence row + signed custody chain for one derived item (caller's transaction)."""
        tm = state.manifest
        if tm is None or self.vault is None:
            raise ParserInputError("bundle manifest missing")
        derived_id, key, put, digests, retention = upload
        now = self.clock()
        entry = member.entry
        acquired = _sane_time(entry.collected_at if entry else None, now) or _sane_time(
            tm.started_at, now
        )
        host = bundle.source_host or (tm.host.hostname or None)
        tool = clean_text(f"{tm.collector.name} {tm.collector.version}", 255)
        parser_kind = DERIVED_KIND.get(parser, "file")
        base_label = f"{bundle.label[:48]}.{(member.index or 0) + 1:04d}"
        ev = Evidence(
            id=derived_id,
            case_id=bundle.case_id,
            label=base_label,
            kind=parser_kind,
            original_name=member.path[:1024],
            size_bytes=digests.size,
            sha256=digests.sha256,
            md5=digests.md5,
            storage_uri=storage_uri(self.vault.bucket, key),
            mime_type="application/octet-stream",
            source_host=clean_text(host, 255) if host else None,
            acquired_at=acquired,
            acquired_by=clean_text(tm.operator, 255) if tm.operator else None,
            acquisition_tool=tool,
            acquisition_notes=clean_text(
                f"Derived from triage bundle {bundle.label} member {member.path}", 2000
            ),
            expected_sha256=member.sha256_manifest,
            status="stored",
            uploaded_by=claim.created_by,
            storage_version_id=put.version_id,
            retain_until=retention.retain_until,
            parent_evidence_id=bundle.id,
        )
        try:
            with session.begin_nested():
                session.add(ev)
                session.flush()
        except IntegrityError:  # label taken (e.g. an analyst's own label): make it unique
            ev.label = f"{base_label}-{derived_id.hex[:6]}"
            with session.begin_nested():
                session.add(ev)
                session.flush()
        custody = CustodyService(session, self.signer, self.clock, self.trusted_keys)
        common = {"source": "bundle_ingest", "job_id": str(job_id)}
        custody.append(
            ev.id,
            "created",
            self.actor,
            {
                **common,
                "case_id": str(ev.case_id),
                "label": ev.label,
                "kind": ev.kind,
                "original_name": ev.original_name,
                "source_host": ev.source_host,
                "acquired_at": _iso(acquired) if acquired else None,
                "acquired_by": ev.acquired_by,
                "acquisition_tool": tool,
                "expected_sha256": member.sha256_manifest,
                "storage_uri": ev.storage_uri,
                "derived_from": {
                    "evidence_id": str(bundle.id),
                    "label": bundle.label,
                    "sha256": bundle.sha256,
                    "version_id": bundle.storage_version_id,
                    "member_path": member.path,
                    "member_index": member.index,
                    "manifest_sha256": state.manifest_sha,
                    "attempt": claim.token,
                },
            },
        )
        custody.append(
            ev.id,
            "ingested",
            self.actor,
            {
                **common,
                "sha256": digests.sha256,
                "md5": digests.md5,
                "size_bytes": digests.size,
                "storage_uri": ev.storage_uri,
                "version_id": put.version_id,
                "etag": put.etag,
            },
        )
        custody.append(
            ev.id,
            "hash_verified",
            self.actor,
            {
                **common,
                "sha256": digests.sha256,
                "version_id": put.version_id,
                "compared": ["manifest_sha256", "extracted_sha256", "uploaded_sha256"],
            },
        )
        custody.append(
            ev.id,
            "locked",
            self.actor,
            {
                "mode": retention.mode,
                "retain_until": _iso(retention.retain_until) if retention.retain_until else None,
                "version_id": put.version_id,
            },
        )
        return ev

    # ------------------------------------------------------------------ finish

    def _finish_bundle(
        self,
        session: Session,
        job_id: uuid.UUID,
        claim: _Claim,
        bundle: Evidence | None,
        manifest: dict[str, Any],
        state: _RunState,
        outcome: str,
        error: str | None,
        read_evidence: bool,
    ) -> RunResult:
        finished = self.clock()
        result = state.result
        counts: dict[str, int] = dict(result.counts()) if result else {}
        ingested = len(state.derived)
        if ingested:
            counts["verified"] = counts.get("verified", 0) - ingested
            counts["ingested"] = ingested
        counts = {k: v for k, v in sorted(counts.items()) if v}
        flagged = result.flagged if result else []
        counts_all = {
            **counts,
            "members": len(result.members) if result else 0,
            "flagged": len(flagged),
            "derived_new": sum(1 for d in state.derived if not d["reused"]),
            "bytes_extracted": result.bytes_extracted if result else 0,
        }
        manifest.update(
            finished_at=_iso(finished),
            duration_ms=int(
                (finished - self._parse_iso(manifest["started_at"])).total_seconds() * 1000
            ),
            outcome=outcome,
            error=error,
            counts=counts_all,
            flagged=[
                {
                    "path": m.path,
                    "status": m.status,
                    "sha256_manifest": m.sha256_manifest,
                    "sha256_actual": m.sha256_actual,
                }
                for m in flagged[:MAX_FLAGGED_IN_MANIFEST]
            ],
            derived=state.derived[:MAX_FLAGGED_IN_MANIFEST],
            derived_capped=state.derived_capped,
            dispatch_failed=state.dispatch_failed,
            rejected=state.rejected,
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
                return RunResult(job_id, "fenced", counts=counts_all)
            if row.status is JobStatus.cancelled:
                outcome = manifest["outcome"] = "cancelled"
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
            if state.rows:
                session.execute(insert(BundleMember), state.rows)
            if read_evidence and bundle is not None:
                self._processed_entry(session, bundle, job_id, claim, manifest, state, digest)
            notice = self._notice(bundle, job_id, state, flagged)
            if notice is not None:
                notify_admins(session, notice[0], notice[1])
            session.commit()
        except DBAPIError:
            session.rollback()
            log.exception("bundle_finish_failed", job_id=str(job_id))
            raise
        log.info("bundle_job_finished", job_id=str(job_id), outcome=outcome, **counts_all)
        return RunResult(job_id, outcome, counts=counts_all, error=error)

    def _processed_entry(
        self,
        session: Session,
        bundle: Evidence,
        job_id: uuid.UUID,
        claim: _Claim,
        manifest: dict[str, Any],
        state: _RunState,
        digest: str,
    ) -> None:
        """Signed ``processed`` entry on the bundle (JSON-safe: ints/strings/bools only)."""
        tm = state.manifest
        flagged = state.result.flagged if state.result else []
        counts = {k: v for k, v in manifest["counts"].items() if isinstance(v, int)}
        CustodyService(session, self.signer, self.clock, self.trusted_keys).append(
            bundle.id,
            "processed",
            self.actor,
            {
                "job_id": str(job_id),
                "kind": BUNDLE,
                "ingester": INGESTER,
                "ingester_version": INGESTER_VERSION,
                "outcome": manifest["outcome"],
                "attempt": claim.token,
                "sha256": manifest.get("evidence_sha256"),
                "version_id": manifest.get("evidence_version_id"),
                "requested_by": str(claim.created_by) if claim.created_by else None,
                "manifest_sha256": digest,
                "bundle_manifest_sha256": state.manifest_sha,
                "collector": f"{tm.collector.name} {tm.collector.version}" if tm else None,
                "collector_trust": state.trust.get("status"),
                "counts": counts,
                "flagged": [
                    {"path": m.path, "status": m.status} for m in flagged[:MAX_CUSTODY_LIST]
                ],
                "derived_evidence_ids": [d["evidence_id"] for d in state.derived[:200]],
                "rejected": sorted({str(r.get("code")) for r in state.rejected}),
            },
        )

    @staticmethod
    def _notice(
        bundle: Evidence | None,
        job_id: uuid.UUID,
        state: _RunState,
        flagged: list[MemberResult],
    ) -> tuple[str, dict[str, Any]] | None:
        if bundle is None:
            return None
        base = {"evidence_id": str(bundle.id), "label": bundle.label, "job_id": str(job_id)}
        if state.rejected:
            codes = sorted({str(r.get("code")) for r in state.rejected})
            return "evidence.bundle_rejected", {**base, "reasons": codes}
        if flagged:
            return "evidence.bundle_manifest_mismatch", {
                **base,
                "members": [m.path for m in flagged[:MAX_CUSTODY_LIST]],
                "count": len(flagged),
            }
        return None


# ---------------------------------------------------------------------- read API


@dataclass(frozen=True)
class BundleSummary:
    evidence: Evidence
    job: Job | None
    members: list[BundleMember]
    derived: list[Evidence]


class BundleQueryService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def summary(self, principal: Principal, evidence_id: uuid.UUID, limit: int) -> BundleSummary:
        ev = self.session.get(Evidence, evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        access = load_case_access(
            self.session, principal, ev.case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.CASE_READ)
        job = self.session.execute(
            select(Job)
            .where(Job.evidence_id == ev.id, Job.kind == BUNDLE)
            .order_by(Job.queued_at.desc(), Job.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        members: list[BundleMember] = []
        if job is not None:
            members = list(
                self.session.execute(
                    select(BundleMember)
                    .where(BundleMember.job_id == job.id, BundleMember.attempt == job.attempts)
                    .order_by(
                        BundleMember.member_index.asc().nulls_last(), BundleMember.member_path
                    )
                    .limit(limit)
                ).scalars()
            )
        derived = list(
            self.session.execute(
                select(Evidence)
                .where(Evidence.parent_evidence_id == ev.id)
                .order_by(Evidence.created_at, Evidence.label)
            ).scalars()
        )
        return BundleSummary(ev, job, members, derived)
