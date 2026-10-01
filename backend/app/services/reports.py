"""Reports (guide 18): snapshot, edit, QA, four-eyes approval, sign, verify, versions, exports.

Lifecycle ``draft -> in_review -> approved -> signed`` (``in_review|approved -> draft`` to rework).

* Every write takes ``FOR SHARE`` on the case row (closing takes ``FOR UPDATE``) and re-checks the
  case is open; closed cases are read-only. Report writes then lock the report row
  (``FOR UPDATE``) and re-check its state after the lock (a concurrent transition may have won).
* Edits happen only in ``draft`` and carry ``expected_revision`` (optimistic concurrency, 409).
* Submit re-runs the deterministic QA gate under the lock. Approve needs ``approve`` and a
  different person than the submitter. Sign needs ``approve``: it renders every artifact from the
  stored snapshot, stores them in the artifacts bucket and seals the manifest with the custody
  key. A DB trigger enforces the same transitions and freezes signed rows.
* Verification trusts only the running signer and ``CUSTODY_TRUSTED_KEYS_PATH`` (never keys from
  the database), re-hashes the stored artifacts and re-renders them from the snapshot.
* Generating reports never touches evidence bytes; the evidence export package reads metadata and
  custody only and appends one ``exported`` custody entry with the package hash.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer

from app import __version__
from app.config import Settings
from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from app.core.permissions import Permission, Principal
from app.core.signing import CustodySigner, SigningKeyError, public_key_pem, trusted_key_set
from app.db.models import (
    AiInteraction,
    Alert,
    Case,
    CaseStatus,
    Event,
    Evidence,
    Job,
    Report,
    User,
)
from app.integrations.messages import EVENT_REPORT_SIGNED
from app.reports.artifacts import (
    ARTIFACT_TYPES,
    FORMAT_TO_NAME,
    KIND_ARTIFACTS,
    render_all,
    render_one,
)
from app.reports.exports import pretty_json
from app.reports.model import CONFIDENCE, SECTIONS, content_sha256, default_sections, section_def
from app.reports.package import build_evidence_package
from app.reports.qa import QaResult, run_qa
from app.reports.render_pdf import RenderLimitError
from app.reports.seal import (
    build_manifest,
    json_sha256,
    manifest_sha256,
    sha256_hex,
    verify_manifest_signature,
)
from app.reports.snapshot import SnapshotBuilder, SnapshotLimits, event_summary, iso, user_label
from app.repositories.artifacts import ArtifactMissingError, ArtifactStore, artifact_prefix
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access
from app.services.custody import Actor, ChainEntry, CustodyService, verify_chain
from app.services.outbox import emit_event

KINDS = tuple(SECTIONS)
STATUS_LABELS = {
    "draft": "DRAFT - not approved",
    "in_review": "IN REVIEW - not approved",
    "approved": "APPROVED - not signed",
    "signed": "Signed",
}
MAX_TITLE = 300
MAX_SECTION_CHARS = 50_000
MAX_FINDINGS = 200
MAX_FINDING_BODY = 20_000
MAX_REFS = 50
MAX_ATTACK = 20
MAX_LIST = 200
REF_TYPES = ("event", "alert", "evidence")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CUSTODY_PACKAGE_ENTRIES = 100_000


def utcnow() -> datetime:
    return datetime.now(UTC)


def _bad(message: str, **details: Any) -> AppError:
    return AppError("invalid_report", message, 422, details)


def _clean_text(value: str, limit: int, what: str) -> str:
    if "\x00" in value:
        raise _bad(f"{what} contains NUL characters.")
    if len(value) > limit:
        raise _bad(f"{what} is longer than {limit} characters.")
    return value


@dataclass(frozen=True)
class Download:
    filename: str
    content_type: str
    data: bytes
    sha256: str


@dataclass(frozen=True)
class PackageResult:
    filename: str
    data: bytes
    sha256: str
    custody_seq: int


class ReportService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        signer: CustodySigner | None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
        artifacts: ArtifactStore | None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.session = session
        self.settings = settings
        self.signer = signer
        self.artifacts = artifacts
        self.clock = clock
        self.custody = CustodyService(session, signer, clock, trusted_keys)
        self.extra_trusted = dict(trusted_keys or {})
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _load(self, principal: Principal, rid: uuid.UUID) -> tuple[Report, CaseAccess]:
        report = self.session.get(Report, rid)
        if report is None:
            raise NotFoundError("Report not found.")
        try:
            access = self._access(principal, report.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Report not found.") from exc
        return report, access

    def _lock_open_case(self, case_id: uuid.UUID) -> None:
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed; its reports are read-only.")

    def _lock_report(self, rid: uuid.UUID) -> Report:
        return self.session.execute(
            select(Report)
            .where(Report.id == rid)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()

    def _require_status(self, report: Report, *allowed: str) -> None:
        if report.status not in allowed:
            self.session.rollback()
            raise InvalidStateError(
                f"The report is '{report.status}'; this needs {' or '.join(allowed)}.",
                status=report.status,
            )

    def _require_revision(self, report: Report, expected: int) -> None:
        if report.revision != expected:
            self.session.rollback()
            raise ConflictError(
                "The report was changed by someone else; reload and try again.",
                "stale_revision",
                revision=report.revision,
            )

    @staticmethod
    def _too_large(exc: RenderLimitError) -> AppError:
        return AppError(
            "report_too_large",
            f"The report is too large to render ({exc}); shorten it or split it.",
            413,
        )

    def _label(self, user_id: uuid.UUID | None) -> str | None:
        return user_label(self.session.get(User, user_id)) if user_id else None

    def _limits(self) -> SnapshotLimits:
        s = self.settings
        return SnapshotLimits(
            key_events=s.report_max_key_events,
            alerts=s.report_max_alerts,
            iocs=s.report_max_iocs,
            max_bytes=s.report_max_context_mb * 1024 * 1024,
        )

    def _snapshot(self, case: Case, principal: Principal) -> dict[str, Any]:
        builder = SnapshotBuilder(
            self.session,
            self.custody,
            self._limits(),
            org=self.settings.report_org_name,
            clock=self.clock,
        )
        return builder.build(case, principal.label)

    def render_meta(self, report: Report, **overrides: Any) -> dict[str, Any]:
        """The cover/status data a rendering shows (frozen into the manifest at signing)."""
        meta: dict[str, Any] = {
            "report_id": str(report.id),
            "family_id": str(report.family_id),
            "version": report.version,
            "kind": report.kind,
            "title": report.title,
            "status": report.status,
            "status_label": STATUS_LABELS[report.status],
            "author": self._label(report.created_by) or "unknown",
            "approved_by": self._label(report.approved_by),
            "approved_at": iso(report.approved_at),
            "signed_by": None,
            "signed_at": None,
            "key_id": None,
            "context_sha256": report.context_sha256,
            "content_sha256": content_sha256(report.title, report.sections, report.findings),
        }
        meta.update(overrides)
        return meta

    def _audit(
        self,
        action: str,
        principal: Principal,
        meta: RequestMeta | None,
        report: Report,
        **detail: Any,
    ) -> None:
        self.audit.record(
            action,
            user_id=principal.user_id,
            meta=meta,
            object_type="report",
            object_id=report.id,
            detail={"case_id": str(report.case_id), "version": report.version, **detail},
        )

    # ------------------------------------------------------------------ read

    def list_reports(self, principal: Principal, case_id: uuid.UUID) -> list[Report]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        rows = list(
            self.session.execute(
                select(Report)
                .options(defer(Report.context))
                .where(Report.case_id == case_id)
                .order_by(Report.created_at.desc(), Report.version.desc())
                .limit(MAX_LIST)
            ).scalars()
        )
        self.session.commit()
        return rows

    def get(self, principal: Principal, rid: uuid.UUID) -> tuple[Report, CaseAccess]:
        report, access = self._load(principal, rid)
        access.require(Permission.CASE_READ)
        return report, access

    # ------------------------------------------------------------------ create / versions

    def create(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        kind: str,
        title: str | None = None,
    ) -> Report:
        access = self._access(principal, case_id)
        access.require(Permission.INVESTIGATE)
        if kind not in KINDS:
            raise _bad("Unknown report kind.", allowed=list(KINDS))
        self._lock_open_case(case_id)
        case = access.case
        context = self._snapshot(case, principal)
        rid = uuid.uuid4()
        report = Report(
            id=rid,
            case_id=case_id,
            kind=kind,
            version=1,
            family_id=rid,
            title=_clean_text(title or f"{case.case_number} {kind} report", MAX_TITLE, "Title"),
            status="draft",
            context=context,
            context_sha256=json_sha256(context),
            sections=default_sections(kind),
            findings=[],
            revision=0,
            created_by=principal.user_id,
            updated_by=principal.user_id,
        )
        self.session.add(report)
        self.session.flush()
        self._audit(
            "report.create",
            principal,
            meta,
            report,
            kind=kind,
            context_sha256=report.context_sha256,
            input_hashes=context.get("input_hashes", {}),
        )
        self.session.commit()
        return report

    def new_version(self, principal: Principal, rid: uuid.UUID, meta: RequestMeta) -> Report:
        source, access = self._load(principal, rid)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(source.case_id)
        latest = self.session.execute(
            select(func.max(Report.version)).where(Report.family_id == source.family_id)
        ).scalar_one()
        context = self._snapshot(access.case, principal)
        sections = default_sections(source.kind)
        sections.update(source.sections or {})
        report = Report(
            id=uuid.uuid4(),
            case_id=source.case_id,
            kind=source.kind,
            version=int(latest or source.version) + 1,
            family_id=source.family_id,
            supersedes_id=source.id,
            title=source.title,
            status="draft",
            context=context,
            context_sha256=json_sha256(context),
            sections=sections,
            findings=list(source.findings or []),
            revision=0,
            created_by=principal.user_id,
            updated_by=principal.user_id,
        )
        self.session.add(report)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "Another new version was created at the same time; reload.", "version_conflict"
            ) from exc
        self._audit(
            "report.version",
            principal,
            meta,
            report,
            supersedes=str(source.id),
            context_sha256=report.context_sha256,
            input_hashes=context.get("input_hashes", {}),
        )
        self.session.commit()
        return report

    # ------------------------------------------------------------------ edit

    def _resolve_ref(self, case_id: uuid.UUID, ref_type: str, ref_id: str) -> dict[str, Any]:
        try:
            oid = uuid.UUID(str(ref_id))
        except ValueError as exc:
            raise _bad("A reference id must be a UUID.", type=ref_type) from exc
        if ref_type == "event":
            ev = self.session.execute(
                select(Event).where(Event.case_id == case_id, Event.id == oid).limit(1)
            ).scalar_one_or_none()
            if ev is not None:
                label = f"{ev.source_type} {ev.event_code or ''} on {ev.host or '?'}"
                return {
                    "type": "event",
                    "id": str(oid),
                    "label": " ".join(label.split())[:200],
                    "ts": iso(ev.ts),
                    "summary": event_summary(ev),
                }
        elif ref_type == "alert":
            al = self.session.execute(
                select(Alert).where(Alert.case_id == case_id, Alert.id == oid)
            ).scalar_one_or_none()
            if al is not None:
                return {
                    "type": "alert",
                    "id": str(oid),
                    "label": (al.rule_id or "alert")[:200],
                    "ts": iso(al.first_seen),
                    "summary": al.title[:500],
                }
        elif ref_type == "evidence":
            evd = self.session.execute(
                select(Evidence).where(Evidence.case_id == case_id, Evidence.id == oid)
            ).scalar_one_or_none()
            if evd is not None:
                return {
                    "type": "evidence",
                    "id": str(oid),
                    "label": evd.label,
                    "ts": iso(evd.acquired_at or evd.created_at),
                    "summary": f"{evd.original_name[:300]} (SHA-256 {evd.sha256 or 'missing'})",
                }
        else:
            raise _bad("Unknown reference type.", allowed=list(REF_TYPES))
        raise NotFoundError("A cited record does not exist in this case.", type=ref_type)

    def _clean_findings(
        self, case_id: uuid.UUID, findings: Sequence[Mapping[str, Any]], old: Sequence[Any]
    ) -> list[dict[str, Any]]:
        if len(findings) > MAX_FINDINGS:
            raise _bad(f"At most {MAX_FINDINGS} findings.")
        previous = {str(f.get("id")): f for f in old if isinstance(f, Mapping)}
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for f in findings:
            fid = str(f.get("id") or uuid.uuid4())
            if fid in seen or len(fid) > 64:
                raise _bad("Finding ids must be unique.")
            seen.add(fid)
            title = _clean_text(str(f.get("title") or "").strip(), MAX_TITLE, "A finding title")
            if not title:
                raise _bad("Every finding needs a title.")
            body = _clean_text(str(f.get("body") or ""), MAX_FINDING_BODY, "A finding body")
            confidence = str(f.get("confidence") or "medium")
            if confidence not in CONFIDENCE:
                raise _bad("Confidence is low, medium or high.")
            attack = [str(t).strip().upper() for t in f.get("attack") or []]
            if len(attack) > MAX_ATTACK or not all(TECHNIQUE_RE.match(t) for t in attack):
                raise _bad("ATT&CK ids look like T1059 or T1059.001.")
            refs_in = list(f.get("refs") or [])
            if len(refs_in) > MAX_REFS:
                raise _bad(f"At most {MAX_REFS} references per finding.")
            refs: list[dict[str, Any]] = []
            keys: set[tuple[str, str]] = set()
            for ref in refs_in:
                key = (str(ref.get("type")), str(ref.get("id")))
                if key in keys:
                    continue
                keys.add(key)
                refs.append(self._resolve_ref(case_id, *key))
            prev = previous.get(fid)
            origin = "analyst"
            entry: dict[str, Any] = {
                "id": fid,
                "title": title,
                "body": body,
                "confidence": confidence,
                "attack": sorted(set(attack)),
                "refs": refs,
                "origin": origin,
            }
            if prev is not None and prev.get("ai"):
                entry["ai"] = prev["ai"]
                same = prev.get("title") == title and prev.get("body") == body
                entry["origin"] = prev.get("origin") if same else "ai_edited"
            out.append(entry)
        return out

    def _merge_sections(
        self, kind: str, current: Mapping[str, Any], changes: Mapping[str, str]
    ) -> dict[str, Any]:
        merged = {k: dict(v) for k, v in current.items() if isinstance(v, Mapping)}
        for name, text in changes.items():
            if section_def(kind, name) is None:
                raise _bad("Unknown section for this report kind.", section=name)
            text = _clean_text(str(text), MAX_SECTION_CHARS, f"Section {name}")
            stored = merged.get(name) or {}
            if stored.get("text") == text:
                continue
            if stored.get("origin") in ("ai_approved", "ai_edited"):
                merged[name] = {"text": text, "origin": "ai_edited", "ai": stored.get("ai")}
            else:
                merged[name] = {"text": text, "origin": "analyst"}
        return merged

    def update(
        self,
        principal: Principal,
        rid: uuid.UUID,
        meta: RequestMeta,
        *,
        expected_revision: int,
        title: str | None = None,
        sections: Mapping[str, str] | None = None,
        findings: Sequence[Mapping[str, Any]] | None = None,
    ) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "draft")
        self._require_revision(report, expected_revision)
        changed: list[str] = []
        if title is not None:
            clean = _clean_text(title.strip(), MAX_TITLE, "Title")
            if not clean:
                raise _bad("The title is empty.")
            if clean != report.title:
                report.title = clean
                changed.append("title")
        if sections:
            merged = self._merge_sections(report.kind, report.sections or {}, sections)
            if merged != report.sections:
                report.sections = merged
                changed.append("sections")
        if findings is not None:
            cleaned = self._clean_findings(report.case_id, findings, report.findings or [])
            if cleaned != report.findings:
                report.findings = cleaned
                changed.append("findings")
        if changed:
            report.revision += 1
            report.qa = None
            report.updated_by = principal.user_id
            report.updated_at = self.clock()
            self._audit(
                "report.update",
                principal,
                meta,
                report,
                changed=changed,
                revision=report.revision,
                content_sha256=content_sha256(report.title, report.sections, report.findings),
            )
        self.session.commit()
        return report

    # ------------------------------------------------------------------ QA / workflow

    def _missing_refs(self, report: Report) -> set[tuple[str, str]]:
        wanted: dict[str, set[uuid.UUID]] = {t: set() for t in REF_TYPES}
        for f in report.findings or []:
            for ref in f.get("refs") or []:
                if ref.get("type") in wanted:
                    wanted[ref["type"]].add(uuid.UUID(str(ref["id"])))
        models: dict[str, Any] = {"event": Event, "alert": Alert, "evidence": Evidence}
        missing: set[tuple[str, str]] = set()
        for kind, ids in wanted.items():
            if not ids:
                continue
            model = models[kind]
            found: set[uuid.UUID] = set(
                self.session.execute(
                    select(model.id).where(model.case_id == report.case_id, model.id.in_(ids))
                ).scalars()
            )
            missing |= {(kind, str(i)) for i in ids - found}
        return missing

    def _qa(self, report: Report, principal: Principal) -> QaResult:
        result = run_qa(
            report.kind,
            report.context,
            report.title,
            report.sections or {},
            report.findings or [],
            self._missing_refs(report),
        )
        report.qa = {
            **result.as_dict(),
            "revision": report.revision,
            "checked_at": iso(self.clock()),
            "checked_by": principal.label,
        }
        return result

    def run_qa(self, principal: Principal, rid: uuid.UUID, meta: RequestMeta) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "draft")
        result = self._qa(report, principal)
        self._audit(
            "report.qa",
            principal,
            meta,
            report,
            ok=result.ok,
            errors=len(result.errors),
            warnings=len(result.warnings),
        )
        self.session.commit()
        return report

    def submit(
        self, principal: Principal, rid: uuid.UUID, meta: RequestMeta, *, expected_revision: int
    ) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "draft")
        self._require_revision(report, expected_revision)
        result = self._qa(report, principal)
        if not result.ok:
            self.session.commit()  # keep the failed QA run on the report
            raise ConflictError("The report does not pass QA.", "qa_failed", errors=result.errors)
        now = self.clock()
        report.status = "in_review"
        report.submitted_by = principal.user_id
        report.submitted_at = now
        self._audit(
            "report.submit",
            principal,
            meta,
            report,
            revision=report.revision,
            content_sha256=content_sha256(report.title, report.sections, report.findings),
        )
        self.session.commit()
        return report

    def return_to_draft(
        self, principal: Principal, rid: uuid.UUID, meta: RequestMeta, *, reason: str
    ) -> Report:
        report, access = self._load(principal, rid)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "in_review", "approved")
        withdraw = report.status == "in_review" and report.submitted_by == principal.user_id
        if not withdraw:
            access.require(Permission.APPROVE)
        else:
            access.require(Permission.INVESTIGATE)
        previous = report.status
        report.status = "draft"
        report.submitted_by = None
        report.submitted_at = None
        report.approved_by = None
        report.approved_at = None
        report.qa = None
        self._audit(
            "report.return",
            principal,
            meta,
            report,
            previous=previous,
            reason=_clean_text(reason, 2000, "Reason"),
        )
        self.session.commit()
        return report

    def approve(self, principal: Principal, rid: uuid.UUID, meta: RequestMeta) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.APPROVE)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "in_review")
        if report.submitted_by == principal.user_id:
            self.session.rollback()
            raise ForbiddenError(
                "A report must be approved by someone other than the person who submitted it.",
                rule="four_eyes",
            )
        report.status = "approved"
        report.approved_by = principal.user_id
        report.approved_at = self.clock()
        self._audit("report.approve", principal, meta, report)
        self.session.commit()
        return report

    def sign(self, principal: Principal, rid: uuid.UUID, meta: RequestMeta) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.APPROVE)
        signer = self.signer
        if signer is None:
            raise AppError("custody_signer_unavailable", "The signing key is not configured.", 503)
        store = self.artifacts
        if store is None:
            raise AppError("artifacts_unavailable", "Artifact storage is not available.", 503)
        self._lock_open_case(report.case_id)
        report = self._lock_report(rid)
        self._require_status(report, "approved")
        now = self.clock()
        signed_at = iso(now) or ""
        render_meta = self.render_meta(
            report,
            status="signed",
            status_label=STATUS_LABELS["signed"],
            signed_by=principal.label,
            signed_at=signed_at,
            key_id=signer.key_id,
        )
        try:
            artifacts = render_all(
                report.kind,
                render_meta,
                report.context,
                report.sections,
                report.findings,
                time_budget_s=self.settings.report_render_timeout_s,
            )
        except RenderLimitError as exc:
            raise self._too_large(exc) from exc
        prefix = artifact_prefix(report.case_id, report.family_id, report.version)
        for art in artifacts:  # bounded by the snapshot caps; a few MB at most
            store.put_bytes(prefix + art.name, art.data, art.content_type)
        manifest = build_manifest(
            report_id=str(report.id),
            family_id=str(report.family_id),
            version=report.version,
            case_id=str(report.case_id),
            case_number=str(report.context.get("case", {}).get("case_number") or ""),
            kind=report.kind,
            context_sha256=report.context_sha256,
            content_sha256=render_meta["content_sha256"],
            render_meta=render_meta,
            artifacts=artifacts,
            signed_at=signed_at,
            key_id=signer.key_id,
        )
        digest = manifest_sha256(manifest)
        report.manifest = manifest
        report.sha256 = digest
        report.signature = signer.sign(digest)
        report.key_id = signer.key_id
        report.signed_by = principal.user_id
        report.signed_at = now
        report.storage_uri = f"s3://{store.bucket}/{prefix}"
        report.status = "signed"
        self._audit(
            "report.sign",
            principal,
            meta,
            report,
            manifest_sha256=digest,
            key_id=signer.key_id,
            artifacts={a.name: a.sha256 for a in artifacts},
        )
        emit_event(
            self.session,
            EVENT_REPORT_SIGNED,
            case_id=report.case_id,
            payload={
                "report_id": str(report.id),
                "kind": report.kind,
                "version": report.version,
                "manifest_sha256": digest,
                "actor_id": str(principal.user_id),
            },
            dedup_key=f"{EVENT_REPORT_SIGNED}:{report.id}",
        )
        self.session.commit()
        return report

    # ------------------------------------------------------------------ verify / downloads

    def _trusted(self) -> dict[str, Ed25519PublicKey]:
        try:
            return trusted_key_set(self.signer, self.extra_trusted)
        except SigningKeyError as exc:
            raise AppError("signing_key_conflict", str(exc), 500) from exc

    def verify(self, principal: Principal, rid: uuid.UUID, meta: RequestMeta) -> dict[str, Any]:
        report, _ = self.get(principal, rid)
        if report.status != "signed" or not report.manifest:
            raise InvalidStateError("Only signed reports can be verified.", status=report.status)
        store = self.artifacts
        if store is None:
            raise AppError("artifacts_unavailable", "Artifact storage is not available.", 503)
        manifest = report.manifest
        seal = verify_manifest_signature(
            manifest, report.sha256 or "", report.signature or "", self._trusted()
        )
        problems = list(seal.problems)
        if (
            json_sha256(report.context) != report.context_sha256
            or manifest.get("context_sha256") != report.context_sha256
        ):
            problems.append({"code": "context_mismatch", "message": "The snapshot changed."})
        if manifest.get("content_sha256") != content_sha256(
            report.title, report.sections, report.findings
        ):
            problems.append({"code": "content_mismatch", "message": "The content changed."})
        if manifest.get("report_id") != str(report.id):
            problems.append({"code": "report_mismatch", "message": "Manifest of another report."})
        prefix = artifact_prefix(
            manifest.get("case_id"), manifest.get("family_id"), int(manifest.get("version") or 0)
        )
        results = []
        # One render budget for the whole call (not one per artifact), shared by the re-renders.
        budget = float(self.settings.report_render_timeout_s)
        deadline = monotonic() + budget
        for entry in manifest.get("artifacts") or []:
            name = str(entry.get("name"))
            item: dict[str, Any] = {"name": name, "expected_sha256": entry.get("sha256")}
            if name not in ARTIFACT_TYPES:
                problems.append({"code": "unknown_artifact", "message": name[:100]})
                continue
            try:
                stored = sha256_hex(store.get_bytes(prefix + name))
                item["stored_sha256"] = stored
                item["stored_ok"] = stored == entry.get("sha256")
            except ArtifactMissingError:
                item["stored_ok"] = False
                item["stored_sha256"] = None
            if not item["stored_ok"]:
                problems.append({"code": "artifact_mismatch", "message": f"{name} changed"})
            try:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise RenderLimitError(f"the verification used its {budget:g} s render budget")
                rendered = render_one(
                    name,
                    manifest.get("render_meta") or {},
                    report.context,
                    report.sections,
                    report.findings,
                    time_budget_s=remaining,
                )
            except RenderLimitError as exc:
                item["rerender_ok"] = False
                problems.append({"code": "rerender_limit", "message": f"{name}: {exc}"})
            else:
                item["rerender_ok"] = rendered.sha256 == entry.get("sha256")
                if not item["rerender_ok"]:
                    problems.append(
                        {"code": "rerender_mismatch", "message": f"{name} does not re-render"}
                    )
            results.append(item)
        result = {
            "ok": not problems,
            "report_id": str(report.id),
            "version": report.version,
            "manifest_sha256": report.sha256,
            "key_id": manifest.get("key_id"),
            "signature_ok": seal.ok,
            "artifacts": results,
            "problems": problems,
            "checked_at": iso(self.clock()),
        }
        self._audit(
            "report.verify",
            principal,
            meta,
            report,
            ok=result["ok"],
            problems=[p["code"] for p in problems][:20],
        )
        self.session.commit()
        return result

    def download(
        self, principal: Principal, rid: uuid.UUID, meta: RequestMeta, *, fmt: str
    ) -> Download:
        report, _ = self.get(principal, rid)
        base = f"{report.context.get('case', {}).get('case_number', 'report')}_{report.kind}"
        base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)[:80] + f"_v{report.version}"
        if fmt == "seal":
            if report.status != "signed":
                raise InvalidStateError("Only signed reports have a seal.")
            body = {
                "manifest": report.manifest,
                "manifest_sha256": report.sha256,
                "signature": report.signature,
                "algorithm": "ed25519",
                "message": "Ed25519 over the manifest_sha256 hex string (ASCII)",
                "public_key_pem": public_key_pem(self.signer.public_key)
                if self.signer is not None and self.signer.key_id == report.key_id
                else None,
            }
            data = pretty_json(body)
            out = Download(f"{base}_seal.json", "application/json", data, sha256_hex(data))
        else:
            name = FORMAT_TO_NAME.get(fmt)
            if name is None or name not in KIND_ARTIFACTS[report.kind]:
                raise _bad(
                    "This report kind has no such format.",
                    allowed=[ARTIFACT_TYPES[n][0] for n in KIND_ARTIFACTS[report.kind]],
                )
            content_type = ARTIFACT_TYPES[name][1]
            if report.status == "signed":
                out = self._signed_artifact(report, name, base, content_type)
            else:
                try:
                    art = render_one(
                        name,
                        self.render_meta(report),
                        report.context,
                        report.sections,
                        report.findings,
                        time_budget_s=self.settings.report_render_timeout_s,
                    )
                except RenderLimitError as exc:
                    raise self._too_large(exc) from exc
                out = Download(f"{base}_DRAFT_{name}", content_type, art.data, art.sha256)
        self._audit(
            "report.download",
            principal,
            meta,
            report,
            format=fmt,
            sha256=out.sha256,
            status=report.status,
        )
        self.session.commit()
        return out

    def _signed_artifact(self, report: Report, name: str, base: str, content_type: str) -> Download:
        store = self.artifacts
        if store is None:
            raise AppError("artifacts_unavailable", "Artifact storage is not available.", 503)
        manifest = report.manifest or {}
        entry = next((a for a in manifest.get("artifacts") or [] if a.get("name") == name), None)
        if entry is None:
            raise NotFoundError("The signed report has no such artifact.")
        prefix = artifact_prefix(report.case_id, report.family_id, report.version)
        try:
            data = store.get_bytes(prefix + name)
        except ArtifactMissingError as exc:
            raise AppError("artifact_missing", "The signed artifact is missing.", 409) from exc
        digest = sha256_hex(data)
        if digest != entry.get("sha256"):
            raise AppError(
                "artifact_tampered",
                "The stored artifact does not match the signed manifest; run verification.",
                409,
                {"name": name},
            )
        return Download(f"{base}_{name}", content_type, data, digest)

    # ------------------------------------------------------------------ AI drafts (A4)

    def apply_ai(
        self,
        principal: Principal,
        rid: uuid.UUID,
        section: str,
        meta: RequestMeta,
        *,
        interaction_id: uuid.UUID,
        expected_revision: int,
    ) -> Report:
        report, access = self._load(principal, rid)
        access.require(Permission.INVESTIGATE)
        sd = section_def(report.kind, section)
        if sd is None or not sd.ai_draft:
            raise _bad("This section cannot take an AI draft.", section=section)
        self._lock_open_case(report.case_id)
        interaction = self.session.execute(
            select(AiInteraction)
            .where(AiInteraction.id == interaction_id)
            .with_for_update(read=True)
        ).scalar_one_or_none()
        refs = (interaction.input_refs or {}) if interaction is not None else {}
        if (
            interaction is None
            or interaction.case_id != report.case_id
            or interaction.feature != "report_draft"
            or refs.get("report_id") != str(report.id)
            or refs.get("section") != section
        ):
            self.session.rollback()
            raise NotFoundError("No AI draft for this report section with that id.")
        if interaction.status != "valid" or interaction.accepted is not True:
            self.session.rollback()
            raise InvalidStateError(
                "Only an AI draft that a person has accepted can be applied.",
                accepted=interaction.accepted,
                status=interaction.status,
            )
        report = self._lock_report(rid)
        self._require_status(report, "draft")
        self._require_revision(report, expected_revision)
        text = _clean_text(
            str(interaction.output.get("text") or ""), MAX_SECTION_CHARS, "The AI draft"
        )
        ai = {
            "interaction_id": str(interaction.id),
            "reviewed_by_label": self._label(interaction.reviewed_by),
            "reviewed_at": iso(interaction.reviewed_at),
            "requested_by_label": self._label(interaction.user_id),
            "model": interaction.model_served or interaction.model,
            "provider": interaction.provider,
            "prompt_version": interaction.prompt_version,
            "output_sha256": interaction.output_sha256,
            "cites": [
                {k: c.get(k) for k in ("short_id", "kind", "id", "ts")}
                for c in (interaction.citations or [])[:100]
            ],
            "limitations": str(interaction.output.get("limitations") or "")[:600],
        }
        sections = {k: dict(v) for k, v in (report.sections or {}).items()}
        sections[section] = {"text": text, "origin": "ai_approved", "ai": ai}
        report.sections = sections
        report.revision += 1
        report.qa = None
        report.updated_by = principal.user_id
        report.updated_at = self.clock()
        self._audit(
            "report.apply_ai",
            principal,
            meta,
            report,
            section=section,
            interaction_id=str(interaction.id),
            output_sha256=interaction.output_sha256,
        )
        self.session.commit()
        return report

    # ------------------------------------------------------------------ evidence package (8.4)

    def export_package(
        self, principal: Principal, evidence_id: uuid.UUID, meta: RequestMeta
    ) -> PackageResult:
        ev = self.session.get(Evidence, evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        try:
            access = self._access(principal, ev.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Evidence not found.") from exc
        access.require(Permission.CUSTODY_VIEW)
        signer = self.signer
        if signer is None:
            raise AppError("custody_signer_unavailable", "The signing key is not configured.", 503)
        ev = self.session.execute(
            select(Evidence)
            .where(Evidence.id == evidence_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()
        rows = self.custody.entries(evidence_id)[:CUSTODY_PACKAGE_ENTRIES]
        chain = verify_chain(
            [ChainEntry.from_row(r) for r in rows],
            self.custody.trusted_keys(),
            published_keys=self.custody.public_keys(),
            evidence_id=str(evidence_id),
        )
        runs = self.session.execute(
            select(Job)
            .where(Job.evidence_id == evidence_id, Job.run_manifest.is_not(None))
            .order_by(Job.queued_at, Job.id)
            .limit(200)
        ).scalars()
        parent = (
            self.session.get(Evidence, ev.parent_evidence_id) if ev.parent_evidence_id else None
        )
        now = self.clock()
        manifest = {
            "evidence": {
                "id": str(ev.id),
                "label": ev.label,
                "kind": ev.kind,
                "original_name": ev.original_name,
                "size_bytes": ev.size_bytes,
                "sha256": ev.sha256,
                "md5": ev.md5,
                "expected_sha256": ev.expected_sha256,
                "status": ev.status,
                "mime_type": ev.mime_type,
                "source_host": ev.source_host,
                "acquired_at": iso(ev.acquired_at),
                "acquired_by": ev.acquired_by,
                "acquisition_tool": ev.acquisition_tool,
                "acquisition_notes": ev.acquisition_notes,
                "received_at": iso(ev.created_at),
                "storage_version_id": ev.storage_version_id,
                "parent": {"id": str(parent.id), "label": parent.label} if parent else None,
            },
            "case": {
                "id": str(access.case.id),
                "case_number": access.case.case_number,
                "title": access.case.title,
            },
            "processing_runs": [
                {
                    "job_id": str(j.id),
                    "kind": j.kind,
                    "parser": j.parser,
                    "status": j.status.value,
                    "run_manifest": j.run_manifest,
                }
                for j in runs
            ],
            "custody": {
                "entries": len(rows),
                "head_seq": chain.head_seq,
                "head_hash": chain.head_hash,
                "verified": chain.ok,
            },
            "original_included": False,
            "exported_by": principal.label,
            "exported_at": iso(now),
            "exporter": {"software": "dfirbench", "version": __version__},
        }
        custody = {
            "evidence_id": str(ev.id),
            "entries": [
                {
                    "evidence_id": str(r.evidence_id),
                    "seq": r.seq,
                    "ts": r.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "actor_id": str(r.actor_id) if r.actor_id else None,
                    "actor_label": r.actor_label,
                    "action": r.action,
                    "detail": r.detail or {},
                    "prev_hash": r.prev_hash,
                    "entry_hash": r.entry_hash,
                    "signature": r.signature,
                    "key_id": r.key_id,
                }
                for r in rows
            ],
            "verification": chain.as_dict(),
        }
        data = build_evidence_package(manifest, custody, signer)
        digest = sha256_hex(data)
        entry = self.custody.append(
            ev.id,
            "exported",
            Actor.of(principal),
            {
                "format": "evidence_package_zip",
                "package_sha256": digest,
                "custody_head_seq": chain.head_seq,
                "original_included": False,
                "source_ip": meta.ip,
            },
        )
        self.audit.record(
            "evidence.export_package",
            user_id=principal.user_id,
            meta=meta,
            object_type="evidence",
            object_id=ev.id,
            detail={"package_sha256": digest, "custody_seq": entry.seq},
        )
        self.session.commit()
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", ev.label)[:64]
        return PackageResult(f"{safe}_package.zip", data, digest, entry.seq)
