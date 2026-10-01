"""Evidence lifecycle (guide 8.1): create record, streaming upload, finalize, verify, download.

Status: ``uploading`` (record created) -> ``uploaded`` (bytes in the vault, ``ingested`` custody
entry) -> ``stored`` (re-hashed from the vault, compared, locked) or ``failed`` (hash mismatch).
Originals are never modified or deleted; every state change writes a custody entry in the same
transaction. Long reads/writes of evidence bytes happen outside any database transaction.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, ConflictError, InvalidStateError, NotFoundError
from app.core.hashing import Digests, HashingReader, Readable, UploadTooLargeError, hash_chunks
from app.core.permissions import Permission, Principal
from app.core.signing import CustodySigner
from app.db.models import CaseStatus, CustodyLog, Evidence
from app.repositories.vault import (
    MIB,
    RetentionInfo,
    VaultObjectMissingError,
    VaultStore,
    object_key,
    storage_uri,
)
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access
from app.services.custody import Actor, ChainReport, CustodyService
from app.services.notifications import notify_admins
from app.services.outbox import emit_verification_failed

log = structlog.stdlib.get_logger("dfirbench.evidence")

EVIDENCE_KINDS = frozenset(
    {"disk_image", "memory", "evtx", "pcap", "triage_bundle", "log", "file", "cloud_export"}
)
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
AUTO_LABEL_RE = re.compile(r"^EV-(\d+)$")
HAS_BYTES = ("uploaded", "stored", "failed")
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


def safe_filename(name: str) -> str:
    """Storage-safe basename; the client's original name is kept separately (never a path)."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = unicodedata.normalize("NFKC", base)
    base = "".join(ch for ch in base if ch.isprintable())
    base = _UNSAFE_CHARS.sub("_", base).strip(" .")
    base = re.sub(r"_+", "_", base)[:200]
    return base or "evidence.bin"


def utcnow() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


@dataclass(frozen=True)
class FinalizeResult:
    ok: bool
    evidence: Evidence
    digests: Digests
    mismatches: list[dict[str, Any]]
    retention: RetentionInfo | None


@dataclass
class ObjectCheck:
    ok: bool = True
    expected: dict[str, Any] = field(default_factory=dict)
    actual: dict[str, Any] | None = None
    version_expected: str | None = None
    version_latest: str | None = None
    latest_sha256: str | None = None
    problems: list[dict[str, Any]] = field(default_factory=list)

    def fail(self, code: str, message: str, **extra: Any) -> None:
        self.ok = False
        self.problems.append({"code": code, "message": message, **extra})

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "expected": self.expected,
            "actual": self.actual,
            "version_expected": self.version_expected,
            "version_latest": self.version_latest,
            "latest_sha256": self.latest_sha256,
            "problems": self.problems,
        }


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    evidence: Evidence
    object_check: ObjectCheck
    chain: ChainReport
    custody_entry: CustodyLog
    verified_at: datetime


@dataclass(frozen=True)
class DownloadHandle:
    filename: str
    size: int | None
    sha256: str | None
    mime_type: str
    chunks: Iterator[bytes]


class EvidenceService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        vault: VaultStore | None,
        signer: CustodySigner | None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.session = session
        self.settings = settings
        self.vault = vault
        self.clock = clock
        self.custody = CustodyService(session, signer, clock, trusted_keys)
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers

    def _vault(self) -> VaultStore:
        if self.vault is None:
            raise AppError("vault_unavailable", "The evidence vault is not available.", 503)
        return self.vault

    def _access(self, principal: Principal, case_id: uuid.UUID, lock: bool = False) -> CaseAccess:
        return load_case_access(
            self.session,
            principal,
            case_id,
            auditor_all_cases=self.settings.auditor_all_cases,
            lock=lock,
        )

    def _load(
        self, principal: Principal, evidence_id: uuid.UUID, permission: Permission
    ) -> tuple[Evidence, CaseAccess]:
        ev = self.session.get(Evidence, evidence_id)
        if ev is None:
            raise NotFoundError("Evidence not found.")
        access = self._access(principal, ev.case_id)
        access.require(permission)
        return ev, access

    def _lock(self, evidence_id: uuid.UUID) -> Evidence:
        ev = self.session.execute(
            select(Evidence).where(Evidence.id == evidence_id).with_for_update()
        ).scalar_one()
        self.session.refresh(ev)
        return ev

    def _key(self, ev: Evidence) -> str:
        prefix = f"s3://{self._vault().bucket}/"
        if not ev.storage_uri.startswith(prefix):
            raise AppError("storage_mismatch", "Evidence is stored in another vault.", 500)
        return ev.storage_uri[len(prefix) :]

    def _next_label(self, case_id: uuid.UUID) -> str:
        labels = self.session.execute(
            select(Evidence.label).where(Evidence.case_id == case_id)
        ).scalars()
        highest = 0
        for label in labels:
            match = AUTO_LABEL_RE.fullmatch(label)
            if match:
                highest = max(highest, int(match.group(1)))
        return f"EV-{highest + 1:03d}"

    def _hash_stored(self, key: str, version_id: str | None) -> Digests:
        return hash_chunks(self._vault().iter_object(key, version_id))

    # ------------------------------------------------------------------ create / read

    def create(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        meta: RequestMeta,
        kind: str,
        original_name: str,
        label: str | None = None,
        size_bytes: int | None = None,
        mime_type: str | None = None,
        source_host: str | None = None,
        acquired_at: datetime | None = None,
        acquired_by: str | None = None,
        acquisition_tool: str | None = None,
        acquisition_notes: str | None = None,
        expected_sha256: str | None = None,
        expected_md5: str | None = None,
    ) -> Evidence:
        access = self._access(principal, case_id, lock=True)  # lock: serial EV-### numbering
        access.require(Permission.EVIDENCE_ADD)
        if access.case.status is CaseStatus.closed:
            raise InvalidStateError("Cannot add evidence to a closed case.")
        if kind not in EVIDENCE_KINDS:
            raise AppError(
                "invalid_kind",
                "Unknown evidence kind.",
                422,
                details={"allowed": sorted(EVIDENCE_KINDS)},
            )
        if label is not None and not LABEL_RE.fullmatch(label):
            raise AppError("invalid_label", "Label may use letters, digits, '.', '_' and '-'.", 422)
        if size_bytes is not None and size_bytes > self.settings.max_upload_bytes:
            raise AppError("upload_too_large", "Declared size exceeds MAX_UPLOAD_GB.", 413)
        evidence_id = uuid.uuid4()
        vault = self._vault()
        key = object_key(case_id, evidence_id, safe_filename(original_name))
        ev = Evidence(
            id=evidence_id,
            case_id=case_id,
            label=label or self._next_label(case_id),
            kind=kind,
            original_name=original_name,
            size_bytes=size_bytes,
            storage_uri=storage_uri(vault.bucket, key),
            mime_type=mime_type,
            source_host=source_host,
            acquired_at=acquired_at,
            acquired_by=acquired_by,
            acquisition_tool=acquisition_tool,
            acquisition_notes=acquisition_notes,
            expected_sha256=expected_sha256.lower() if expected_sha256 else None,
            expected_md5=expected_md5.lower() if expected_md5 else None,
            status="uploading",
            uploaded_by=principal.user_id,
        )
        self.session.add(ev)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError("Label already used in this case.", "label_taken") from exc
        self.custody.append(
            ev.id,
            "created",
            Actor.of(principal),
            {
                "case_id": str(case_id),
                "label": ev.label,
                "kind": kind,
                "original_name": original_name,
                "declared_size": size_bytes,
                "source_host": source_host,
                "acquired_at": _iso(acquired_at),
                "acquired_by": acquired_by,
                "acquisition_tool": acquisition_tool,
                "expected_sha256": ev.expected_sha256,
                "expected_md5": ev.expected_md5,
                "storage_uri": ev.storage_uri,
            },
        )
        self.audit.record(
            "evidence.created",
            user_id=principal.user_id,
            meta=meta,
            object_type="evidence",
            object_id=ev.id,
            detail={"case_id": str(case_id), "label": ev.label},
        )
        self.session.commit()
        return ev

    def get(self, principal: Principal, evidence_id: uuid.UUID) -> Evidence:
        ev, _ = self._load(principal, evidence_id, Permission.CASE_READ)
        return ev

    def list_for_case(self, principal: Principal, case_id: uuid.UUID) -> list[Evidence]:
        self._access(principal, case_id)
        return list(
            self.session.execute(
                select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at)
            ).scalars()
        )

    def custody_entries(self, principal: Principal, evidence_id: uuid.UUID) -> list[CustodyLog]:
        self._load(principal, evidence_id, Permission.CUSTODY_VIEW)
        return self.custody.entries(evidence_id)

    # ------------------------------------------------------------------ upload

    def _upload_lock(self, evidence_id: uuid.UUID) -> Any:
        """Session-level advisory lock on a dedicated connection: one upload per evidence item.

        Released explicitly; if the process dies the connection closes and the lock goes with it.
        """
        bind = self.session.get_bind()
        engine = bind if isinstance(bind, Engine) else bind.engine
        conn = engine.connect()
        key = int.from_bytes(evidence_id.bytes[:8], "big", signed=True)
        got: bool = conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar_one()
        conn.commit()
        if not got:
            conn.close()
            raise ConflictError(
                "An upload for this evidence is already in progress.", "upload_in_progress"
            )
        return conn, key

    @staticmethod
    def _upload_unlock(handle: Any) -> None:
        conn, key = handle
        try:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
            conn.commit()
        except Exception:  # noqa: BLE001 - make sure the lock dies with the connection
            conn.invalidate()
        finally:
            conn.close()

    def receive_upload(
        self,
        principal: Principal,
        evidence_id: uuid.UUID,
        source: Readable,
        *,
        meta: RequestMeta,
        content_type: str | None = None,
        declared_length: int | None = None,
    ) -> Evidence:
        ev, access = self._load(principal, evidence_id, Permission.EVIDENCE_ADD)
        if access.case.status is CaseStatus.closed:
            raise InvalidStateError("The case is closed.")
        if ev.status != "uploading":
            raise InvalidStateError("Evidence bytes were already received.", status=ev.status)
        limit = self.settings.max_upload_bytes
        if declared_length is not None and declared_length > limit:
            raise AppError("upload_too_large", "Upload exceeds MAX_UPLOAD_GB.", 413)
        vault = self._vault()
        key = self._key(ev)
        self.session.commit()  # no transaction stays open while bytes stream

        handle = self._upload_lock(evidence_id)
        try:
            # Re-check under the lock: another upload may have finished between the first check and
            # acquiring the lock, and a second PUT would add another version at the original's key.
            current = self.session.execute(
                select(Evidence.status).where(Evidence.id == evidence_id)
            ).scalar_one()
            self.session.commit()
            if current != "uploading":
                raise InvalidStateError("Evidence bytes were already received.", status=current)
            reader = HashingReader(source, limit)
            part_size = self.settings.upload_part_size_mb * MIB
            try:
                result = vault.put_stream(
                    key, reader, part_size, content_type or "application/octet-stream"
                )
            except UploadTooLargeError as exc:
                raise AppError("upload_too_large", "Upload exceeds MAX_UPLOAD_GB.", 413) from exc
            except AppError:
                raise
            except Exception as exc:
                log.error(
                    "upload_failed", evidence_id=str(evidence_id), exc_type=type(exc).__name__
                )
                raise AppError(
                    "upload_failed", "The upload did not complete; nothing was stored.", 502
                ) from exc
            digests = reader.hasher.digests()

            ev = self._lock(evidence_id)
            if ev.status != "uploading":
                raise InvalidStateError("Evidence bytes were already received.", status=ev.status)
            ev.sha256 = digests.sha256
            ev.md5 = digests.md5
            ev.size_bytes = digests.size
            ev.storage_version_id = result.version_id
            if content_type and not ev.mime_type:
                ev.mime_type = content_type
            ev.status = "uploaded"
            self.custody.append(
                ev.id,
                "ingested",
                Actor.of(principal),
                {
                    "sha256": digests.sha256,
                    "md5": digests.md5,
                    "size_bytes": digests.size,
                    "storage_uri": ev.storage_uri,
                    "version_id": result.version_id,
                    "etag": result.etag,
                    "source_ip": meta.ip,
                },
            )
            self.audit.record(
                "evidence.uploaded",
                user_id=principal.user_id,
                meta=meta,
                object_type="evidence",
                object_id=ev.id,
                detail={"sha256": digests.sha256, "size_bytes": digests.size},
            )
            self.session.commit()
            return ev
        finally:
            self._upload_unlock(handle)

    # ------------------------------------------------------------------ finalize

    def finalize(
        self, principal: Principal, evidence_id: uuid.UUID, meta: RequestMeta
    ) -> FinalizeResult:
        ev, _ = self._load(principal, evidence_id, Permission.EVIDENCE_ADD)
        if ev.status != "uploaded":
            raise InvalidStateError("Only uploaded evidence can be finalized.", status=ev.status)
        key = self._key(ev)
        version = ev.storage_version_id
        declared = self.custody.signed_value(ev.id, "created", "declared_size")
        self.session.commit()

        # Recompute from the stored bytes; never trust the streaming or client hash alone (8.2).
        digests = self._hash_stored(key, version)
        retention = self._vault().retention(key, version)
        if retention is None or retention.mode is None:
            raise AppError("vault_not_worm", "The stored object has no Object Lock retention.", 503)

        ev = self._lock(evidence_id)
        if ev.status != "uploaded":
            raise InvalidStateError("Only uploaded evidence can be finalized.", status=ev.status)
        mismatches: list[dict[str, Any]] = []
        checks: list[tuple[str, Any, Any]] = [
            ("sha256", ev.sha256, digests.sha256),
            ("md5", ev.md5, digests.md5),
            ("size_bytes", ev.size_bytes, digests.size),
        ]
        if ev.expected_sha256:
            checks.append(("expected_sha256", ev.expected_sha256, digests.sha256))
        if ev.expected_md5:
            checks.append(("expected_md5", ev.expected_md5, digests.md5))
        if declared is not None:
            checks.append(("declared_size", declared, digests.size))
        for name, expected, actual in checks:
            if expected != actual:
                mismatches.append({"field": name, "expected": expected, "actual": actual})
        actor = Actor.of(principal)
        common = {"source": "finalize", "version_id": version, **digests.as_dict()}
        if mismatches:
            ev.status = "failed"
            # Guide 8.1 step 3: a mismatch at ingest stops processing -> verification_failed.
            self.custody.append(
                ev.id, "verification_failed", actor, {**common, "mismatches": mismatches}
            )
            notify_admins(
                self.session,
                "evidence.verification_failed",
                {"evidence_id": str(ev.id), "label": ev.label, "stage": "finalize"},
            )
            emit_verification_failed(self.session, ev.case_id, ev.id, "finalize", ev.label)
        else:
            ev.status = "stored"
            ev.retain_until = retention.retain_until
            compared = [name for name, _, _ in checks]
            self.custody.append(ev.id, "hash_verified", actor, {**common, "compared": compared})
            self.custody.append(
                ev.id,
                "locked",
                actor,
                {
                    "mode": retention.mode,
                    "retain_until": _iso(retention.retain_until),
                    "version_id": version,
                },
            )
        self.audit.record(
            "evidence.finalized",
            user_id=principal.user_id,
            meta=meta,
            object_type="evidence",
            object_id=ev.id,
            detail={"ok": not mismatches, "mismatches": [m["field"] for m in mismatches]},
        )
        self.session.commit()
        return FinalizeResult(not mismatches, ev, digests, mismatches, retention)

    # ------------------------------------------------------------------ verify

    def _check_object(self, ev: Evidence, key: str) -> ObjectCheck:
        check = ObjectCheck(
            expected={"sha256": ev.sha256, "md5": ev.md5, "size_bytes": ev.size_bytes},
            version_expected=ev.storage_version_id,
        )
        signed_sha = self.custody.signed_value(ev.id, "ingested", "sha256")
        signed_size = self.custody.signed_value(ev.id, "ingested", "size_bytes")
        if signed_sha is not None and (signed_sha != ev.sha256 or signed_size != ev.size_bytes):
            check.fail(
                "metadata_mismatch",
                "Evidence hash/size in the database differ from the signed ingest entry.",
                signed_sha256=signed_sha,
                signed_size=signed_size,
            )
        vault = self._vault()
        try:
            latest = vault.stat(key)
            check.version_latest = latest.version_id
            digests = self._hash_stored(key, ev.storage_version_id)
        except VaultObjectMissingError:
            check.fail("object_missing", "The original object is missing from the vault.")
            return check
        check.actual = digests.as_dict()
        reference = signed_sha or ev.sha256
        if digests.sha256 != reference or digests.sha256 != ev.sha256:
            check.fail(
                "hash_mismatch",
                "Stored bytes do not match the recorded SHA-256.",
                expected=reference,
                actual=digests.sha256,
            )
        if digests.md5 != ev.md5 or digests.size != ev.size_bytes:
            check.fail("md5_or_size_mismatch", "Stored bytes do not match the recorded MD5/size.")
        if ev.storage_version_id and latest.version_id != ev.storage_version_id:
            latest_digests = self._hash_stored(key, latest.version_id)
            check.latest_sha256 = latest_digests.sha256
            if latest_digests.sha256 != reference:
                check.fail(
                    "object_replaced",
                    "A different object version now sits at the original's key.",
                    latest_version=latest.version_id,
                    latest_sha256=latest_digests.sha256,
                )
        return check

    def verify(
        self, principal: Principal, evidence_id: uuid.UUID, meta: RequestMeta
    ) -> VerifyResult:
        ev, _ = self._load(principal, evidence_id, Permission.EVIDENCE_VERIFY)
        if ev.status not in HAS_BYTES:
            raise InvalidStateError("Evidence has no stored bytes yet.", status=ev.status)
        key = self._key(ev)
        chain = self.custody.verify(ev.id)
        object_check = self._check_object(ev, key)
        self.session.commit()

        ev = self._lock(evidence_id)
        ok = chain.ok and object_check.ok
        if not object_check.ok:
            action = "hash_failed"
            ev.status = "failed"
        elif not chain.ok:
            action = "verification_failed"
        else:
            action = "hash_verified"
        entry = self.custody.append(
            ev.id,
            action,
            Actor.of(principal),
            {
                "source": "verify",
                "object_ok": object_check.ok,
                "object_problems": [p["code"] for p in object_check.problems],
                "sha256_expected": ev.sha256,
                "sha256_actual": (object_check.actual or {}).get("sha256"),
                "chain_ok": chain.ok,
                "chain_entries": chain.entries,
                "broken_seqs": chain.broken_seqs,
            },
        )
        if not ok:
            notify_admins(
                self.session,
                "evidence.integrity_failure",
                {
                    "evidence_id": str(ev.id),
                    "label": ev.label,
                    "object_problems": [p["code"] for p in object_check.problems],
                    "broken_seqs": chain.broken_seqs,
                },
            )
            emit_verification_failed(self.session, ev.case_id, ev.id, "verify", ev.label)
            self.audit.record(
                "evidence.integrity_failure",
                user_id=principal.user_id,
                meta=meta,
                object_type="evidence",
                object_id=ev.id,
                detail={"object_ok": object_check.ok, "chain_ok": chain.ok},
            )
        self.audit.record(
            "evidence.verify",
            user_id=principal.user_id,
            meta=meta,
            object_type="evidence",
            object_id=ev.id,
            detail={"ok": ok, "custody_seq": entry.seq},
        )
        self.session.commit()
        return VerifyResult(ok, ev, object_check, chain, entry, entry.ts)

    # ------------------------------------------------------------------ download

    def download(
        self, principal: Principal, evidence_id: uuid.UUID, meta: RequestMeta
    ) -> DownloadHandle:
        ev, _ = self._load(principal, evidence_id, Permission.EVIDENCE_DOWNLOAD)
        if ev.status not in HAS_BYTES:
            raise InvalidStateError("Evidence has no stored bytes yet.", status=ev.status)
        key = self._key(ev)
        vault = self._vault()
        try:
            vault.stat(key, ev.storage_version_id)
        except VaultObjectMissingError as exc:
            raise AppError("object_missing", "The original object is missing.", 409) from exc
        self._lock(evidence_id)
        self.custody.append(
            ev.id,
            "downloaded",
            Actor.of(principal),
            {"version_id": ev.storage_version_id, "sha256": ev.sha256, "source_ip": meta.ip},
        )
        self.audit.record(
            "evidence.download",
            user_id=principal.user_id,
            meta=meta,
            object_type="evidence",
            object_id=ev.id,
            detail={"sha256": ev.sha256},
        )
        self.session.commit()
        return DownloadHandle(
            filename=safe_filename(ev.original_name),
            size=ev.size_bytes,
            sha256=ev.sha256,
            mime_type="application/octet-stream",
            chunks=vault.iter_object(key, ev.storage_version_id),
        )
