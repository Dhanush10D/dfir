"""Read-only integrity check of the whole platform, and signed state manifests (Phase 10).

``IntegrityChecker.check()`` runs in a READ ONLY transaction and never writes (no custody entry,
no status change): after a restore the data must be checked exactly as it was restored, and a
scheduled run must not grow the custody log. It verifies

* every evidence item's custody chain against trusted keys supplied by the caller (the running
  signer's public key and/or a trust file, never keys read from the database);
* that the evidence row's SHA-256 and size equal the signed ``ingested`` custody entry;
* for stored evidence: the original's bytes at the recorded vault version hash to that value, and
  the object still has an Object Lock retention;
* that keys published in ``signing_keys`` equal the trusted keys with the same id;
* optionally, a signed manifest (``build_manifest``): its signature, the Alembic revision, row
  counts, every evidence item (hash, size, version, status) and custody chain head, and every
  signed report. Chain heads catch truncation or extension of a chain relative to the manifest.

``build_manifest`` is what a backup records (``python -m app.cli backup-manifest``); it is signed
with the custody key so a restore can be checked against a trust anchor outside the backup.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.hashing import MultiHasher
from app.core.signing import (
    CustodySigner,
    SigningKeyError,
    load_public_key_pem,
    same_key,
    verify_signature,
)
from app.db.models import CustodyLog, Evidence, SigningKey
from app.repositories.vault import VaultObjectMissingError, VaultStore
from app.services.custody import ChainEntry, canonical, verify_chain

MANIFEST_FORMAT = "dfirbench-state-manifest"
MANIFEST_VERSION = 1
READ_CHUNK = 1024 * 1024
# Tables whose row counts a manifest records (forensic records and their context).
COUNTED_TABLES = (
    "users",
    "cases",
    "evidence",
    "custody_log",
    "signing_keys",
    "audit_log",
    "jobs",
    "events",
    "alerts",
    "notes",
    "note_versions",
    "bundle_members",
    "ai_interactions",
    "reports",
    "playbook_runs",
    "action_requests",
    "integrations",
    "outbound_events",
)


class ManifestError(ValueError):
    """The manifest is malformed or its signature does not verify."""


@dataclass
class Problem:
    code: str
    message: str
    evidence_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.evidence_id:
            out["evidence_id"] = self.evidence_id
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class IntegrityReport:
    evidence_checked: int = 0
    objects_hashed: int = 0
    bytes_hashed: int = 0
    chains_checked: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    manifest_checked: bool = False
    problems: list[Problem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def fail(self, code: str, message: str, evidence_id: str | None = None, **detail: Any) -> None:
        self.problems.append(Problem(code, message, evidence_id, detail))

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "evidence_checked": self.evidence_checked,
            "chains_checked": self.chains_checked,
            "objects_hashed": self.objects_hashed,
            "bytes_hashed": self.bytes_hashed,
            "by_status": dict(sorted(self.by_status.items())),
            "manifest_checked": self.manifest_checked,
            "problems": [p.as_dict() for p in self.problems],
        }


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _vault_key(vault: VaultStore, storage_uri: str) -> str | None:
    prefix = f"s3://{vault.bucket}/"
    return storage_uri[len(prefix) :] if storage_uri.startswith(prefix) else None


def collect_state(session: Session) -> dict[str, Any]:
    """The state a manifest records (sorted, JSON-safe, no evidence content)."""
    revision = session.execute(text("SELECT version_num FROM alembic_version")).scalar()
    counts = {
        table: int(session.execute(text(f"SELECT count(*) FROM {table}")).scalar_one())  # noqa: S608  # nosec B608 - fixed table names
        for table in COUNTED_TABLES
    }
    heads: dict[str, dict[str, Any]] = {}
    for row in session.execute(
        text(
            "SELECT DISTINCT ON (evidence_id) evidence_id, seq, entry_hash, "
            "count(*) OVER (PARTITION BY evidence_id) AS n FROM custody_log "
            "ORDER BY evidence_id, seq DESC, id DESC"
        )
    ):
        heads[str(row.evidence_id)] = {
            "entries": int(row.n),
            "head_seq": int(row.seq),
            "head_hash": str(row.entry_hash),
        }
    evidence = [
        {
            "id": str(ev.id),
            "case_id": str(ev.case_id),
            "status": ev.status,
            "sha256": ev.sha256,
            "size_bytes": ev.size_bytes,
            "storage_uri": ev.storage_uri,
            "version_id": ev.storage_version_id,
            "chain": heads.get(str(ev.id), {"entries": 0, "head_seq": None, "head_hash": None}),
        }
        for ev in session.execute(select(Evidence).order_by(Evidence.id)).scalars()
    ]
    reports = [
        {
            "id": str(row.id),
            "version": int(row.version),
            "sha256": row.sha256,
            "signature": row.signature,
            "key_id": row.key_id,
            "storage_uri": row.storage_uri,
        }
        for row in session.execute(
            text(
                "SELECT id, version, sha256, signature, key_id, storage_uri FROM reports "
                "WHERE status = 'signed' ORDER BY id"
            )
        )
    ]
    return {
        "alembic_revision": revision,
        "counts": counts,
        "evidence": evidence,
        "signed_reports": reports,
    }


def build_manifest(
    session: Session, signer: CustodySigner, *, now: datetime | None = None
) -> dict[str, Any]:
    """Signed state manifest (the body's canonical SHA-256, Ed25519-signed by the custody key)."""
    session.execute(text("SET TRANSACTION READ ONLY"))
    try:
        body = {
            "format": MANIFEST_FORMAT,
            "version": MANIFEST_VERSION,
            "created_at": _iso(now or datetime.now(UTC)),
            **collect_state(session),
        }
    finally:
        session.rollback()
    digest = hashlib.sha256(canonical(body)).hexdigest()
    return {
        "manifest": body,
        "sha256": digest,
        "signature": {"alg": "ed25519", "key_id": signer.key_id, "value": signer.sign(digest)},
    }


def verify_manifest(
    document: Mapping[str, Any], trusted_keys: Mapping[str, Ed25519PublicKey]
) -> dict[str, Any]:
    """The manifest body if its hash and signature verify under a trusted key."""
    body = document.get("manifest")
    signature = document.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, dict):
        raise ManifestError("not a state manifest")
    if body.get("format") != MANIFEST_FORMAT or body.get("version") != MANIFEST_VERSION:
        raise ManifestError("unknown manifest format or version")
    try:
        digest = hashlib.sha256(canonical(body)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise ManifestError("manifest body is not canonical JSON") from exc
    if document.get("sha256") != digest:
        raise ManifestError("manifest hash does not match its body")
    key = trusted_keys.get(str(signature.get("key_id")))
    if key is None:
        raise ManifestError(f"manifest signed by an untrusted key {signature.get('key_id')!r}")
    if signature.get("alg") != "ed25519" or not verify_signature(
        key, str(signature.get("value", "")), digest
    ):
        raise ManifestError("manifest signature does not verify")
    return body


class IntegrityChecker:
    def __init__(
        self,
        session: Session,
        vault: VaultStore | None,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        *,
        hash_objects: bool = True,
    ) -> None:
        self.session = session
        self.vault = vault
        self.trusted_keys = dict(trusted_keys)
        self.hash_objects = hash_objects

    def check(self, manifest: Mapping[str, Any] | None = None) -> IntegrityReport:
        report = IntegrityReport()
        if not self.trusted_keys:
            report.fail("no_trusted_keys", "No trusted custody keys were supplied.")
            return report
        body: dict[str, Any] | None = None
        if manifest is not None:
            try:
                body = verify_manifest(manifest, self.trusted_keys)
            except ManifestError as exc:
                report.fail("manifest_invalid", str(exc))
                return report
        self.session.execute(text("SET TRANSACTION READ ONLY"))
        try:
            published = self._published_keys(report)
            state = collect_state(self.session)
            self._check_evidence(report, published)
            if body is not None:
                self._compare(report, body, state)
                report.manifest_checked = True
        finally:
            self.session.rollback()
        return report

    # ------------------------------------------------------------------ parts

    def _published_keys(self, report: IntegrityReport) -> dict[str, Ed25519PublicKey]:
        keys: dict[str, Ed25519PublicKey] = {}
        for row in self.session.execute(select(SigningKey)).scalars():
            try:
                key = load_public_key_pem(row.public_key)
            except (SigningKeyError, ValueError):
                report.fail("signing_key_unreadable", f"published key {row.key_id!r} is unreadable")
                continue
            keys[row.key_id] = key
            trusted = self.trusted_keys.get(row.key_id)
            if trusted is not None and not same_key(trusted, key):
                report.fail(
                    "signing_key_mismatch",
                    f"published key {row.key_id!r} differs from the trusted key",
                )
        return keys

    def _check_evidence(
        self, report: IntegrityReport, published: Mapping[str, Ed25519PublicKey]
    ) -> None:
        statuses: Counter[str] = Counter()
        evidence = list(self.session.execute(select(Evidence).order_by(Evidence.id)).scalars())
        for ev in evidence:
            eid = str(ev.id)
            statuses[ev.status] += 1
            report.evidence_checked += 1
            rows = list(
                self.session.execute(
                    select(CustodyLog)
                    .where(CustodyLog.evidence_id == ev.id)
                    .order_by(CustodyLog.seq, CustodyLog.id)
                ).scalars()
            )
            entries = [ChainEntry.from_row(r) for r in rows]
            chain = verify_chain(
                entries, self.trusted_keys, published_keys=published, evidence_id=eid
            )
            report.chains_checked += 1
            if not chain.ok:
                report.fail(
                    "chain_broken",
                    "The custody chain does not verify.",
                    eid,
                    broken_seqs=chain.broken_seqs,
                    codes=sorted({p.code for p in chain.problems}),
                )
            signed = next(
                (e.detail for e in entries if e.action == "ingested" and "sha256" in e.detail),
                None,
            )
            if signed is not None and (
                signed.get("sha256") != ev.sha256 or signed.get("size_bytes") != ev.size_bytes
            ):
                report.fail(
                    "metadata_mismatch",
                    "Evidence hash/size differ from the signed ingest entry.",
                    eid,
                )
            if ev.status == "stored":
                self._check_object(report, ev, signed)
        report.by_status = dict(statuses)

    def _check_object(
        self, report: IntegrityReport, ev: Evidence, signed: Mapping[str, Any] | None
    ) -> None:
        eid = str(ev.id)
        if signed is None:
            report.fail("not_ingested", "Stored evidence has no signed ingest entry.", eid)
            return
        if self.vault is None:
            report.fail("vault_unavailable", "No vault to check stored objects against.", eid)
            return
        key = _vault_key(self.vault, ev.storage_uri)
        if key is None:
            report.fail("storage_mismatch", "Evidence is stored in another vault.", eid)
            return
        try:
            retention = self.vault.retention(key, ev.storage_version_id)
        except VaultObjectMissingError:
            report.fail("object_missing", "The original object is missing from the vault.", eid)
            return
        if retention is None or retention.mode is None:
            report.fail("not_locked", "The original object has no Object Lock retention.", eid)
        if not self.hash_objects:
            return
        hasher = MultiHasher()
        try:
            for chunk in self.vault.iter_object(key, ev.storage_version_id, READ_CHUNK):
                hasher.update(chunk)
        except VaultObjectMissingError:
            report.fail("object_missing", "The original object is missing from the vault.", eid)
            return
        digests = hasher.digests()
        report.objects_hashed += 1
        report.bytes_hashed += digests.size
        if digests.sha256 != signed.get("sha256") or digests.size != signed.get("size_bytes"):
            report.fail(
                "hash_mismatch",
                "Stored bytes do not match the signed SHA-256.",
                eid,
                expected=signed.get("sha256"),
                actual=digests.sha256,
            )

    @staticmethod
    def _compare(
        report: IntegrityReport, body: Mapping[str, Any], state: Mapping[str, Any]
    ) -> None:
        if body.get("alembic_revision") != state["alembic_revision"]:
            report.fail(
                "revision_mismatch",
                "The schema revision differs from the manifest.",
                expected=body.get("alembic_revision"),
                actual=state["alembic_revision"],
            )
        expected_counts = body.get("counts") or {}
        for table, expected in sorted(expected_counts.items()):
            actual = state["counts"].get(table)
            if actual != expected:
                report.fail(
                    "count_mismatch",
                    f"Row count of {table} differs from the manifest.",
                    table=table,
                    expected=expected,
                    actual=actual,
                )
        recorded = {e["id"]: e for e in body.get("evidence") or [] if isinstance(e, dict)}
        current = {e["id"]: e for e in state["evidence"]}
        for eid in sorted(set(recorded) - set(current)):
            report.fail("evidence_missing", "Evidence in the manifest is missing.", eid)
        for eid in sorted(set(current) - set(recorded)):
            report.fail("evidence_unexpected", "Evidence not in the manifest.", eid)
        for eid in sorted(set(recorded) & set(current)):
            want, have = recorded[eid], current[eid]
            for name in ("status", "sha256", "size_bytes", "storage_uri", "version_id", "chain"):
                if want.get(name) != have.get(name):
                    code = "chain_head_mismatch" if name == "chain" else "evidence_changed"
                    report.fail(
                        code,
                        f"Evidence {name} differs from the manifest.",
                        eid,
                        field=name,
                        expected=want.get(name),
                        actual=have.get(name),
                    )
        if (body.get("signed_reports") or []) != state["signed_reports"]:
            report.fail("reports_changed", "Signed reports differ from the manifest.")
