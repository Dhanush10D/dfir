"""Hash-chained, Ed25519-signed chain of custody (guide 8.3). The ONLY writer of ``custody_log``.

Each entry stores ``prev_hash`` (previous ``entry_hash`` of the same evidence, or 64 zeros) and
``entry_hash = SHA-256(canonical_json(body))`` where ``body`` is every recorded field except the
hash, signature and key id. The hex hash is signed with Ed25519; public keys live in
``signing_keys``.

Entries are appended inside the caller's transaction (the action and its custody record commit
together) while holding ``SELECT ... FOR UPDATE`` on the evidence row, so ``seq`` and ``prev_hash``
stay consistent under concurrency. Callers commit.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.exceptions import AppError, NotFoundError
from app.core.permissions import Principal
from app.core.signing import (
    ALGORITHM,
    CustodySigner,
    SigningKeyError,
    load_public_key_pem,
    verify_signature,
)
from app.db.models import CustodyLog, Evidence, SigningKey

GENESIS = "0" * 64
BODY_FIELDS = (
    "evidence_id",
    "seq",
    "ts",
    "actor_id",
    "actor_label",
    "action",
    "detail",
    "prev_hash",
)

# Guide 8.3 + 8.1 vocabulary.
ACTIONS = frozenset(
    {
        "created",
        "ingested",
        "hash_verified",
        "hash_failed",
        "verification_failed",
        "locked",
        "accessed",
        "downloaded",
        "processed",
        "exported",
        "transferred",
        "note",
    }
)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def format_ts(ts: datetime) -> str:
    if ts.tzinfo is None:
        raise ValueError("custody timestamps must be timezone-aware")
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def check_detail(value: Any, path: str = "detail") -> None:
    """Only JSON values that round-trip exactly through jsonb (no floats, no NUL characters)."""
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, str):
        if "\x00" in value:
            raise ValueError(f"{path}: NUL characters are not allowed")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            check_detail(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: keys must be strings")
            check_detail(key, f"{path}.<key>")
            check_detail(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported type {type(value).__name__}")


def entry_body(
    *,
    evidence_id: uuid.UUID | str,
    seq: int,
    ts: datetime,
    actor_id: uuid.UUID | str | None,
    actor_label: str,
    action: str,
    detail: Mapping[str, Any],
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "evidence_id": str(evidence_id),
        "seq": seq,
        "ts": format_ts(ts),
        "actor_id": str(actor_id) if actor_id is not None else None,
        "actor_label": actor_label,
        "action": action,
        "detail": dict(detail),
        "prev_hash": prev_hash,
    }


def compute_entry_hash(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical({k: body[k] for k in BODY_FIELDS})).hexdigest()


@dataclass(frozen=True)
class ChainEntry:
    """One custody record as stored (or as built in memory by tests)."""

    evidence_id: str
    seq: int
    ts: datetime
    actor_id: str | None
    actor_label: str
    action: str
    detail: dict[str, Any]
    prev_hash: str
    entry_hash: str
    signature: str
    key_id: str
    row_id: int | None = None

    @classmethod
    def from_row(cls, row: CustodyLog) -> ChainEntry:
        return cls(
            evidence_id=str(row.evidence_id),
            seq=row.seq,
            ts=row.ts,
            actor_id=str(row.actor_id) if row.actor_id is not None else None,
            actor_label=row.actor_label,
            action=row.action,
            detail=dict(row.detail or {}),
            prev_hash=row.prev_hash,
            entry_hash=row.entry_hash,
            signature=row.signature,
            key_id=row.key_id,
            row_id=row.id,
        )

    def body(self) -> dict[str, Any]:
        return entry_body(
            evidence_id=self.evidence_id,
            seq=self.seq,
            ts=self.ts,
            actor_id=self.actor_id,
            actor_label=self.actor_label,
            action=self.action,
            detail=self.detail,
            prev_hash=self.prev_hash,
        )


def build_entry(
    signer: CustodySigner,
    *,
    evidence_id: uuid.UUID | str,
    seq: int,
    ts: datetime,
    actor_id: uuid.UUID | str | None,
    actor_label: str,
    action: str,
    detail: Mapping[str, Any],
    prev_hash: str,
) -> ChainEntry:
    body = entry_body(
        evidence_id=evidence_id,
        seq=seq,
        ts=ts,
        actor_id=actor_id,
        actor_label=actor_label,
        action=action,
        detail=detail,
        prev_hash=prev_hash,
    )
    entry_hash = compute_entry_hash(body)
    return ChainEntry(
        evidence_id=body["evidence_id"],
        seq=seq,
        ts=ts,
        actor_id=body["actor_id"],
        actor_label=actor_label,
        action=action,
        detail=body["detail"],
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signature=signer.sign(entry_hash),
        key_id=signer.key_id,
    )


@dataclass(frozen=True)
class ChainProblem:
    seq: int
    code: str  # seq_gap|duplicate_seq|broken_link|hash_mismatch|bad_signature|unknown_key|...
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "code": self.code, "message": self.message}


@dataclass
class ChainReport:
    evidence_id: str | None
    entries: int
    problems: list[ChainProblem] = field(default_factory=list)
    head_seq: int | None = None
    head_hash: str | None = None

    @property
    def ok(self) -> bool:
        return not self.problems

    @property
    def first_broken_seq(self) -> int | None:
        return min((p.seq for p in self.problems), default=None)

    @property
    def broken_seqs(self) -> list[int]:
        return sorted({p.seq for p in self.problems})

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "evidence_id": self.evidence_id,
            "entries": self.entries,
            "head_seq": self.head_seq,
            "head_hash": self.head_hash,
            "first_broken_seq": self.first_broken_seq,
            "broken_seqs": self.broken_seqs,
            "problems": [p.as_dict() for p in self.problems],
        }


def verify_chain(
    entries: Sequence[ChainEntry],
    public_keys: Mapping[str, Ed25519PublicKey],
    *,
    evidence_id: str | None = None,
    require_entries: bool = True,
) -> ChainReport:
    """Check sequence continuity, links, entry hashes and signatures; report each problem's seq.

    Links are checked against the *stored* previous hash, so a single edited row is reported at its
    own seq (hash mismatch or bad signature) and, if its stored hash was rewritten, at seq+1
    (broken link). Deleting the newest entries is only detectable with anchors (BACKLOG).
    """
    report = ChainReport(evidence_id=evidence_id, entries=len(entries))
    if not entries:
        if require_entries:
            report.problems.append(ChainProblem(0, "empty_chain", "no custody entries"))
        return report
    ordered = sorted(entries, key=lambda e: (e.seq, e.row_id or 0))
    prev_hash = GENESIS
    expected_seq = 1
    seen: set[int] = set()
    for entry in ordered:
        seq = entry.seq
        if seq in seen:
            report.problems.append(ChainProblem(seq, "duplicate_seq", f"seq {seq} appears twice"))
        elif seq != expected_seq:
            report.problems.append(
                ChainProblem(seq, "seq_gap", f"expected seq {expected_seq}, found {seq}")
            )
        seen.add(seq)
        if evidence_id is not None and entry.evidence_id != evidence_id:
            report.problems.append(
                ChainProblem(seq, "evidence_mismatch", "entry belongs to another evidence item")
            )
        if entry.prev_hash != prev_hash:
            report.problems.append(
                ChainProblem(seq, "broken_link", "prev_hash does not match the previous entry")
            )
        try:
            recomputed = compute_entry_hash(entry.body())
        except (ValueError, TypeError) as exc:
            recomputed = f"<invalid: {exc}>"
        if recomputed != entry.entry_hash:
            report.problems.append(
                ChainProblem(seq, "hash_mismatch", "entry content does not match entry_hash")
            )
        key = public_keys.get(entry.key_id)
        if key is None:
            report.problems.append(
                ChainProblem(seq, "unknown_key", f"signing key {entry.key_id!r} is not published")
            )
        elif not verify_signature(key, entry.signature, entry.entry_hash):
            report.problems.append(
                ChainProblem(seq, "bad_signature", "Ed25519 signature does not verify")
            )
        prev_hash = entry.entry_hash
        expected_seq = seq + 1
    report.head_seq = ordered[-1].seq
    report.head_hash = ordered[-1].entry_hash
    return report


@dataclass(frozen=True)
class Actor:
    user_id: uuid.UUID | None
    label: str

    @classmethod
    def of(cls, principal: Principal) -> Actor:
        return cls(user_id=principal.user_id, label=principal.label)


def utcnow() -> datetime:
    return datetime.now(UTC)


class CustodyService:
    def __init__(
        self,
        session: Session,
        signer: CustodySigner | None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.session = session
        self.signer = signer
        self.clock = clock

    def _require_signer(self) -> CustodySigner:
        if self.signer is None:
            raise AppError(
                "custody_signer_unavailable",
                "The custody signing key is not configured; evidence cannot be changed.",
                503,
            )
        return self.signer

    def ensure_signing_key(self) -> None:
        """Publish the signer's public key in ``signing_keys`` (idempotent, race-safe)."""
        signer = self._require_signer()
        pem = signer.public_key_pem()
        self.session.execute(
            pg_insert(SigningKey)
            .values(key_id=signer.key_id, algorithm=ALGORITHM, public_key=pem, purpose="custody")
            .on_conflict_do_nothing(index_elements=["key_id"])
        )
        stored = self.session.get(SigningKey, signer.key_id)
        if stored is None or stored.public_key.strip() != pem.strip():
            raise AppError(
                "signing_key_conflict",
                f"Key id {signer.key_id!r} is already published with a different public key.",
                500,
            )

    def append(
        self,
        evidence_id: uuid.UUID,
        action: str,
        actor: Actor,
        detail: Mapping[str, Any] | None = None,
    ) -> CustodyLog:
        if action not in ACTIONS:
            raise ValueError(f"unknown custody action {action!r}")
        detail = dict(detail or {})
        check_detail(detail)
        signer = self._require_signer()
        locked = self.session.execute(
            select(Evidence.id).where(Evidence.id == evidence_id).with_for_update()
        ).scalar_one_or_none()
        if locked is None:
            raise NotFoundError("Evidence not found.")
        self.ensure_signing_key()
        last = self.session.execute(
            select(CustodyLog)
            .where(CustodyLog.evidence_id == evidence_id)
            .order_by(CustodyLog.seq.desc())
            .limit(1)
        ).scalar_one_or_none()
        entry = build_entry(
            signer,
            evidence_id=evidence_id,
            seq=(last.seq + 1) if last else 1,
            ts=self.clock(),
            actor_id=actor.user_id,
            actor_label=actor.label,
            action=action,
            detail=detail,
            prev_hash=last.entry_hash if last else GENESIS,
        )
        row = CustodyLog(
            evidence_id=evidence_id,
            seq=entry.seq,
            ts=entry.ts,
            actor_id=actor.user_id,
            actor_label=entry.actor_label,
            action=entry.action,
            detail=entry.detail,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
            signature=entry.signature,
            key_id=entry.key_id,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def entries(self, evidence_id: uuid.UUID) -> list[CustodyLog]:
        return list(
            self.session.execute(
                select(CustodyLog)
                .where(CustodyLog.evidence_id == evidence_id)
                .order_by(CustodyLog.seq, CustodyLog.id)
            ).scalars()
        )

    def public_keys(self) -> dict[str, Ed25519PublicKey]:
        keys: dict[str, Ed25519PublicKey] = {}
        for row in self.session.execute(select(SigningKey)).scalars():
            if row.algorithm != ALGORITHM:
                continue
            try:
                keys[row.key_id] = load_public_key_pem(row.public_key)
            except (SigningKeyError, ValueError):
                continue
        return keys

    def list_signing_keys(self) -> list[SigningKey]:
        return list(
            self.session.execute(select(SigningKey).order_by(SigningKey.created_at)).scalars()
        )

    def verify(self, evidence_id: uuid.UUID) -> ChainReport:
        rows = self.entries(evidence_id)
        return verify_chain(
            [ChainEntry.from_row(r) for r in rows],
            self.public_keys(),
            evidence_id=str(evidence_id),
        )

    def signed_value(self, evidence_id: uuid.UUID, action: str, key: str) -> Any:
        """``detail[key]`` of the first entry with ``action`` (e.g. the ingested SHA-256)."""
        for row in self.entries(evidence_id):
            if row.action == action and key in (row.detail or {}):
                return row.detail[key]
        return None
