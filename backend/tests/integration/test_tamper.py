"""Integrity tests (guide 22.3): tampering with custody rows, vault objects or evidence metadata is
detected by POST /evidence/{id}/verify, which reports the exact broken custody seq.

Custody edits use the database owner with ``session_replication_role = replica`` (superuser only),
which disables the append-only triggers: the strongest insider an application can face. The app role
itself cannot mutate custody rows at all.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import DBAPIError

from app.core.signing import CustodySigner
from app.db.models import UserRole
from app.services.custody import build_entry
from tests.fakes import FakeVault
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration


def _setup(h: Harness) -> tuple[UserCtx, dict[str, Any]]:
    """Stored evidence with custody seq 1..4: created, ingested, hash_verified, locked."""
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead)
    ev = h.stored_evidence(lead, case["id"], b"evidence bytes\n" * 50)
    return lead, ev


def _as_owner_without_triggers(engine: Engine) -> Connection:
    conn = engine.connect()
    conn.execute(text("SET session_replication_role = replica"))
    return conn


def _verify(h: Harness, user: UserCtx, evidence_id: str) -> dict[str, Any]:
    r = h.post(f"/evidence/{evidence_id}/verify", user)
    assert r.status_code == 200, r.text
    return dict(r.json())


def _codes(report: dict[str, Any]) -> set[tuple[int, str]]:
    return {(p["seq"], p["code"]) for p in report["chain"]["problems"]}


def _row(engine: Engine, evidence_id: str, seq: int) -> dict[str, Any]:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT * FROM custody_log WHERE evidence_id = :e AND seq = :s"),
            {"e": evidence_id, "s": seq},
        ).one()
    return dict(row._mapping)


def test_untampered_evidence_verifies(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is True
    assert report["chain"]["entries"] == 4


def test_edited_custody_detail_is_detected_at_its_seq(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text(
                "UPDATE custody_log SET detail = jsonb_set(detail, '{sha256}', '\"forged\"') "
                "WHERE evidence_id = :e AND seq = 2"
            ),
            {"e": ev["id"]},
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert report["status"] == "integrity_failure"
    assert report["chain"]["first_broken_seq"] == 2
    assert report["chain"]["broken_seqs"] == [2]
    assert _codes(report) == {(2, "hash_mismatch")}
    # The verification itself is recorded (and signed) as a new custody entry.
    assert report["custody_entry"]["action"] == "hash_failed"  # signed ingest sha256 was forged
    assert report["custody_entry"]["detail"]["broken_seqs"] == [2]


def test_edited_timestamp_and_actor_are_detected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text(
                "UPDATE custody_log SET ts = ts - interval '3 days' "
                "WHERE evidence_id = :e AND seq = 3"
            ),
            {"e": ev["id"]},
        )
        conn.execute(
            text(
                "UPDATE custody_log SET actor_label = 'Someone Else' "
                "WHERE evidence_id = :e AND seq = 4"
            ),
            {"e": ev["id"]},
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert _codes(report) == {(3, "hash_mismatch"), (4, "hash_mismatch")}
    assert report["custody_entry"]["action"] == "verification_failed"


def test_rehashed_edit_without_the_key_fails_signature_and_next_link(
    h: Harness, db_engine: Engine
) -> None:
    lead, ev = _setup(h)
    row = _row(db_engine, ev["id"], 2)
    attacker = CustodySigner(row["key_id"], Ed25519PrivateKey.generate())
    forged = build_entry(
        attacker,
        evidence_id=ev["id"],
        seq=2,
        ts=row["ts"],
        actor_id=row["actor_id"],
        actor_label=row["actor_label"],
        action=row["action"],
        detail={**row["detail"], "source_ip": "203.0.113.66"},
        prev_hash=row["prev_hash"],
    )
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text(
                "UPDATE custody_log SET detail = CAST(:d AS jsonb), entry_hash = :h, "
                "signature = :s WHERE evidence_id = :e AND seq = 2"
            ),
            {
                "d": json.dumps(forged.detail),
                "h": forged.entry_hash,
                "s": forged.signature,
                "e": ev["id"],
            },
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert _codes(report) == {(2, "bad_signature"), (3, "broken_link")}
    assert report["chain"]["first_broken_seq"] == 2


def test_deleted_entry_is_detected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text("DELETE FROM custody_log WHERE evidence_id = :e AND seq = 2"), {"e": ev["id"]}
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert report["chain"]["entries"] == 3
    assert _codes(report) == {(3, "seq_gap"), (3, "broken_link")}
    assert report["chain"]["first_broken_seq"] == 3


def test_reordered_entries_are_detected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    with _as_owner_without_triggers(db_engine) as conn:
        params = {"e": ev["id"]}
        conn.execute(
            text("UPDATE custody_log SET seq = 99 WHERE evidence_id = :e AND seq = 2"), params
        )
        conn.execute(
            text("UPDATE custody_log SET seq = 2 WHERE evidence_id = :e AND seq = 3"), params
        )
        conn.execute(
            text("UPDATE custody_log SET seq = 3 WHERE evidence_id = :e AND seq = 99"), params
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    codes = _codes(report)
    assert {(2, "hash_mismatch"), (2, "broken_link"), (3, "hash_mismatch")} <= codes
    assert report["chain"]["broken_seqs"] == [2, 3, 4]
    assert report["chain"]["first_broken_seq"] == 2


def test_forged_appended_entry_is_rejected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    head = _row(db_engine, ev["id"], 4)
    attacker = CustodySigner(head["key_id"], Ed25519PrivateKey.generate())  # claims the real key id
    forged = build_entry(
        attacker,
        evidence_id=ev["id"],
        seq=5,
        ts=head["ts"] + timedelta(seconds=1),
        actor_id=None,
        actor_label="Evidence Custodian",
        action="transferred",
        detail={"to": "offsite"},
        prev_hash=head["entry_hash"],
    )
    rogue = CustodySigner("rogue-key", Ed25519PrivateKey.generate())
    forged2 = build_entry(
        rogue,
        evidence_id=ev["id"],
        seq=6,
        ts=head["ts"] + timedelta(seconds=2),
        actor_id=None,
        actor_label="Evidence Custodian",
        action="note",
        detail={},
        prev_hash=forged.entry_hash,
    )
    with db_engine.begin() as conn:  # plain INSERT: the trigger allows appends
        for entry in (forged, forged2):
            conn.execute(
                text(
                    "INSERT INTO custody_log (evidence_id, seq, ts, actor_id, actor_label, action, "
                    "detail, prev_hash, entry_hash, signature, key_id) VALUES (:e, :s, :ts, NULL, "
                    ":al, :a, CAST(:d AS jsonb), :p, :h, :sig, :k)"
                ),
                {
                    "e": ev["id"],
                    "s": entry.seq,
                    "ts": entry.ts,
                    "al": entry.actor_label,
                    "a": entry.action,
                    "d": json.dumps(entry.detail),
                    "p": entry.prev_hash,
                    "h": entry.entry_hash,
                    "sig": entry.signature,
                    "k": entry.key_id,
                },
            )
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert _codes(report) == {(5, "bad_signature"), (6, "unknown_key")}


def test_wrong_signature_bytes_are_rejected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    row = _row(db_engine, ev["id"], 1)
    flipped = ("0" if row["signature"][0] != "0" else "1") + row["signature"][1:]
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text("UPDATE custody_log SET signature = :s WHERE evidence_id = :e AND seq = 1"),
            {"s": flipped, "e": ev["id"]},
        )
        conn.commit()
    report = _verify(h, lead, ev["id"])
    assert _codes(report) == {(1, "bad_signature")}


def test_replaced_vault_object_is_detected(h: Harness, vault: FakeVault, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    admin = h.make_user(UserRole.admin)
    new_version = vault.tamper_put(h.key_of(ev), b"evidence bytes\n" * 49 + b"evidence bytez\n")
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert report["chain"]["ok"] is True
    problems = {p["code"] for p in report["object"]["problems"]}
    assert problems == {"object_replaced"}
    assert report["object"]["version_latest"] == new_version
    assert report["custody_entry"]["action"] == "hash_failed"
    assert report["evidence_status"] == "failed"
    with db_engine.connect() as conn:
        kinds = set(
            conn.execute(
                text("SELECT kind FROM notifications WHERE user_id = :u"), {"u": admin.id}
            ).scalars()
        )
        audit = set(
            conn.execute(
                text("SELECT action FROM audit_log WHERE object_id = :o"), {"o": ev["id"]}
            ).scalars()
        )
    assert "evidence.integrity_failure" in kinds
    assert {"evidence.integrity_failure", "evidence.verify"} <= audit


def test_flipped_byte_in_stored_version_is_detected(h: Harness, vault: FakeVault) -> None:
    lead, ev = _setup(h)
    vault.corrupt(h.key_of(ev), ev["storage_version_id"], offset=7)
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert {p["code"] for p in report["object"]["problems"]} >= {"hash_mismatch"}
    assert report["object"]["actual"]["sha256"] != ev["sha256"]
    assert report["custody_entry"]["action"] == "hash_failed"


def test_tampered_evidence_hash_in_database_is_detected(h: Harness, db_engine: Engine) -> None:
    lead, ev = _setup(h)
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE evidence SET sha256 = :s WHERE id = :e"), {"s": "f" * 64, "e": ev["id"]}
        )
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    problems = {p["code"] for p in report["object"]["problems"]}
    assert {"metadata_mismatch", "hash_mismatch"} <= problems


def test_missing_vault_object_is_detected(h: Harness, vault: FakeVault) -> None:
    lead, ev = _setup(h)
    vault.delete_all(h.key_of(ev))
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert [p["code"] for p in report["object"]["problems"]] == ["object_missing"]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE custody_log SET action = 'tampered'",
        "DELETE FROM custody_log",
        "TRUNCATE custody_log",
        "UPDATE audit_log SET action = 'tampered'",
        "DELETE FROM audit_log",
        "SET session_replication_role = replica",
    ],
)
def test_app_role_cannot_mutate_custody_or_audit(app_engine: Engine, statement: str) -> None:
    with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text(statement))


def test_app_role_can_append_and_read(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "dfirbench_app"
        conn.execute(text("INSERT INTO audit_log (action) VALUES ('probe')"))
        assert conn.execute(text("SELECT count(*) FROM custody_log")).scalar_one() >= 0
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text("UPDATE alembic_version SET version_num = 'x'"))


def test_unknown_evidence_verify_is_404(h: Harness) -> None:
    lead = h.make_user(UserRole.lead)
    assert h.post(f"/evidence/{uuid.uuid4()}/verify", lead).status_code == 404
