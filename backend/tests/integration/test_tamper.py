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

from app.core.signing import CustodySigner, public_key_pem
from app.db.models import UserRole
from app.services.custody import GENESIS, ChainEntry, build_entry
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
    # SET LOCAL: ends with the transaction, so the pooled connection never keeps triggers off.
    conn.execute(text("SET LOCAL session_replication_role = replica"))
    return conn


def _insert_entry(conn: Connection, entry: ChainEntry) -> None:
    conn.execute(
        text(
            "INSERT INTO custody_log (evidence_id, seq, ts, actor_id, actor_label, action, "
            "detail, prev_hash, entry_hash, signature, key_id) VALUES (:e, :s, :ts, :aid, "
            ":al, :a, CAST(:d AS jsonb), :p, :h, :sig, :k)"
        ),
        {
            "e": entry.evidence_id,
            "s": entry.seq,
            "ts": entry.ts,
            "aid": entry.actor_id,
            "al": entry.actor_label,
            "a": entry.action,
            "d": json.dumps(entry.detail),
            "p": entry.prev_hash,
            "h": entry.entry_hash,
            "sig": entry.signature,
            "k": entry.key_id,
        },
    )


def _publish_key(conn: Connection, signer: CustodySigner) -> None:
    conn.execute(
        text(
            "INSERT INTO signing_keys (key_id, algorithm, public_key, purpose) "
            "VALUES (:k, 'ed25519', :pem, 'custody')"
        ),
        {"k": signer.key_id, "pem": public_key_pem(signer.public_key)},
    )


def _resign_chain(engine: Engine, evidence_id: str, signer: CustodySigner) -> list[ChainEntry]:
    """Rebuild an evidence item's whole chain with ``signer`` (same content, fresh links)."""
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM custody_log WHERE evidence_id = :e ORDER BY seq"),
            {"e": evidence_id},
        ).all()
    entries: list[ChainEntry] = []
    prev = GENESIS
    for row in rows:
        m = row._mapping
        entry = build_entry(
            signer,
            evidence_id=evidence_id,
            seq=m["seq"],
            ts=m["ts"],
            actor_id=m["actor_id"],
            actor_label=m["actor_label"],
            action=m["action"],
            detail=m["detail"],
            prev_hash=prev,
        )
        entries.append(entry)
        prev = entry.entry_hash
    return entries


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
            _insert_entry(conn, entry)
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert _codes(report) == {(5, "bad_signature"), (6, "untrusted_key")}


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


def test_owner_publishing_attacker_key_and_resigning_whole_chain_fails(
    h: Harness, db_engine: Engine
) -> None:
    """Demo (a): signing_keys is not a trust anchor; a key added there verifies nothing."""
    lead, ev = _setup(h)
    attacker = CustodySigner("attacker-key", Ed25519PrivateKey.generate())
    forged = _resign_chain(db_engine, ev["id"], attacker)
    with _as_owner_without_triggers(db_engine) as conn:
        _publish_key(conn, attacker)
        for entry in forged:
            conn.execute(
                text(
                    "UPDATE custody_log SET prev_hash = :p, entry_hash = :h, signature = :s, "
                    "key_id = :k WHERE evidence_id = :e AND seq = :q"
                ),
                {
                    "p": entry.prev_hash,
                    "h": entry.entry_hash,
                    "s": entry.signature,
                    "k": entry.key_id,
                    "e": ev["id"],
                    "q": entry.seq,
                },
            )
        conn.commit()
    try:
        report = _verify(h, lead, ev["id"])
        assert report["ok"] is False
        assert _codes(report) == {(seq, "untrusted_key") for seq in (1, 2, 3, 4)}
        assert report["chain"]["first_broken_seq"] == 1
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM signing_keys WHERE key_id = 'attacker-key'"))


def test_owner_replacing_published_real_key_is_detected(h: Harness, db_engine: Engine) -> None:
    """Swapping the published key for the real kid and re-signing under that kid also fails."""
    lead, ev = _setup(h)
    real_kid = _row(db_engine, ev["id"], 1)["key_id"]
    attacker = CustodySigner(real_kid, Ed25519PrivateKey.generate())
    forged = _resign_chain(db_engine, ev["id"], attacker)
    with db_engine.connect() as conn:
        original_pem = conn.execute(
            text("SELECT public_key FROM signing_keys WHERE key_id = :k"), {"k": real_kid}
        ).scalar_one()
    with _as_owner_without_triggers(db_engine) as conn:
        conn.execute(
            text("UPDATE signing_keys SET public_key = :pem WHERE key_id = :k"),
            {"pem": public_key_pem(attacker.public_key), "k": real_kid},
        )
        for entry in forged:
            conn.execute(
                text(
                    "UPDATE custody_log SET prev_hash = :p, entry_hash = :h, signature = :s "
                    "WHERE evidence_id = :e AND seq = :q"
                ),
                {
                    "p": entry.prev_hash,
                    "h": entry.entry_hash,
                    "s": entry.signature,
                    "e": ev["id"],
                    "q": entry.seq,
                },
            )
        conn.commit()
    try:
        report = _verify(h, lead, ev["id"])
        assert report["ok"] is False
        codes = _codes(report)
        assert {(1, "bad_signature"), (1, "untrusted_key")} <= codes
        assert report["chain"]["broken_seqs"] == [1, 2, 3, 4]
    finally:
        with db_engine.begin() as conn:
            conn.execute(
                text("UPDATE signing_keys SET public_key = :pem WHERE key_id = :k"),
                {"pem": original_pem, "k": real_kid},
            )


def test_app_role_rogue_key_and_signed_append_fails(
    h: Harness, app_engine: Engine, db_engine: Engine
) -> None:
    """Demo (b): what SQL injection as dfirbench_app could do: publish a key, append an entry."""
    lead, ev = _setup(h)
    rogue = CustodySigner(f"rogue-{uuid.uuid4().hex[:8]}", Ed25519PrivateKey.generate())
    head = _row(db_engine, ev["id"], 4)
    entry = build_entry(
        rogue,
        evidence_id=ev["id"],
        seq=5,
        ts=head["ts"] + timedelta(seconds=1),
        actor_id=None,
        actor_label="Evidence Custodian",
        action="transferred",
        detail={"to": "offsite"},
        prev_hash=head["entry_hash"],
    )
    with app_engine.begin() as conn:
        assert conn.execute(text("SELECT current_user")).scalar_one() == "dfirbench_app"
        _publish_key(conn, rogue)
        _insert_entry(conn, entry)
    report = _verify(h, lead, ev["id"])
    assert report["ok"] is False
    assert _codes(report) == {(5, "untrusted_key")}
    assert report["custody_entry"]["action"] == "verification_failed"


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE signing_keys SET public_key = 'x'",
        "DELETE FROM signing_keys",
        "TRUNCATE signing_keys",
    ],
)
def test_app_role_cannot_rewrite_or_delete_signing_keys(app_engine: Engine, statement: str) -> None:
    with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(text(statement))


def test_retired_key_is_trusted_only_via_trust_file(h: Harness) -> None:
    """Key rotation: chains signed by an old key verify only if that key is configured trusted."""
    lead, ev = _setup(h)
    old_signer = h.signer
    assert old_signer is not None
    h.signer = CustodySigner(f"rotated-{uuid.uuid4().hex[:8]}", Ed25519PrivateKey.generate())
    try:
        report = _verify(h, lead, ev["id"])
        assert report["ok"] is False
        assert {code for _, code in _codes(report)} == {"untrusted_key"}
        assert report["chain"]["broken_seqs"] == [1, 2, 3, 4]
        h.trusted = {old_signer.key_id: old_signer.public_key}
        report = _verify(h, lead, ev["id"])
        # seq 5 (previous verification entry) was signed by the new signer: all trusted now.
        assert report["chain"]["ok"] is True, report["chain"]
    finally:
        h.signer = old_signer
        h.trusted = {}
