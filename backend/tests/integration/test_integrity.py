"""Phase 10: read-only integrity check and signed state manifests (backup/restore verification).

Runs on its own throwaway database, because the check covers every evidence item and other test
modules tamper with theirs on purpose.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import Engine, create_engine, text

from app.core.signing import CustodySigner
from app.db.models import UserRole
from app.db.session import make_engine
from app.services.integrity import IntegrityChecker, ManifestError, build_manifest, verify_manifest
from tests.fakes import FakeVault
from tests.integration.conftest import (
    APP_ROLE,
    alembic_config,
    create_temp_database,
    drop_temp_database,
    make_test_settings,
)
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

DATA = b"Jan  1 00:00:01 host sshd[1]: Accepted password for root from 192.0.2.1\n"


@pytest.fixture(scope="module")
def fresh_db(admin_engine: Engine) -> Iterator[str]:
    from alembic import command

    url = create_temp_database(admin_engine)
    try:
        command.upgrade(alembic_config(url), "head")
        yield url
    finally:
        drop_temp_database(admin_engine, url)


@pytest.fixture(scope="module")
def module_vault() -> FakeVault:
    return FakeVault()  # one vault for the module's database (objects of every test)


@pytest.fixture
def world(
    fresh_db: str, signer: CustodySigner, module_vault: FakeVault
) -> Iterator[dict[str, Any]]:
    """A harness on the fresh database plus an owner engine for tampering."""
    app_engine = make_engine(fresh_db, role=APP_ROLE)
    owner = create_engine(fresh_db)
    vault = module_vault
    h = Harness(app_engine, make_test_settings(fresh_db), signer, vault)
    with h.client:
        yield {"h": h, "owner": owner, "vault": vault}
    app_engine.dispose()
    owner.dispose()


def _evidence(h: Harness, user: UserCtx) -> dict[str, Any]:
    case = h.create_case(user, "Integrity")
    return h.stored_evidence(user, case["id"], DATA, original_name="auth.log")


def _check(world: dict[str, Any], signer: CustodySigner, manifest: Any = None) -> dict[str, Any]:
    h: Harness = world["h"]
    with h.sessions() as session:
        report = IntegrityChecker(session, world["vault"], {signer.key_id: signer.public_key})
        return report.check(manifest).as_dict()


def _codes(result: dict[str, Any]) -> set[str]:
    return {p["code"] for p in result["problems"]}


def _custody_rows(owner: Engine) -> int:
    with owner.connect() as conn:
        return int(conn.execute(text("SELECT count(*) FROM custody_log")).scalar_one())


def test_clean_platform_passes_and_nothing_is_written(
    world: dict[str, Any], signer: CustodySigner
) -> None:
    h: Harness = world["h"]
    user = h.make_user(UserRole.analyst)
    _evidence(h, user)
    before = _custody_rows(world["owner"])
    result = _check(world, signer)
    assert result["ok"], result["problems"]
    assert result["objects_hashed"] >= 1 and result["bytes_hashed"] >= len(DATA)
    assert _custody_rows(world["owner"]) == before  # read-only: no hash_verified entries


def test_flipped_byte_and_edited_custody_row_are_found(
    world: dict[str, Any], signer: CustodySigner
) -> None:
    h: Harness = world["h"]
    user = h.make_user(UserRole.analyst)
    ev = _evidence(h, user)
    assert _check(world, signer)["ok"]
    world["vault"].corrupt(h.key_of(ev))
    result = _check(world, signer)
    assert _codes(result) == {"hash_mismatch"}
    assert all(p.get("evidence_id") == ev["id"] for p in result["problems"])
    with world["owner"].begin() as conn:  # owner bypasses the append-only trigger
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "UPDATE custody_log SET actor_label = 'someone else' "
                "WHERE evidence_id = :e AND seq = 1"
            ),
            {"e": ev["id"]},
        )
    assert "chain_broken" in _codes(_check(world, signer))


def test_untrusted_keys_fail_every_chain(world: dict[str, Any], signer: CustodySigner) -> None:
    h: Harness = world["h"]
    _evidence(h, h.make_user(UserRole.analyst))
    other = Ed25519PrivateKey.generate().public_key()
    with h.sessions() as session:
        result = IntegrityChecker(session, world["vault"], {signer.key_id: other}).check()
    assert "chain_broken" in {p.code for p in result.problems}
    with h.sessions() as session:
        empty = IntegrityChecker(session, world["vault"], {}).check()
    assert [p.code for p in empty.problems] == ["no_trusted_keys"]


def test_manifest_round_trip_and_tail_truncation(
    world: dict[str, Any], signer: CustodySigner
) -> None:
    h: Harness = world["h"]
    with world["owner"].begin() as conn:  # earlier tests in this module tampered on purpose
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        for table in ("custody_log", "events", "jobs", "bundle_members", "evidence", "cases"):
            conn.execute(text(f"DELETE FROM {table}"))  # fixed names, owner, test DB
    user = h.make_user(UserRole.analyst)
    ev = _evidence(h, user)
    with h.sessions() as session:
        document = json.loads(json.dumps(build_manifest(session, signer)))
    assert verify_manifest(document, {signer.key_id: signer.public_key})["evidence"]
    assert _check(world, signer, document)["ok"]

    # A later custody entry: chain still valid, but the head moved and counts changed.
    r = h.post(f"/evidence/{ev['id']}/verify", user)
    assert r.status_code == 200, r.text
    codes = _codes(_check(world, signer, document))
    assert {"chain_head_mismatch", "count_mismatch"} <= codes

    # Tail truncation (delete the newest entries): the chain alone still verifies, the manifest
    # head does not.
    with world["owner"].begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "DELETE FROM custody_log WHERE evidence_id = :e AND seq = "
                "(SELECT max(seq) FROM custody_log WHERE evidence_id = :e)"
            ),
            {"e": ev["id"]},
        )
        conn.execute(
            text(
                "DELETE FROM custody_log WHERE evidence_id = :e AND seq = "
                "(SELECT max(seq) FROM custody_log WHERE evidence_id = :e)"
            ),
            {"e": ev["id"]},
        )
    truncated = _check(world, signer, document)
    assert "chain_broken" not in _codes(truncated)
    assert "chain_head_mismatch" in _codes(truncated)


def test_tampered_or_foreign_manifests_are_refused(
    world: dict[str, Any], signer: CustodySigner
) -> None:
    h: Harness = world["h"]
    with h.sessions() as session:
        document = json.loads(json.dumps(build_manifest(session, signer)))
    keys = {signer.key_id: signer.public_key}
    bad = json.loads(json.dumps(document))
    bad["manifest"]["counts"]["evidence"] += 1
    with pytest.raises(ManifestError, match="hash"):
        verify_manifest(bad, keys)
    bad = json.loads(json.dumps(document))
    bad["signature"]["value"] = "00" * 64
    with pytest.raises(ManifestError, match="signature"):
        verify_manifest(bad, keys)
    with pytest.raises(ManifestError, match="untrusted"):
        verify_manifest(document, {"other-key": signer.public_key})
    with pytest.raises(ManifestError):
        verify_manifest({"manifest": [], "signature": {}}, keys)
    foreign = CustodySigner(key_id=signer.key_id, private_key=Ed25519PrivateKey.generate())
    with h.sessions() as session:
        forged = build_manifest(session, foreign)
    assert [p["code"] for p in _check(world, signer, forged)["problems"]] == ["manifest_invalid"]
