"""Phase 5: triage bundle ingest end to end (API -> BundleIngestService -> derived evidence ->
parse jobs -> timeline), hostile bundles, RBAC and grants. Fake vault; no broker."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from app.db.models import UserRole
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BUNDLES = FIXTURES / "bundles"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
EVTX = (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes()


@pytest.fixture
def analyst(h: Harness) -> UserCtx:
    return h.make_user(UserRole.analyst)


def _bundle(h: Harness, user: UserCtx, case_id: str, name: str = "good.zip") -> dict[str, Any]:
    data = (BUNDLES / name).read_bytes()
    return h.stored_evidence(
        user, case_id, data, kind="triage_bundle", original_name=name, source_host="web01"
    )


def _ingest(h: Harness, user: UserCtx, evidence_id: str) -> dict[str, Any]:
    r = h.post(f"/evidence/{evidence_id}/process", user, json={})
    assert r.status_code == 202, r.text
    [job] = r.json()["jobs"]
    assert job["kind"] == "bundle" and job["parser"] == "triage_bundle"
    return dict(job)


def _job(h: Harness, user: UserCtx, job_id: str) -> dict[str, Any]:
    r = h.get(f"/jobs/{job_id}", user)
    assert r.status_code == 200, r.text
    return dict(r.json())


def _custody(h: Harness, user: UserCtx, evidence_id: str) -> list[dict[str, Any]]:
    return list(h.get(f"/evidence/{evidence_id}/custody", user).json()["entries"])


def _evidence(h: Harness, user: UserCtx, case_id: str) -> list[dict[str, Any]]:
    return list(h.get(f"/cases/{case_id}/evidence", user).json()["items"])


def _notifications(db_engine: Engine, kind: str) -> list[dict[str, Any]]:
    with db_engine.connect() as conn:
        rows = conn.execute(
            text("SELECT payload FROM notifications WHERE kind = :k"), {"k": kind}
        ).scalars()
        return [dict(r) for r in rows]


def test_bundle_ingest_end_to_end(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    bundle = _bundle(h, analyst, case["id"])
    job = _ingest(h, analyst, bundle["id"])
    assert h.bundle_dispatched == [uuid.UUID(job["id"])] and h.dispatched == []
    # Idempotent: the same request returns the existing job.
    again = h.post(f"/evidence/{bundle['id']}/process", analyst, json={}).json()
    assert again["jobs"][0]["id"] == job["id"] and again["created"] == []

    [result] = h.run_bundle_pending()
    assert result.outcome == "succeeded", result
    detail = _job(h, analyst, job["id"])
    manifest = detail["run_manifest"]
    assert detail["status"] == "succeeded" and detail["progress"] == 1.0
    assert manifest["counts"]["ingested"] == 2 and manifest["counts"]["verified"] == 1
    assert manifest["counts"]["members"] == 3 and manifest["counts"]["flagged"] == 0
    assert manifest["evidence_sha256"] == bundle["sha256"]
    assert manifest["bundle"]["collector"]["name"] == "dfirbench-collect-linux"
    assert manifest["bundle"]["collector_trust"]["status"] == "unknown"
    assert manifest["bundle"]["collector_errors"] == 1
    zip_manifest = __import__("zipfile").ZipFile(BUNDLES / "good.zip").read("manifest.json")
    assert manifest["bundle"]["manifest_sha256"] == hashlib.sha256(zip_manifest).hexdigest()

    items = {e["id"]: e for e in _evidence(h, analyst, case["id"])}
    derived = [e for e in items.values() if e["parent_evidence_id"] == bundle["id"]]
    assert sorted((e["kind"], e["original_name"]) for e in derived) == [
        ("evtx", "logs/Security.evtx"),
        ("log", "logs/var/log/auth.log"),
    ]
    auth = next(e for e in derived if e["kind"] == "log")
    assert auth["status"] == "stored" and auth["sha256"] == hashlib.sha256(AUTH_LOG).hexdigest()
    assert auth["expected_sha256"] == auth["sha256"] and auth["label"].startswith(bundle["label"])
    assert auth["source_host"] == "web01" and auth["acquired_at"].startswith("2026-01-03")
    assert (
        auth["storage_uri"]
        .split("/", 3)[3]
        .startswith(f"{case['id']}/{bundle['id']}/derived/{auth['id']}/")
    )

    chain = _custody(h, analyst, auth["id"])
    assert [e["action"] for e in chain] == ["created", "ingested", "hash_verified", "locked"]
    provenance = chain[0]["detail"]["derived_from"]
    assert provenance["evidence_id"] == bundle["id"] and provenance["sha256"] == bundle["sha256"]
    assert provenance["member_path"] == "logs/var/log/auth.log"
    r = h.post(f"/evidence/{auth['id']}/verify", analyst)
    assert r.status_code == 200 and r.json()["ok"] is True, r.json()
    processed = _custody(h, analyst, bundle["id"])[-1]
    assert processed["action"] == "processed" and processed["detail"]["kind"] == "bundle"
    assert processed["detail"]["counts"]["ingested"] == 2
    assert sorted(processed["detail"]["derived_evidence_ids"]) == sorted(e["id"] for e in derived)

    summary = h.get(f"/evidence/{bundle['id']}/bundle", analyst).json()
    statuses = {m["member_path"]: m["status"] for m in summary["members"]}
    assert statuses == {
        "logs/var/log/auth.log": "ingested",
        "logs/Security.evtx": "ingested",
        "volatile/processes.json": "verified",
    }
    assert summary["outcome"] == "succeeded" and len(summary["derived"]) == 2

    # The derived items go through the ordinary parse pipeline.
    assert len(h.dispatched) == 2
    results = h.run_pending()
    assert sorted(r.outcome for r in results) == ["succeeded", "succeeded"]
    events = h.get(
        f"/cases/{case['id']}/events", analyst, params={"evidence_id": auth["id"], "limit": 500}
    ).json()["items"]
    assert len(events) == 22 and {e["source_file"] for e in events} == {"auth.log"}
    parse_jobs = [
        j
        for j in h.get(f"/cases/{case['id']}/jobs", analyst).json()["items"]
        if j["kind"] == "parse"
    ]
    assert {j["evidence_id"] for j in parse_jobs} == {e["id"] for e in derived}
    assert all(j["created_by"] == str(analyst.id) for j in parse_jobs)

    # Reprocessing the bundle re-verifies it and reuses the derived items (no duplicates).
    r = h.post(f"/jobs/{job['id']}/reprocess", analyst)
    assert r.status_code == 202, r.text
    [rerun] = h.run_bundle_pending()
    assert rerun.outcome == "succeeded" and rerun.counts["derived_new"] == 0
    assert len(_evidence(h, analyst, case["id"])) == 3 and h.dispatched == []


def test_manifest_mismatch_quarantines_members(
    h: Harness, analyst: UserCtx, db_engine: Engine
) -> None:
    h.make_user(UserRole.admin, login=False)
    case = h.create_case(analyst)
    bundle = _bundle(h, analyst, case["id"], "mismatch.zip")
    job = _ingest(h, analyst, bundle["id"])
    [result] = h.run_bundle_pending()
    assert result.outcome == "partial"
    detail = _job(h, analyst, job["id"])
    assert detail["status"] == "partial" and "quarantined" in detail["error"]
    flagged = {f["path"]: f["status"] for f in detail["run_manifest"]["flagged"]}
    assert flagged == {
        "logs/Security.evtx": "hash_mismatch",
        "files/unlisted.txt": "unlisted",
        "logs/var/log/missing.log": "missing",
    }
    derived = [
        e for e in _evidence(h, analyst, case["id"]) if e["parent_evidence_id"] == bundle["id"]
    ]
    assert [e["original_name"] for e in derived] == ["logs/var/log/auth.log"]
    summary = h.get(f"/evidence/{bundle['id']}/bundle", analyst).json()
    evtx = next(m for m in summary["members"] if m["member_path"] == "logs/Security.evtx")
    assert evtx["sha256_manifest"] == "f" * 64
    assert evtx["sha256_actual"] == hashlib.sha256(EVTX).hexdigest()
    assert evtx["derived_evidence_id"] is None
    processed = _custody(h, analyst, bundle["id"])[-1]["detail"]
    assert processed["outcome"] == "partial" and len(processed["flagged"]) == 3
    [note] = _notifications(db_engine, "evidence.bundle_manifest_mismatch")[-1:]
    assert note["evidence_id"] == bundle["id"] and note["count"] == 3
    # The bundle itself is untouched and still verifies.
    assert h.post(f"/evidence/{bundle['id']}/verify", analyst).json()["ok"] is True


@pytest.mark.parametrize(
    ("fixture", "code"),
    [
        ("traversal_dotdot.zip", "unsafe_name"),
        ("traversal_backslash.zip", "unsafe_name"),
        ("symlink.zip", "symlink"),
        ("bomb_ratio.zip", "compression_ratio"),
        ("overlap.zip", "overlapping_entries"),
        ("bad_manifest.zip", "manifest_invalid"),
    ],
)
def test_hostile_bundles_are_rejected(
    h: Harness, analyst: UserCtx, db_engine: Engine, fixture: str, code: str
) -> None:
    h.make_user(UserRole.admin, login=False)
    case = h.create_case(analyst)
    bundle = _bundle(h, analyst, case["id"], fixture)
    job = _ingest(h, analyst, bundle["id"])
    [result] = h.run_bundle_pending()
    assert result.outcome == "failed"
    detail = _job(h, analyst, job["id"])
    assert detail["error"].startswith("bundle rejected") and code in detail["error"]
    assert any(r["code"] == code for r in detail["run_manifest"]["rejected"])
    assert [e["id"] for e in _evidence(h, analyst, case["id"])] == [bundle["id"]]
    assert h.dispatched == []
    processed = _custody(h, analyst, bundle["id"])[-1]
    assert processed["action"] == "processed" and code in processed["detail"]["rejected"]
    assert any(
        n["evidence_id"] == bundle["id"]
        for n in _notifications(db_engine, "evidence.bundle_rejected")
    )
    with db_engine.connect() as conn:
        rows = conn.execute(
            text("SELECT count(*) FROM bundle_members WHERE bundle_evidence_id = :b"),
            {"b": bundle["id"]},
        ).scalar_one()
    assert rows == 0


def test_tampered_bundle_fails_integrity_before_reading(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    bundle = _bundle(h, analyst, case["id"])
    job = _ingest(h, analyst, bundle["id"])
    h.vault.corrupt(h.key_of(bundle), bundle["storage_version_id"], offset=100)  # type: ignore[union-attr]
    [result] = h.run_bundle_pending()
    assert result.outcome == "failed"
    assert "integrity" in _job(h, analyst, job["id"])["error"]
    assert [e["action"] for e in _custody(h, analyst, bundle["id"])][-1] == "hash_failed"
    assert len(_evidence(h, analyst, case["id"])) == 1


def test_derived_cap_and_validation(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    bundle = _bundle(h, analyst, case["id"])
    url = f"/evidence/{bundle['id']}/process"
    r = h.post(url, analyst, json={"params": {"timezone": "UTC"}})
    assert r.status_code == 422
    job = _ingest(h, analyst, bundle["id"])
    assert h.post(f"/jobs/{job['id']}/reprocess", analyst).status_code == 409  # still queued
    h.bundle_dispatched.clear()
    result = h.bundles(bundle_max_derived=1).run(uuid.UUID(job["id"]))
    assert result.outcome == "succeeded"
    summary = h.get(f"/evidence/{bundle['id']}/bundle", analyst).json()
    capped = [m for m in summary["members"] if m["detail"].get("not_derived") == "cap"]
    assert len(summary["derived"]) == 1 and len(capped) == 1


def test_closed_case_and_rbac(h: Harness, db_engine: Engine) -> None:
    lead = h.make_user(UserRole.lead)
    viewer = h.make_user(UserRole.viewer)
    outsider = h.make_user(UserRole.analyst)
    case = h.create_case(lead)
    h.add_member(lead, case["id"], viewer, UserRole.viewer)
    bundle = _bundle(h, lead, case["id"])
    assert h.post(f"/evidence/{bundle['id']}/process", viewer, json={}).status_code == 403
    assert h.get(f"/evidence/{bundle['id']}/bundle", outsider).status_code == 404
    assert h.get(f"/evidence/{bundle['id']}/bundle", viewer).json()["job"] is None
    job = _ingest(h, lead, bundle["id"])
    with db_engine.begin() as conn:  # closed behind the service's back (close refuses active jobs)
        conn.execute(text("UPDATE cases SET status = 'closed' WHERE id = :c"), {"c": case["id"]})
    [result] = h.run_bundle_pending()
    assert result.outcome == "failed"
    assert "closed" in _job(h, lead, job["id"])["error"]
    assert len(_evidence(h, lead, case["id"])) == 1


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE bundle_members SET status = 'verified'",
        "DELETE FROM bundle_members",
        "TRUNCATE bundle_members",
        "UPDATE evidence SET parent_evidence_id = NULL",
        "UPDATE evidence SET case_id = case_id",
        "UPDATE evidence SET storage_uri = 'x'",
        "UPDATE evidence SET label = 'x'",
        "DELETE FROM evidence",
    ],
)
def test_grants_deny_app_role(app_engine: Engine, statement: str) -> None:
    with pytest.raises(DBAPIError, match=r"permission denied|append-only"), app_engine.begin() as c:
        c.execute(text(statement))


def test_grants_keep_the_upload_flow_working(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        conn.execute(text("UPDATE evidence SET status = status, sha256 = sha256 WHERE false"))
        conn.execute(text("SELECT id FROM evidence LIMIT 1 FOR UPDATE"))
