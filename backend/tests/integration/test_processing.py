"""Phase 2: parse jobs end to end (API -> ProcessingService -> events -> timeline API).

The Celery broker is not involved: the harness records dispatched job ids and the tests run
``ProcessingService`` directly (what the ``dfirbench.parse_evidence`` task does in a worker).
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.core.exceptions import AppError
from app.core.permissions import Principal
from app.db.models import UserRole
from app.services.audit import RequestMeta
from app.services.custody import canonical
from app.services.jobs import JobService
from app.services.processing import EventSink, JobFencedError, ProcessingService
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
EVTX = (FIXTURES / "evtx" / "security_short_selected.evtx").read_bytes()
AUTH_COUNTS = {"records_read": 24, "events_emitted": 22, "skipped": 1, "errors": 1}
META = RequestMeta(ip="198.51.100.9")


# ---------------------------------------------------------------------------------- helpers


def _auth_evidence(h: Harness, user: UserCtx, case_id: str, **fields: Any) -> dict[str, Any]:
    fields.setdefault("acquired_at", "2026-01-03T00:00:00Z")
    return h.stored_evidence(user, case_id, AUTH_LOG, original_name="auth.log", **fields)


def _process(h: Harness, user: UserCtx, evidence_id: str, **body: Any) -> dict[str, Any]:
    r = h.post(f"/evidence/{evidence_id}/process", user, json=body)
    assert r.status_code == 202, r.text
    return dict(r.json())


def _job(h: Harness, user: UserCtx, job_id: str) -> dict[str, Any]:
    r = h.get(f"/jobs/{job_id}", user)
    assert r.status_code == 200, r.text
    return dict(r.json())


def _timeline(h: Harness, user: UserCtx, case_id: str, **params: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = None
    while True:
        query = dict(params, limit=params.get("limit", 500))
        if cursor:
            query["cursor"] = cursor
        r = h.get(f"/cases/{case_id}/events", user, params=query)
        assert r.status_code == 200, r.text
        body = r.json()
        items.extend(body["items"])
        cursor = body["next_cursor"]
        if not cursor:
            return items


def _event_rows(db_engine: Engine, evidence_id: str) -> list[Any]:
    with db_engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT id, job_id, ts, tableoid::regclass::text AS part FROM events "
                    "WHERE evidence_id = :e ORDER BY ts, id"
                ),
                {"e": evidence_id},
            )
        )


def _principal(user: UserCtx) -> Principal:
    return Principal(user.id, user.email, "Test", user.role)


def _parallel(n: int, fn: Callable[[int], Any]) -> list[Any]:
    barrier = threading.Barrier(n)

    def run(i: int) -> Any:
        barrier.wait()
        try:
            return fn(i)
        except AppError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(run, range(n)))


@pytest.fixture
def analyst(h: Harness) -> UserCtx:
    return h.make_user(UserRole.analyst)


# ---------------------------------------------------------------------------------- lifecycle


def test_auth_log_job_end_to_end(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"], source_host="web01")
    out = _process(h, analyst, ev["id"])  # parsers: auto
    assert len(out["jobs"]) == 1 and out["created"] == [out["jobs"][0]["id"]]
    job = out["jobs"][0]
    assert job["parser"] == "linux_auth" and job["status"] == "queued"
    assert job["params"] == {"timezone": "UTC"}
    assert h.dispatched == [uuid.UUID(job["id"])]

    [result] = h.run_pending()
    assert result.outcome == "succeeded", result
    detail = _job(h, analyst, job["id"])
    assert detail["status"] == "succeeded" and detail["progress"] == 1.0
    assert detail["attempts"] == 1 and detail["finished_at"]
    manifest = detail["run_manifest"]
    assert detail["counts"]["records_read"] == 24
    for key, value in AUTH_COUNTS.items():
        assert manifest["counts"][key] == value
    assert manifest["counts"]["inserted"] == 22
    assert manifest["evidence_sha256"] == hashlib.sha256(AUTH_LOG).hexdigest()
    assert manifest["evidence_size"] == len(AUTH_LOG)
    assert manifest["parser"] == "linux_auth" and manifest["parser_version"] == "1.0.0"
    assert manifest["tools"]["python"] and manifest["tools"]["tzdata"]
    assert manifest["assumptions"]["timezone"] == "UTC"
    assert manifest["assumptions"]["year_source"] == "acquired_at"
    assert manifest["assumptions"]["year_rollovers"] == 1
    assert manifest["error_samples"][0]["reason"] == "unrecognized_format"
    assert manifest["outcome"] == "succeeded"

    # Signed custody entry that pins the manifest.
    custody = h.get(f"/evidence/{ev['id']}/custody", analyst).json()
    entries = custody["entries"] if isinstance(custody, dict) else custody
    processed = [e for e in entries if e["action"] == "processed"]
    assert len(processed) == 1
    assert (
        processed[0]["detail"]["manifest_sha256"] == hashlib.sha256(canonical(manifest)).hexdigest()
    )
    assert processed[0]["detail"]["events_emitted"] == 22
    assert h.post(f"/evidence/{ev['id']}/verify", analyst).json()["ok"] is True

    # Timeline: UTC timestamps with the original strings, stable ascending order.
    events = _timeline(h, analyst, case["id"])
    assert len(events) == 22
    assert [e["ts"] for e in events] == sorted(e["ts"] for e in events)
    first = events[0]
    assert first["ts"].startswith("2025-12-30T23:58:01") and first["ts"].endswith("Z")
    assert first["ts_original"] == "Dec 30 23:58:01"
    assert first["host"] == "web01" and first["parser_name"] == "linux_auth"
    assert first["job_id"] == job["id"] and first["evidence_id"] == ev["id"]
    iso = next(e for e in events if e["ts_original"].startswith("2026-01-02T09:22:00"))
    assert iso["ts"].startswith("2026-01-02T03:52:00")  # +05:30 converted to UTC

    # Rows went to monthly partitions, not the DEFAULT partition.
    parts = {row.part for row in _event_rows(db_engine, ev["id"])}
    assert parts == {"events_y2025m12", "events_y2026m01"}


def test_timeline_filters_pagination_and_detail(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    _process(h, analyst, ev["id"], parsers=["linux_auth"])
    h.run_pending()
    cid = case["id"]

    failed = _timeline(h, analyst, cid, event_code="ssh_failed")
    assert len(failed) == 3 and all(e["outcome"] == "failure" for e in failed)
    by_ip = _timeline(h, analyst, cid, ip="203.0.113.50")
    assert by_ip and all(e["src_ip"] == "203.0.113.50" for e in by_ip)
    assert {e["user"] for e in _timeline(h, analyst, cid, q="backdoor")} >= {"backdoor"}
    window = _timeline(
        h, analyst, cid, **{"from": "2026-01-02T09:15:00Z", "to": "2026-01-02T09:16:00Z"}
    )
    assert len(window) == 4
    auth = _timeline(h, analyst, cid, source_type="auth_log")
    assert 0 < len(auth) < 22

    # Keyset pagination (both orders) returns every event exactly once.
    all_asc = _timeline(h, analyst, cid)
    paged = _timeline(h, analyst, cid, limit=5)
    assert [e["id"] for e in paged] == [e["id"] for e in all_asc]
    desc = _timeline(h, analyst, cid, limit=4, order="desc")
    assert [e["id"] for e in desc] == [e["id"] for e in reversed(all_asc)]
    r = h.get(f"/cases/{cid}/events", analyst, params={"limit": 5})
    cursor = r.json()["next_cursor"]
    assert (
        h.get(
            f"/cases/{cid}/events", analyst, params={"cursor": cursor, "order": "desc"}
        ).status_code
        == 422
    )
    assert h.get(f"/cases/{cid}/events", analyst, params={"cursor": "bm9wZQ"}).status_code == 422
    assert (
        h.get(f"/cases/{cid}/events", analyst, params={"from": "2026-01-01T00:00:00"}).status_code
        == 422
    )
    assert h.get(f"/cases/{cid}/events", analyst, params={"ip": "not-an-ip"}).status_code == 422
    assert h.get(f"/cases/{cid}/events", analyst, params={"limit": 501}).status_code == 422

    [ssh] = [e for e in all_asc if e["source_record_id"] == "1"]  # line 1
    detail = h.get(f"/cases/{cid}/events/{ssh['id']}", analyst)
    assert detail.status_code == 200
    raw = detail.json()["raw"]
    assert raw["line"].startswith("Dec 30 23:58:01 web01 sshd[1021]: Accepted publickey")
    assert raw["line_no"] == 1 and raw["format"] == "bsd"


def test_evtx_job(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = h.stored_evidence(analyst, case["id"], EVTX, kind="evtx", original_name="Security.evtx")
    out = _process(h, analyst, ev["id"])
    assert out["jobs"][0]["parser"] == "evtx" and out["jobs"][0]["params"] == {}
    [result] = h.run_pending()
    assert result.outcome == "succeeded"
    manifest = _job(h, analyst, out["jobs"][0]["id"])["run_manifest"]
    assert manifest["counts"]["records_read"] == 7 and manifest["counts"]["events_emitted"] == 7
    assert manifest["tools"]["python-evtx"] == "0.8.1"
    events = _timeline(h, analyst, case["id"])
    assert len(events) == 7 and {e["host"] for e in events} == {"temporal"}
    [logon] = [e for e in events if e["event_code"] == "4625"]
    assert logon["action"] == "logon" and logon["outcome"] == "failure"
    assert logon["message"].startswith("Failed logon for")
    assert logon["ts_original"] and logon["source_file"] == "Security.evtx"
    raw = h.get(f"/cases/{case['id']}/events/{logon['id']}", analyst).json()["raw"]
    assert raw["system"]["event_id"] == "4625" and raw["xml"].startswith("<Event")


# ---------------------------------------------------------------------------------- idempotency


def test_idempotent_submit_and_reprocess(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    first = _process(h, analyst, ev["id"], parsers=["linux_auth"])["jobs"][0]
    again = _process(h, analyst, ev["id"], parsers=["linux_auth"], params={"timezone": "UTC"})
    assert again["created"] == [] and again["jobs"][0]["id"] == first["id"]
    # While queued, a different submission for the same pair conflicts (no interleaving runs).
    r = h.post(
        f"/evidence/{ev['id']}/process",
        analyst,
        json={"parsers": ["linux_auth"], "params": {"timezone": "Asia/Kolkata"}},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "job_active"
    h.run_pending()
    before = _event_rows(db_engine, ev["id"])
    assert len(before) == 22
    # Submitting the finished job's parameters again still returns it (no new run).
    assert _process(h, analyst, ev["id"], parsers=["linux_auth"])["created"] == []

    r = h.post(f"/jobs/{first['id']}/reprocess", analyst)
    assert r.status_code == 202, r.text
    second = r.json()
    assert second["id"] != first["id"] and second["status"] == "queued"
    assert _job(h, analyst, first["id"])["superseded_by"] == second["id"]
    h.run_pending()
    after = _event_rows(db_engine, ev["id"])
    assert [row.id for row in after] == [row.id for row in before]  # same deterministic ids
    assert {str(row.job_id) for row in after} == {second["id"]}
    manifest = _job(h, analyst, second["id"])["run_manifest"]
    assert manifest["replaced_previous_events"] == 22
    # The first run's manifest is kept as provenance and it can no longer be retried.
    assert _job(h, analyst, first["id"])["run_manifest"]["counts"]["events_emitted"] == 22
    assert h.post(f"/jobs/{first['id']}/retry", analyst).status_code == 409

    # New parameters: another run replaces the events; timestamps move, nothing duplicates.
    third = _process(
        h, analyst, ev["id"], parsers=["linux_auth"], params={"timezone": "Asia/Kolkata"}
    )["jobs"][0]
    assert third["id"] not in (first["id"], second["id"])
    h.run_pending()
    shifted = _event_rows(db_engine, ev["id"])
    assert len(shifted) == 22
    events = _timeline(h, analyst, case["id"])
    first_event = events[0]
    assert first_event["ts"].startswith("2025-12-30T18:28:01")  # 23:58:01 +05:30
    assert first_event["ts_original"] == "Dec 30 23:58:01"
    assert _job(h, analyst, second["id"])["superseded_by"] == third["id"]


def test_concurrent_submissions_create_one_job(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    principal = _principal(analyst)

    def submit(_: int) -> Any:
        with h.sessions() as session:
            svc = JobService(session, h.settings, vault=h.vault, dispatcher=None)  # type: ignore[arg-type]
            [res] = svc.submit(
                principal, uuid.UUID(ev["id"]), parsers=["linux_auth"], params={}, meta=META
            )
            return (str(res.job.id), res.created)

    results = _parallel(8, submit)
    assert len({r[0] for r in results}) == 1
    assert sum(1 for r in results if r[1]) == 1


def test_concurrent_workers_run_a_job_once(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    job = _process(h, analyst, ev["id"])["jobs"][0]
    outcomes = _parallel(6, lambda _: h.run_job(job["id"]).outcome)
    assert outcomes.count("succeeded") == 1
    assert set(outcomes) <= {"succeeded", "skipped", "busy"}
    assert len(_event_rows(db_engine, ev["id"])) == 22
    assert _job(h, analyst, job["id"])["attempts"] == 1


# ---------------------------------------------------------------------------------- control


def test_cancel_retry_and_fencing(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    job = _process(h, analyst, ev["id"])["jobs"][0]
    r = h.post(f"/jobs/{job['id']}/cancel", analyst)
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    assert h.run_job(job["id"]).outcome == "skipped"  # a cancelled job is never claimed
    assert h.post(f"/jobs/{job['id']}/cancel", analyst).status_code == 409

    # Retry, then cancel while the worker is running: the batch after the cancel is not written
    # and the job is not flipped back to succeeded.
    assert h.post(f"/jobs/{job['id']}/retry", analyst).status_code == 202
    h.dispatched.clear()
    svc = h.processing(ingest_batch_size=5)
    original_flush = EventSink.flush
    calls = {"n": 0}

    def flush_then_cancel(sink: EventSink) -> None:
        original_flush(sink)
        calls["n"] += 1
        if calls["n"] == 1:
            assert h.post(f"/jobs/{job['id']}/cancel", analyst).status_code == 200

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(EventSink, "flush", flush_then_cancel)
        result = svc.run(uuid.UUID(job["id"]))
    assert result.outcome == "cancelled"
    detail = _job(h, analyst, job["id"])
    assert detail["status"] == "cancelled" and detail["attempts"] == 1
    assert detail["run_manifest"]["outcome"] == "cancelled"
    assert len(_event_rows(db_engine, ev["id"])) == 5  # only the batch before the cancel

    # Retry completes and replaces the partial output without duplicates.
    assert h.post(f"/jobs/{job['id']}/retry", analyst).status_code == 202
    [again] = h.run_pending()
    assert again.outcome == "succeeded"
    assert len(_event_rows(db_engine, ev["id"])) == 22
    assert h.post(f"/jobs/{job['id']}/retry", analyst).status_code == 409  # succeeded

    # A worker whose lease was taken over can no longer write (fencing token).
    with db_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE jobs SET status = 'running', attempts = attempts + 1, "
                "heartbeat_at = now() WHERE id = :j"
            ),
            {"j": job["id"]},
        )
    assert h.run_job(job["id"]).outcome == "busy"  # live lease held by "another worker"
    with h.sessions() as session, pytest.raises(JobFencedError):
        ProcessingService.lock_running(session, uuid.UUID(job["id"]), token=2)
    # Lease expired (worker crashed): the job is reclaimed and completed.
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE jobs SET heartbeat_at = now() - interval '2 hours' WHERE id = :j"),
            {"j": job["id"]},
        )
    reclaimed = h.run_job(job["id"])
    assert reclaimed.outcome == "succeeded"
    assert _job(h, analyst, job["id"])["attempts"] == 4
    assert len(_event_rows(db_engine, ev["id"])) == 22


def test_dispatch_failure_marks_job_failed(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    h.dispatch_error = ConnectionError("broker down")
    r = h.post(f"/evidence/{ev['id']}/process", analyst, json={})
    assert r.status_code == 503 and r.json()["error"]["code"] == "queue_unavailable"
    job_id = r.json()["error"]["details"]["job_id"]
    assert _job(h, analyst, job_id)["status"] == "failed"
    h.dispatch_error = None
    assert h.post(f"/jobs/{job_id}/retry", analyst).status_code == 202
    assert [r.outcome for r in h.run_pending()] == ["succeeded"]


def test_integrity_mismatch_fails_the_job(h: Harness, analyst: UserCtx, db_engine: Engine) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    job = _process(h, analyst, ev["id"])["jobs"][0]
    h.vault.corrupt(h.key_of(ev), ev["storage_version_id"], offset=10)  # type: ignore[union-attr]
    [result] = h.run_pending()
    assert result.outcome == "failed"
    detail = _job(h, analyst, job["id"])
    assert detail["status"] == "failed" and "integrity" in detail["error"]
    assert "evidence_sha256" not in detail["run_manifest"]
    assert _event_rows(db_engine, ev["id"]) == []
    actions = [e["action"] for e in _custody(h, analyst, ev["id"])]
    assert actions[-1] == "hash_failed" and "processed" not in actions
    assert h.get(f"/evidence/{ev['id']}", analyst).json()["status"] == "failed"
    assert h.post(f"/jobs/{job['id']}/retry", analyst).status_code == 409  # not stored


def _custody(h: Harness, user: UserCtx, evidence_id: str) -> list[dict[str, Any]]:
    body = h.get(f"/evidence/{evidence_id}/custody", user).json()
    return list(body["entries"] if isinstance(body, dict) else body)


def test_closed_cases_accept_no_processing(h: Harness) -> None:
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead)
    ev = _auth_evidence(h, lead, case["id"])
    job = _process(h, lead, ev["id"])["jobs"][0]
    # A queued job blocks closing the case.
    r = h.post(f"/cases/{case['id']}/close", lead, json={"reason": "done"})
    assert r.status_code == 409 and job["id"] in r.json()["error"]["details"]["jobs"]
    h.run_pending()
    assert h.post(f"/cases/{case['id']}/close", lead, json={"reason": "done"}).status_code == 200
    r = h.post(f"/evidence/{ev['id']}/process", lead, json={"parsers": ["linux_auth"]})
    assert r.status_code == 409
    assert h.post(f"/jobs/{job['id']}/reprocess", lead).status_code == 409
    assert h.post(f"/jobs/{job['id']}/retry", lead).status_code == 409
    # Reading stays possible.
    assert len(_timeline(h, lead, case["id"])) == 22
    assert _job(h, lead, job["id"])["status"] == "succeeded"


def test_submission_validation(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    url = f"/evidence/{ev['id']}/process"
    assert h.post(url, analyst, json={"parsers": ["nope"]}).status_code == 422
    assert (
        h.post(url, analyst, json={"parsers": ["evtx"], "params": {"year": 2025}}).status_code
        == 422
    )
    bad_tz = {"parsers": ["linux_auth"], "params": {"timezone": "Mars/Olympus"}}
    assert h.post(url, analyst, json=bad_tz).status_code == 422
    assert h.post(url, analyst, json={"params": {"other": 1}}).status_code == 422
    pending = h.create_evidence(analyst, case["id"])  # never uploaded
    r = h.post(f"/evidence/{pending['id']}/process", analyst, json={})
    assert r.status_code == 409
    blob = h.stored_evidence(analyst, case["id"], b"\x00\x01binary blob\xff" * 50)
    r = h.post(f"/evidence/{blob['id']}/process", analyst, json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "no_parser"
    parsers = h.get("/parsers", analyst).json()
    assert {p["name"] for p in parsers} >= {"evtx", "linux_auth"}


# ---------------------------------------------------------------------------------- RBAC


def test_rbac_and_case_scoping(h: Harness) -> None:
    owner = h.make_user(UserRole.lead)
    viewer = h.make_user(UserRole.viewer)
    outsider = h.make_user(UserRole.analyst)
    case_a = h.create_case(owner, "Case A")
    h.add_member(owner, case_a["id"], viewer, UserRole.viewer)
    ev = _auth_evidence(h, owner, case_a["id"])
    job = _process(h, owner, ev["id"])["jobs"][0]
    h.run_pending()
    event_id = _timeline(h, owner, case_a["id"])[0]["id"]

    # Viewer: read-only.
    assert len(_timeline(h, viewer, case_a["id"])) == 22
    assert h.get(f"/jobs/{job['id']}", viewer).status_code == 200
    assert h.get(f"/cases/{case_a['id']}/jobs", viewer).status_code == 200
    assert h.post(f"/evidence/{ev['id']}/process", viewer, json={}).status_code == 403
    for action in ("cancel", "retry", "reprocess"):
        assert h.post(f"/jobs/{job['id']}/{action}", viewer).status_code == 403

    # Outsider: everything of case A is "not found", including via ids.
    case_b = h.create_case(outsider, "Case B")
    assert h.get(f"/cases/{case_a['id']}/events", outsider).status_code == 404
    assert h.get(f"/cases/{case_a['id']}/events/{event_id}", outsider).status_code == 404
    assert h.get(f"/cases/{case_a['id']}/jobs", outsider).status_code == 404
    assert h.get(f"/jobs/{job['id']}", outsider).status_code == 404
    for action in ("cancel", "retry", "reprocess"):
        assert h.post(f"/jobs/{job['id']}/{action}", outsider).status_code == 404
    assert h.post(f"/evidence/{ev['id']}/process", outsider, json={}).status_code == 404
    # An event id of case A under the outsider's own case B is not found either.
    assert h.get(f"/cases/{case_b['id']}/events/{event_id}", outsider).status_code == 404
    assert _timeline(h, outsider, case_b["id"]) == []
    assert h.get(f"/cases/{case_b['id']}/jobs", outsider).json()["items"] == []
    other = _timeline(h, outsider, case_b["id"], evidence_id=ev["id"], job_id=job["id"])
    assert other == []
    # Unauthenticated.
    assert h.get(f"/cases/{case_a['id']}/events").status_code == 401
    assert h.get("/parsers").status_code == 401


def test_job_list_filters(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev1 = _auth_evidence(h, analyst, case["id"])
    ev2 = h.stored_evidence(analyst, case["id"], EVTX, kind="evtx", original_name="S.evtx")
    j1 = _process(h, analyst, ev1["id"])["jobs"][0]
    _process(h, analyst, ev2["id"])
    h.run_job(j1["id"])
    items = h.get(f"/cases/{case['id']}/jobs", analyst).json()["items"]
    assert len(items) == 2
    queued = h.get(f"/cases/{case['id']}/jobs", analyst, params={"status": "queued"}).json()
    assert [j["parser"] for j in queued["items"]] == ["evtx"]
    by_ev = h.get(f"/cases/{case['id']}/jobs", analyst, params={"evidence_id": ev1["id"]}).json()
    assert [j["id"] for j in by_ev["items"]] == [j1["id"]]
    assert by_ev["items"][0]["counts"]["events_emitted"] == 22


def test_app_role_cannot_update_events_or_delete_jobs(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    ev = _auth_evidence(h, analyst, case["id"])
    job = _process(h, analyst, ev["id"])["jobs"][0]
    h.run_pending()
    for statement in (
        "UPDATE events SET message = 'x' WHERE evidence_id = :e",
        "DELETE FROM jobs WHERE evidence_id = :e",
        "TRUNCATE events",
        "DELETE FROM events_default",
        "SELECT count(*) FROM events_y2026m01",
    ):
        with h.sessions() as session, pytest.raises(Exception, match="permission denied"):
            session.execute(text(statement), {"e": ev["id"]})
    with h.sessions() as session:  # the app role reaches rows through the parent table only
        n = session.execute(
            text("SELECT count(*) FROM events WHERE job_id = :j"), {"j": job["id"]}
        ).scalar_one()
    assert n == 22
