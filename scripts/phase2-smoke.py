#!/usr/bin/env python3
"""Phase 2 live smoke test against the running compose stack (real API, Redis and Celery worker).

    python scripts/phase2-smoke.py --admin-email E --admin-password P [--base http://127.0.0.1:8000]

1. an analyst uploads the auth.log and EVTX fixtures and submits parse jobs (auto-detect);
2. the worker (queue ``parse``) runs them: jobs end ``succeeded`` with run manifests whose record
   counts match the golden files, and signed ``processed`` custody entries; verify stays ok;
3. the timeline API returns the events (UTC + original timestamp) with filters and pagination;
4. reprocessing replaces the events without duplicates; a viewer cannot submit jobs (403).
Exits non-zero on the first failed expectation.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "backend" / "tests" / "fixtures"
_spec = importlib.util.spec_from_file_location("phase1_smoke", ROOT / "scripts" / "phase1-smoke.py")
assert _spec and _spec.loader
p1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p1)
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user


def stored(api: Any, token: str, cid: str, name: str, kind: str, data: bytes) -> str:
    status, body, _ = api.call(
        "POST",
        f"/cases/{cid}/evidence",
        token,
        {"kind": kind, "original_name": name, "acquired_at": "2026-01-03T00:00:00Z"},
    )
    expect(status == 201, f"create evidence {name}", body)
    eid = str(body["evidence"]["id"])
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", token, raw=data)
    expect(status == 200, f"upload {name}", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/finalize", token)
    expect(status == 200 and body["ok"], f"finalize {name}", body)
    return eid


def wait_job(api: Any, token: str, job_id: str, timeout: float = 180) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, body, _ = api.call("GET", f"/jobs/{job_id}", token)
        if status != 200:
            expect(False, "poll job", body)
        if body["status"] not in ("queued", "running"):
            return dict(body)
        time.sleep(1)
    expect(False, f"job {job_id} finished within {timeout}s", body)
    raise AssertionError


def timeline(api: Any, token: str, cid: str, query: str = "") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    cursor = ""
    while True:
        sep = "&" if query else ""
        status, body, _ = api.call(
            "GET", f"/cases/{cid}/events?limit=7{sep}{query}{cursor}", token
        )
        if status != 200:
            expect(False, "timeline page", body)
        items.extend(body["items"])
        if not body["next_cursor"]:
            return items
        cursor = f"&cursor={body['next_cursor']}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    args = parser.parse_args()
    api = Api(args.base)
    admin = login(api, args.admin_email, args.admin_password)
    _, lead = make_user(api, admin, "lead")
    analyst_id, analyst = make_user(api, admin, "analyst")
    viewer_id, viewer = make_user(api, admin, "viewer")

    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 2 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call(
            "POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role}
        )
        expect(status == 200, f"lead adds {role}", body)

    auth_id = stored(
        api, analyst, cid, "auth.log", "log", (FIXTURES / "linux" / "auth.log").read_bytes()
    )
    evtx_id = stored(
        api,
        analyst,
        cid,
        "Security.evtx",
        "evtx",
        (FIXTURES / "evtx" / "security_short_selected.evtx").read_bytes(),
    )
    status, body, _ = api.call("POST", f"/evidence/{auth_id}/process", viewer, {})
    expect(status == 403, "viewer cannot submit jobs (403)", body)

    jobs = {}
    for eid, parser_name in ((auth_id, "linux_auth"), (evtx_id, "evtx")):
        status, body, _ = api.call("POST", f"/evidence/{eid}/process", analyst, {})
        expect(status == 202 and body["jobs"][0]["parser"] == parser_name,
               f"auto-detected {parser_name} job queued", body)
        jobs[parser_name] = body["jobs"][0]["id"]

    expected = {"linux_auth": (24, 22), "evtx": (7, 7)}
    for parser_name, job_id in jobs.items():
        job = wait_job(api, analyst, job_id)
        counts = job["run_manifest"]["counts"] if job.get("run_manifest") else {}
        read, emitted = expected[parser_name]
        expect(job["status"] == "succeeded" and counts.get("records_read") == read
               and counts.get("events_emitted") == emitted and counts.get("inserted") == emitted,
               f"worker ran {parser_name}: {counts}", job)

    events = timeline(api, viewer, cid)
    expect(len(events) == 29 and len({e["id"] for e in events}) == 29,
           "timeline has 29 unique events (paged by 7)", len(events))
    first = events[0]
    expect(first["ts"].endswith("Z") and first["ts_original"], "UTC ts + original kept", first)
    failed = timeline(api, viewer, cid, "event_code=ssh_failed")
    expect(len(failed) == 3, "filter event_code=ssh_failed -> 3", len(failed))

    status, body, _ = api.call("POST", f"/jobs/{jobs['linux_auth']}/reprocess", analyst)
    expect(status == 202, "reprocess queued", body)
    job = wait_job(api, analyst, body["id"])
    expect(job["status"] == "succeeded" and job["run_manifest"]["replaced_previous_events"] == 22,
           "reprocess replaced 22 events", job)
    events = timeline(api, viewer, cid, f"evidence_id={auth_id}")
    expect(len(events) == 22 and {e["job_id"] for e in events} == {job["id"]},
           "no duplicates after reprocess", len(events))

    status, body, _ = api.call("GET", f"/evidence/{auth_id}/custody", analyst)
    processed = [e for e in body["entries"] if e["action"] == "processed"]
    expect(status == 200 and len(processed) == 2, "two signed 'processed' custody entries", body)
    status, body, _ = api.call("POST", f"/evidence/{auth_id}/verify", analyst)
    expect(status == 200 and body["ok"] is True, "custody chain + object still verify", body)
    print("PHASE 2 SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
