#!/usr/bin/env python3
"""Phase 3 live smoke test against the running compose stack (real API, Redis, Celery worker).

    python scripts/phase3-smoke.py --admin-email E [--admin-password P] [--base URL]

1. an analyst uploads the auth.log and new_user_security.evtx fixtures and submits parse jobs;
2. when the parse jobs finish, the worker queues a detection run by itself (``detect`` queue);
   the expected built-in rules fire (user created, privileged group, record gap, clock/gap
   anti-forensics) with a run manifest citing rule versions;
3. alert lifecycle over the API: a viewer cannot change alerts (403), an analyst triages one;
4. an IOC is added and an on-demand detection run produces an IOC alert; re-running does not
   duplicate alerts. Exits non-zero on the first failed expectation.
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


def _load(name: str, file: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", "phase1-smoke.py")
p2 = _load("phase2_smoke", "phase2-smoke.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user
EXPECTED = {
    "DFIR-LNX-0004",
    "DFIR-LNX-0011",
    "DFIR-AF-0001",
    "DFIR-AF-0002",
    "DFIR-WIN-0008",
    "DFIR-WIN-0009",
    "DFIR-WIN-0027",
}


def jobs(api: Any, token: str, cid: str) -> list[dict[str, Any]]:
    status, body, _ = api.call("GET", f"/cases/{cid}/jobs?limit=500", token)
    expect(status == 200, "list jobs", body)
    return list(body["items"])


def alerts(api: Any, token: str, cid: str) -> list[dict[str, Any]]:
    status, body, _ = api.call("GET", f"/cases/{cid}/alerts?limit=500", token)
    expect(status == 200, "list alerts", body)
    return list(body["items"])


def settle(api: Any, token: str, cid: str, timeout: float = 240) -> list[dict[str, Any]]:
    """Wait until no job of the case is queued/running and a detection run started after the
    last parse job finished (the parse task queues detection right after recording its result);
    return the detection jobs, newest first."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        items = jobs(api, token, cid)
        parse_done = [j["finished_at"] for j in items if j["kind"] == "parse" and j["finished_at"]]
        detects = [j for j in items if j["kind"] == "detect"]
        idle = items and all(j["status"] not in ("queued", "running") for j in items)
        caught_up = detects and all(
            (detects[0]["started_at"] or "") >= done for done in parse_done
        )
        if idle and caught_up:
            return detects
        time.sleep(1)
    expect(False, f"jobs settled within {timeout}s", jobs(api, token, cid))
    raise AssertionError


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
    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 3 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call(
            "POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role}
        )
        expect(status == 200, f"lead adds {role}", body)

    auth_id = p2.stored(
        api, analyst, cid, "auth.log", "log", (FIXTURES / "linux" / "auth.log").read_bytes()
    )
    evtx_id = p2.stored(
        api,
        analyst,
        cid,
        "Security.evtx",
        "evtx",
        (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes(),
    )
    for eid in (auth_id, evtx_id):
        status, body, _ = api.call("POST", f"/evidence/{eid}/process", analyst, {})
        expect(status == 202, "parse job queued", body)

    detect_jobs = settle(api, analyst, cid)
    expect(
        bool(detect_jobs) and all(j["status"] == "succeeded" for j in detect_jobs),
        "worker queued and ran detection after parsing",
        detect_jobs,
    )
    status, job, _ = api.call("GET", f"/jobs/{detect_jobs[0]['id']}", analyst)
    manifest = job.get("run_manifest") or {}
    expect(
        status == 200 and manifest.get("rules") and all("sha256" in r for r in manifest["rules"]),
        "run manifest cites rule versions",
        manifest,
    )
    found = alerts(api, viewer, cid)
    fired = {a["rule_id"] for a in found}
    expect(fired == EXPECTED, f"expected rules fired: {sorted(fired)}", found)

    target = next(a for a in found if a["rule_id"] == "DFIR-LNX-0011")
    status, body, _ = api.call("PATCH", f"/alerts/{target['id']}", viewer, {"status": "triaged"})
    expect(status == 403, "viewer cannot change alerts (403)", body)
    status, body, _ = api.call(
        "PATCH",
        f"/alerts/{target['id']}",
        analyst,
        {"status": "triaged", "expected_status": "new", "assignee_id": analyst_id},
    )
    expect(status == 200 and body["status"] == "triaged", "analyst triages an alert", body)
    status, body, _ = api.call("GET", f"/alerts/{target['id']}/events", viewer)
    expect(
        status == 200 and body["items"] and not body["items"][0]["missing"],
        "linked events resolve",
        body,
    )

    status, body, _ = api.call(
        "POST", f"/cases/{cid}/iocs", analyst, {"type": "ip", "value": "203.0.113[.]50"}
    )
    expect(status == 201 and body["value"] == "203.0.113.50", "analyst adds a defanged IOC", body)
    status, body, _ = api.call("POST", f"/cases/{cid}/detect", analyst, {})
    expect(status == 202, "on-demand detection queued", body)
    settle(api, analyst, cid)
    found = alerts(api, viewer, cid)
    expect(
        # 203.0.113.50 appears on Dec 31 and Jan 2: one IOC alert per day bucket.
        sum(a["rule_id"] == "DFIR-IOC-0001" for a in found) == 2
        and len({a["dedup_key"] for a in found}) == len(found) == len(EXPECTED) + 2,
        "IOC alerts added (one per day), nothing duplicated",
        [a["title"] for a in found],
    )
    status, body, _ = api.call("GET", f"/alerts/{target['id']}", viewer)
    expect(body["status"] == "triaged", "detection does not overwrite triage state", body)
    status, body, _ = api.call("GET", "/rules/coverage", viewer)
    expect(status == 200 and any(r["technique"] == "T1070.001" for r in body), "coverage", body)
    status, body, _ = api.call("GET", f"/cases/{cid}/risk", viewer)
    expect(status == 200 and 0 < body["case_risk"] <= 100, "case risk score", body)
    print("PHASE 3 SMOKE PASSED")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
