"""Phase 3: detection end to end (API -> DetectionService -> alerts -> alert/rule/IOC APIs).

Like the parse tests, the Celery broker is not involved: the harness records dispatched
detection job ids and the tests run ``DetectionService`` directly (what ``dfirbench.detect_case``
does in a worker).
"""

from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.db.models import UserRole
from app.services.detection import DetectionService
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
EVTX = (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes()
EXPECTED = {
    "DFIR-LNX-0004",
    "DFIR-LNX-0011",
    "DFIR-AF-0001",
    "DFIR-AF-0002",
    "DFIR-WIN-0008",
    "DFIR-WIN-0009",
    "DFIR-WIN-0027",
}


# ---------------------------------------------------------------------------------- helpers


class World:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.lead = h.make_user(UserRole.lead)
        self.analyst = h.make_user(UserRole.analyst)
        self.viewer = h.make_user(UserRole.viewer)
        self.outsider = h.make_user(UserRole.analyst)
        self.case = h.create_case(self.lead, "Detection case")
        self.cid = self.case["id"]
        h.add_member(self.lead, self.cid, self.analyst, UserRole.analyst)
        h.add_member(self.lead, self.cid, self.viewer, UserRole.viewer)
        self.auth_ev = h.stored_evidence(
            self.analyst,
            self.cid,
            AUTH_LOG,
            original_name="auth.log",
            acquired_at="2026-01-03T00:00:00Z",
        )
        self.evtx_ev = h.stored_evidence(
            self.analyst, self.cid, EVTX, original_name="Security.evtx", kind="evtx"
        )
        self.parse_jobs = {}
        for ev, parser in ((self.auth_ev, "linux_auth"), (self.evtx_ev, "evtx")):
            r = h.post(f"/evidence/{ev['id']}/process", self.analyst, json={"parsers": [parser]})
            assert r.status_code == 202, r.text
            self.parse_jobs[parser] = r.json()["jobs"][0]["id"]
        assert {r.outcome for r in h.run_pending()} == {"succeeded"}

    def detect(self, user: UserCtx | None = None, **body: Any) -> dict[str, Any]:
        r = self.h.post(f"/cases/{self.cid}/detect", user or self.analyst, json=body or None)
        assert r.status_code == 202, r.text
        return dict(r.json())

    def run(self) -> list[Any]:
        return self.h.run_detect_pending()

    def alerts(self, user: UserCtx | None = None, **params: Any) -> list[dict[str, Any]]:
        r = self.h.get(f"/cases/{self.cid}/alerts", user or self.viewer, params=params)
        assert r.status_code == 200, r.text
        return list(r.json()["items"])


@pytest.fixture
def world(h: Harness) -> World:
    return World(h)


def _count(db: Engine, sql: str, **params: Any) -> int:
    with db.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


# ---------------------------------------------------------------------------------- runs


def test_detection_end_to_end(world: World, db_engine: Engine) -> None:
    h = world.h
    body = world.detect()
    assert body["created"] is True and body["job"]["kind"] == "detect"
    [result] = world.run()
    assert result.outcome == "succeeded", result
    job = h.get(f"/jobs/{body['job']['id']}", world.viewer).json()
    manifest = job["run_manifest"]
    assert job["status"] == "succeeded" and job["progress"] == 1.0
    assert manifest["counts"]["events_scanned"] == 26  # 22 auth + 4 evtx
    assert manifest["counts"]["alerts_created"] == len(EXPECTED)
    ids = {r["id"] for r in manifest["rules"]}
    assert ids >= EXPECTED and all(
        r["version"] >= 1 and len(r["sha256"]) == 64 for r in manifest["rules"]
    )
    alerts = world.alerts()
    assert {a["rule_id"] for a in alerts} == EXPECTED
    by_rule = {a["rule_id"]: a for a in alerts}
    lnx = by_rule["DFIR-LNX-0004"]
    assert lnx["status"] == "new" and lnx["host"] == "web01" and lnx["event_count"] == 1
    assert lnx["risk_score"] == 36.0  # medium 45 x confidence 0.8 (documented formula)
    assert lnx["attack_tags"] == ["T1136.001"] and lnx["stale"] is False
    # Linked events resolve, and matched events carry the ATT&CK tag.
    r = h.get(f"/alerts/{by_rule['DFIR-WIN-0009']['id']}/events", world.viewer)
    assert r.status_code == 200
    [link] = r.json()["items"]
    assert link["missing"] is False and link["event"]["event_code"] == "4732"
    assert link["event"]["attack_tags"] == ["T1070.001", "T1098"]  # also a record-gap boundary
    gap = h.get(f"/alerts/{by_rule['DFIR-WIN-0027']['id']}", world.viewer).json()
    assert gap["details"]["missing_records"] == 2 and gap["history"][0]["action"] == "created"
    # ATT&CK view, risk summary and coverage
    attack = h.get(f"/cases/{world.cid}/attack", world.viewer).json()
    assert {row["technique"] for row in attack} >= {"T1098", "T1136.001", "T1070.001"}
    risk = h.get(f"/cases/{world.cid}/risk", world.viewer).json()
    assert 0 < risk["case_risk"] <= 100 and {x["host"] for x in risk["hosts"]} >= {"web01"}
    coverage = h.get("/rules/coverage", world.viewer).json()
    assert any(row["technique"] == "T1110" for row in coverage)
    assert (
        _count(db_engine, "SELECT count(*) FROM audit_log WHERE action = 'detection.completed'")
        >= 1
    )


def test_rerun_is_idempotent_and_reprocess_keeps_links(world: World, db_engine: Engine) -> None:
    h = world.h
    world.detect()
    world.run()
    first = {a["dedup_key"]: a["id"] for a in world.alerts()}
    links = _count(db_engine, "SELECT count(*) FROM alert_events")
    world.detect()
    [again] = world.run()
    assert again.outcome == "succeeded" and again.counts["alerts_created"] == 0
    assert {a["dedup_key"]: a["id"] for a in world.alerts()} == first
    assert _count(db_engine, "SELECT count(*) FROM alert_events") == links
    # Reprocess (delete + re-insert with the same deterministic ids): links still resolve.
    r = h.post(f"/jobs/{world.parse_jobs['linux_auth']}/reprocess", world.analyst)
    assert r.status_code == 202
    assert [x.outcome for x in h.run_pending()] == ["succeeded"]
    lnx = next(a for a in world.alerts() if a["rule_id"] == "DFIR-LNX-0004")
    [link] = h.get(f"/alerts/{lnx['id']}/events", world.viewer).json()["items"]
    assert link["missing"] is False and link["event"]["attack_tags"] == []  # re-inserted
    world.detect()
    [third] = world.run()
    assert third.counts["alerts_created"] == 0 and third.counts["alerts_marked_stale"] == 0
    [link] = h.get(f"/alerts/{lnx['id']}/events", world.viewer).json()["items"]
    assert link["event"]["attack_tags"] == ["T1136.001"]  # re-tagged
    # Reprocess with another timezone moves timestamps: links follow (event_ts refreshed).
    r = h.post(
        f"/jobs/{world.parse_jobs['linux_auth']}/reprocess",
        world.analyst,
        json={"params": {"timezone": "Asia/Kolkata"}},
    )
    assert r.status_code == 202
    h.run_pending()
    world.detect()
    [fourth] = world.run()
    assert fourth.outcome == "succeeded"
    assert (
        _count(
            db_engine,
            "SELECT count(*) FROM alert_events ae JOIN events e ON e.id = ae.event_id "
            "WHERE ae.event_ts <> e.ts",
        )
        == 0
    )
    keys = [a["dedup_key"] for a in world.alerts()]
    assert len(keys) == len(set(keys))
    live = {a["rule_id"] for a in world.alerts(include_stale=False)}
    assert live == EXPECTED


def test_concurrent_runs_never_duplicate_alerts(world: World, db_engine: Engine) -> None:
    job_ids = []
    with db_engine.begin() as conn:
        for status in ("queued", "running"):
            job_ids.append(
                conn.execute(
                    text(
                        "INSERT INTO jobs (case_id, kind, status, heartbeat_at) VALUES "
                        "(:c, 'detect', CAST(:s AS job_status), now() - interval '2 days') "
                        "RETURNING id"
                    ),
                    {"c": world.cid, "s": status},
                ).scalar_one()
            )
    barrier = threading.Barrier(len(job_ids))

    def run(job_id: uuid.UUID) -> str:
        barrier.wait()
        return world.h.run_detect(job_id).outcome

    with ThreadPoolExecutor(len(job_ids)) as pool:
        outcomes = list(pool.map(run, job_ids))
    assert outcomes == ["succeeded", "succeeded"]
    assert _count(db_engine, "SELECT count(*) FROM alerts WHERE case_id = :c", c=world.cid) == len(
        EXPECTED
    )
    distinct = "SELECT count(DISTINCT dedup_key) FROM alerts WHERE case_id = :c"
    assert _count(db_engine, distinct, c=world.cid) == len(EXPECTED)
    # The database itself refuses a duplicate (case_id, dedup_key).
    with pytest.raises(IntegrityError), db_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO alerts (case_id, title, severity, dedup_key, first_seen, last_seen) "
                "SELECT case_id, title, severity, dedup_key, first_seen, last_seen FROM alerts "
                "LIMIT 1"
            )
        )


def test_concurrent_submits_coalesce_into_one_queued_job(world: World, db_engine: Engine) -> None:
    barrier = threading.Barrier(8)

    def submit(i: int) -> int:
        barrier.wait()
        body = {"rules": ["DFIR-LNX-0004"]} if i % 2 else None
        r = world.h.post(f"/cases/{world.cid}/detect", world.analyst, json=body)
        return r.status_code

    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(submit, range(8)))
    assert codes == [202] * 8
    queued = _count(
        db_engine,
        "SELECT count(*) FROM jobs WHERE case_id = :c AND kind = 'detect' AND status = 'queued'",
        c=world.cid,
    )
    assert queued == 1
    assert len(world.h.detect_dispatched) == 1
    with db_engine.connect() as conn:
        params = conn.execute(
            text("SELECT params FROM jobs WHERE case_id = :c AND kind = 'detect'"),
            {"c": world.cid},
        ).scalar_one()
    assert params["rules"] is None  # "all rules" wins when merged


def test_rule_subset_and_disabled_rules(world: World) -> None:
    h = world.h
    world.detect(rules=["DFIR-LNX-0004"])
    world.run()
    assert {a["rule_id"] for a in world.alerts()} == {"DFIR-LNX-0004"}
    r = h.patch("/rules/DFIR-WIN-0027", world.lead, json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    world.detect()
    world.run()
    assert {a["rule_id"] for a in world.alerts()} == EXPECTED - {"DFIR-WIN-0027"}
    r = h.post(f"/cases/{world.cid}/detect", world.analyst, json={"rules": ["NOPE-0001"]})
    assert r.status_code == 422
    h.patch("/rules/DFIR-WIN-0027", world.lead, json={"enabled": True})


def test_cancel_before_flush_writes_nothing(
    world: World, db_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = world.detect()
    job_id = body["job"]["id"]
    original = DetectionService._flush

    def cancel_then_flush(self: DetectionService, *args: Any) -> Any:
        r = world.h.post(f"/jobs/{job_id}/cancel", world.analyst)
        assert r.status_code == 200, r.text
        return original(self, *args)

    monkeypatch.setattr(DetectionService, "_flush", cancel_then_flush)
    [result] = world.run()
    assert result.outcome == "cancelled"
    assert _count(db_engine, "SELECT count(*) FROM alerts WHERE case_id = :c", c=world.cid) == 0
    job = world.h.get(f"/jobs/{job_id}", world.viewer).json()
    assert job["status"] == "cancelled"
    # A cancelled detection job can be retried (re-queued and dispatched to the detect queue).
    monkeypatch.setattr(DetectionService, "_flush", original)
    r = world.h.post(f"/jobs/{job_id}/retry", world.analyst)
    assert r.status_code == 202 and r.json()["status"] == "queued"
    assert [x.outcome for x in world.run()] == ["succeeded"]


# ---------------------------------------------------------------------------------- alerts


def test_alert_lifecycle_rbac_and_audit(world: World, db_engine: Engine) -> None:
    h = world.h
    world.detect()
    world.run()
    alert = next(a for a in world.alerts() if a["rule_id"] == "DFIR-LNX-0011")
    path = f"/alerts/{alert['id']}"
    assert h.patch(path, world.viewer, json={"status": "triaged"}).status_code == 403
    assert h.get(path, world.outsider).status_code == 404  # cross-case by alert id
    assert h.get(f"{path}/events", world.outsider).status_code == 404
    assert h.patch(path, world.outsider, json={"status": "triaged"}).status_code == 404
    assert h.get(f"/cases/{world.cid}/alerts", world.outsider).status_code == 404
    r = h.patch(path, world.analyst, json={"status": "closed"})
    assert r.status_code == 409  # new -> closed not allowed
    r = h.patch(path, world.analyst, json={"status": "triaged", "expected_status": "new"})
    assert r.status_code == 200 and r.json()["status"] == "triaged"
    r = h.patch(path, world.analyst, json={"status": "investigating", "expected_status": "new"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "stale_state"
    r = h.patch(path, world.analyst, json={"status": "true_positive"})
    assert r.status_code == 422  # reason required
    r = h.patch(path, world.analyst, json={"status": "true_positive", "reason": "confirmed"})
    assert r.status_code == 200 and r.json()["status_reason"] == "confirmed"
    r = h.patch(path, world.analyst, json={"assignee_id": str(world.viewer.id)})
    assert r.status_code == 422  # viewers cannot work alerts
    r = h.patch(path, world.analyst, json={"assignee_id": str(world.outsider.id)})
    assert r.status_code == 422  # not a member of the case
    r = h.patch(path, world.analyst, json={"assignee_id": str(world.analyst.id)})
    assert r.status_code == 200 and r.json()["assignee_id"] == str(world.analyst.id)
    r = h.patch(path, world.analyst, json={"assignee_id": None})
    assert r.status_code == 200 and r.json()["assignee_id"] is None
    history = h.get(path, world.viewer).json()["history"]
    assert [x["action"] for x in history] == ["created", "status", "status", "assign", "assign"]
    assert (
        _count(
            db_engine,
            "SELECT count(*) FROM audit_log "
            "WHERE action = 'alert.status_changed' AND object_id = :a",
            a=alert["id"],
        )
        == 2
    )
    # Detection never overwrites triage state.
    world.detect()
    world.run()
    assert h.get(path, world.viewer).json()["status"] == "true_positive"


def test_concurrent_status_changes_one_wins(world: World) -> None:
    world.detect()
    world.run()
    alert = next(a for a in world.alerts() if a["rule_id"] == "DFIR-LNX-0004")
    barrier = threading.Barrier(6)

    def change(i: int) -> int:
        barrier.wait()
        target = "triaged" if i % 2 else "investigating"
        r = world.h.patch(
            f"/alerts/{alert['id']}",
            world.analyst,
            json={"status": target, "expected_status": "new"},
        )
        return r.status_code

    with ThreadPoolExecutor(6) as pool:
        codes = sorted(pool.map(change, range(6)))
    assert codes == [200, 409, 409, 409, 409, 409]
    history = world.h.get(f"/alerts/{alert['id']}", world.viewer).json()["history"]
    assert [x["action"] for x in history] == ["created", "status"]


def test_closed_case_is_read_only(world: World) -> None:
    h = world.h
    world.detect()
    world.run()
    alert = world.alerts()[0]
    r = h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"})
    assert r.status_code == 200, r.text
    assert h.post(f"/cases/{world.cid}/detect", world.analyst).status_code == 409
    r = h.patch(f"/alerts/{alert['id']}", world.analyst, json={"status": "triaged"})
    assert r.status_code == 409
    r = h.post(
        f"/cases/{world.cid}/iocs", world.analyst, json={"type": "ip", "value": "203.0.113.1"}
    )
    assert r.status_code == 409
    assert h.get(f"/alerts/{alert['id']}", world.viewer).status_code == 200  # still readable


def test_detect_requires_permission(world: World) -> None:
    assert world.h.post(f"/cases/{world.cid}/detect", world.viewer).status_code == 403
    assert world.h.post(f"/cases/{world.cid}/detect", world.outsider).status_code == 404


# ---------------------------------------------------------------------------------- rules


CUSTOM = """id: CUST-TEST-0001
title: Sudo to root
level: low
attack: [T1548.003]
description: sudo command run as root
false_positives: [admins]
logsource: {source_type: [auth_log]}
detection:
  selection: {event_code: sudo_command, raw.auth.target: root}
  condition: selection
"""

SIGMA_OK = """title: Whoami execution
id: 8f5e4b3c-1d2a-4f6b-9c8d-7e6f5a4b3c2d
status: test
level: medium
tags: [attack.discovery, attack.t1033]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\\\whoami.exe'
  filter:
    CommandLine|contains: '/all'
  condition: selection and not filter
"""

SIGMA_BAD = """title: Aggregation
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
    CommandLine|base64offset|contains: 'x'
  keywords: ['evil']
  condition: selection | count() > 5
"""


def test_rule_management(world: World) -> None:
    h = world.h
    assert h.get("/rules", world.viewer).status_code == 200
    assert h.post("/rules", world.analyst, json={"yaml": CUSTOM}).status_code == 403
    r = h.post("/rules", world.lead, json={"yaml": CUSTOM})
    assert r.status_code == 201, r.text
    assert r.json()["origin"] == "custom" and r.json()["version"] == 1
    assert h.post("/rules", world.lead, json={"yaml": CUSTOM}).status_code == 409
    bad = CUSTOM.replace("level: low", "level: low\nsurprise: 1")
    r = h.post("/rules", world.lead, json={"yaml": bad.replace("0001", "0002")})
    assert r.status_code == 422 and "surprise" in str(r.json())
    r = h.patch(
        "/rules/CUST-TEST-0001",
        world.lead,
        json={"yaml": CUSTOM.replace("level: low", "level: medium"), "expected_version": 1},
    )
    assert r.status_code == 200 and r.json()["version"] == 2 and len(r.json()["versions"]) == 2
    r = h.patch("/rules/CUST-TEST-0001", world.lead, json={"enabled": False, "expected_version": 1})
    assert r.status_code == 409  # stale version
    r = h.patch("/rules/DFIR-WIN-0001", world.lead, json={"yaml": CUSTOM})
    assert r.status_code == 409  # built-in rules are not editable
    world.detect(rules=["CUST-TEST-0001"])
    world.run()
    alerts = world.alerts()
    assert {a["rule_id"] for a in alerts} == {"CUST-TEST-0001"} and alerts[0][
        "severity"
    ] == "medium"
    # Sigma import: supported subset converts; unsupported features are listed, never approximated.
    r = h.post("/rules/import/sigma", world.lead, json={"yaml": SIGMA_OK})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["rule"]["id"] == "SIGMA-8F5E4B3C1D2A" and body["rule"]["attack"] == ["T1033"]
    assert "file_path|endswith" in body["rule"]["raw_yaml"]
    r = h.post("/rules/import/sigma", world.lead, json={"yaml": SIGMA_BAD})
    assert r.status_code == 422
    problems = " ".join(r.json()["error"]["details"]["unsupported"])
    assert "base64offset" in problems and "keyword" in problems and "count()" in problems
    assert h.post("/rules/import/sigma", world.analyst, json={"yaml": SIGMA_OK}).status_code == 403
    # Rule test endpoint (pure).
    r = h.post(
        "/rules/test",
        world.analyst,
        json={
            "yaml": CUSTOM,
            "events": [
                {
                    "ts": "2026-01-02T09:00:00Z",
                    "source_type": "auth_log",
                    "event_code": "sudo_command",
                    "raw": {"auth": {"target": "root"}},
                },
                {"ts": "2026-01-02T09:01:00Z", "source_type": "auth_log", "event_code": "x"},
            ],
        },
    )
    assert r.status_code == 200 and r.json()["matches"] == 1
    assert (
        h.post("/rules/test", world.viewer, json={"yaml": CUSTOM, "events": []}).status_code == 403
    )


# ---------------------------------------------------------------------------------- IOCs


def test_ioc_import_matching_and_deactivation(world: World) -> None:
    h = world.h
    base = f"/cases/{world.cid}/iocs"
    r = h.post(base, world.analyst, json={"type": "ip", "value": "203.0.113[.]50"})
    assert r.status_code == 201 and r.json()["value"] == "203.0.113.50"
    assert h.post(base, world.viewer, json={"type": "ip", "value": "1.2.3.4"}).status_code == 403
    csv = "type,value,tlp\nemail,bad@evil.example,red\nsha256,nothex,amber\nfilename,usermod,\n"
    r = h.post(f"{base}/import", world.analyst, json={"format": "csv", "content": csv})
    assert r.status_code == 200, r.text
    assert r.json()["created"] == 2 and r.json()["rejected_count"] == 1
    stix = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']"},
            {"type": "indicator", "pattern": "[process:pid = 4] AND [file:name = 'x']"},
        ],
    }
    r = h.post(
        f"{base}/import", world.analyst, json={"format": "stix", "content": json.dumps(stix)}
    )
    assert r.status_code == 200 and r.json()["created"] == 1 and r.json()["rejected_count"] >= 1
    world.detect()
    world.run()
    ioc_alerts = [a for a in world.alerts() if a["rule_id"] == "DFIR-IOC-0001"]
    titles = {a["title"] for a in ioc_alerts}
    assert "IOC match: ip 203.0.113.50" in titles and "IOC match: filename usermod" in titles
    ip_ioc = next(i for i in h.get(base, world.viewer).json()["items"] if i["type"] == "ip")
    r = h.delete(f"{base}/{ip_ioc['id']}", world.analyst)
    assert r.status_code == 200 and r.json()["active"] is False
    world.detect()
    world.run()
    stale = {a["title"] for a in world.alerts() if a["stale"]}
    assert stale == {"IOC match: ip 203.0.113.50"}
    other = world.h.create_case(world.outsider, "Other")
    assert h.delete(f"/cases/{other['id']}/iocs/{ip_ioc['id']}", world.outsider).status_code == 404


# ---------------------------------------------------------------------------------- grants


def test_app_role_grants_on_detection_tables(app_engine: Engine, db_engine: Engine) -> None:
    def privileges(table: str) -> set[str]:
        with db_engine.connect() as conn:
            return {
                p
                for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
                if conn.execute(
                    text("SELECT has_table_privilege('dfirbench_app', :t, :p)"),
                    {"t": table, "p": p},
                ).scalar_one()
            }

    def column(table: str, col: str) -> bool:
        with db_engine.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT has_column_privilege('dfirbench_app', :t, :c, 'UPDATE')"),
                    {"t": table, "c": col},
                ).scalar_one()
            )

    assert privileges("rules") == {"SELECT", "INSERT", "UPDATE"}
    assert privileges("rule_versions") == {"SELECT", "INSERT"}
    assert privileges("alerts") == {"SELECT", "INSERT", "UPDATE"}
    assert privileges("alert_history") == {"SELECT", "INSERT"}
    assert privileges("alert_events") == {"SELECT", "INSERT"}
    assert column("alert_events", "event_ts") and not column("alert_events", "alert_id")
    assert privileges("iocs") == {"SELECT", "INSERT", "UPDATE"}
    assert column("events", "attack_tags") and not column("events", "message")
    for stmt in (
        "UPDATE events SET message = 'x'",
        "DELETE FROM alerts",
        "DELETE FROM alert_history",
        "UPDATE rule_versions SET raw_yaml = 'x'",
        "DELETE FROM iocs",
        "UPDATE alert_events SET alert_id = alert_id",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
            conn.execute(text(stmt))
    # Append-only even for the owner (trigger), like custody/audit.
    for stmt in ("UPDATE alert_history SET reason = 'x'", "DELETE FROM rule_versions"):
        with pytest.raises(DBAPIError, match="append-only"), db_engine.begin() as conn:
            conn.execute(text(stmt))
