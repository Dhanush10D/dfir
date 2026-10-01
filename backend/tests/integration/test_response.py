"""Phase 9: playbooks, runs, steps and four-eyes action approvals through the API and the service.

Covers the packaged playbooks and custom imports, dry runs that write nothing, a full run that
records user, time, result and the triggering alert for every step, honest ``not_executed``
outcomes for agent actions, the four-eyes rule in the service and in the database (attacks as the
app role), rejection, withdrawal, expiry, at-most-once execution under concurrency, closed cases,
RBAC, case isolation, cancellation, notifications and grants.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import DBAPIError

from app.core.exceptions import AppError
from app.core.permissions import Principal
from app.db.models import (
    ActionRequest,
    Alert,
    AuditLog,
    Notification,
    OutboundEvent,
    PlaybookRun,
    PlaybookRunStep,
    Severity,
    UserRole,
)
from app.services.audit import RequestMeta
from app.services.playbooks import PlaybookService
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

T0 = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)
META = RequestMeta(ip="198.51.100.7", request_id="test")
HOST = "WS-SECRET-042"


def custom_yaml(pid: str) -> str:
    return f"""
id: {pid}
title: Custom test playbook
phases:
  - name: Notify
    steps:
      - {{ id: n1, text: "Tell the team (approved first)", action: notify.team,
           requires_approval: true }}
      - {{ id: n2, text: "Tell the team", action: notify.team }}
      - {{ id: m1, text: "Write it down", manual: true }}
notify: {{ channels: [in_app], roles: [lead] }}
"""


def principal(user: UserCtx) -> Principal:
    return Principal(user.id, user.email, f"Test {user.role.value}", user.role)


class World:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.lead = h.make_user(UserRole.lead)
        self.lead2 = h.make_user(UserRole.lead)
        self.analyst = h.make_user(UserRole.analyst)
        self.analyst2 = h.make_user(UserRole.analyst)
        self.viewer = h.make_user(UserRole.viewer)
        self.outsider = h.make_user(UserRole.lead)
        self.cid = h.create_case(self.lead, "Response case")["id"]
        for user, role in (
            (self.lead2, UserRole.lead),
            (self.analyst, UserRole.analyst),
            (self.analyst2, UserRole.analyst),
            (self.viewer, UserRole.viewer),
        ):
            h.add_member(self.lead, self.cid, user, role)
        with h.sessions() as session:
            alert = Alert(
                id=uuid.uuid4(),
                case_id=uuid.UUID(self.cid),
                rule_id=None,
                title="Volume shadow copies deleted",
                severity=Severity.high,
                attack_tags=["T1490"],
                dedup_key=f"test:{uuid.uuid4().hex}",
                first_seen=T0,
                last_seen=T0,
            )
            session.add(alert)
            session.commit()
            self.alert_id = str(alert.id)

    def start(self, playbook_id: str = "PB-RANSOMWARE-01", user: UserCtx | None = None) -> Any:
        r = self.h.post(
            f"/cases/{self.cid}/playbook-runs",
            user or self.analyst,
            json={"playbook_id": playbook_id, "alert_id": self.alert_id},
        )
        assert r.status_code == 201, r.text
        return r.json()

    def step(self, run: Any, key: str, user: UserCtx, **body: Any) -> Any:
        return self.h.patch(f"/playbook-runs/{run['id']}/steps/{key}", user, json=body)

    def custom(self) -> str:
        pid = f"PB-T-{uuid.uuid4().hex[:10].upper()}"
        r = self.h.post("/playbooks", self.lead, json={"yaml": custom_yaml(pid)})
        assert r.status_code == 201, r.text
        return pid


@pytest.fixture
def world(h: Harness) -> World:
    return World(h)


def by_key(run: Any) -> dict[str, Any]:
    return {s["step_key"]: s for s in run["steps"]}


def counts(h: Harness) -> dict[str, int]:
    with h.sessions() as session:
        return {
            model.__tablename__: int(
                session.execute(select(func.count()).select_from(model)).scalar_one()
            )
            for model in (PlaybookRun, PlaybookRunStep, ActionRequest, OutboundEvent, Notification)
        } | {
            "audit": int(
                session.execute(
                    select(func.count())
                    .select_from(AuditLog)
                    .where(AuditLog.action.like("playbook.%"))
                ).scalar_one()
            )
        }


# ------------------------------------------------------------------ catalogue


def test_builtin_playbooks_are_synced_and_listed(world: World) -> None:
    h = world.h
    r = h.get("/playbooks", world.viewer)
    assert r.status_code == 200, r.text
    builtin = {p["id"]: p for p in r.json()["items"] if p["origin"] == "builtin"}
    assert set(builtin) == {
        "PB-RANSOMWARE-01",
        "PB-PHISHING-01",
        "PB-CREDENTIAL-01",
        "PB-MALWARE-01",
        "PB-LOGTAMPER-01",
        "PB-EXFIL-01",
        "PB-CLOUD-01",
        "PB-WEBSHELL-01",
    }
    ransomware = builtin["PB-RANSOMWARE-01"]
    assert ransomware["enabled"] and len(ransomware["sha256"]) == 64
    steps = {s["id"]: s for p in ransomware["phases"] for s in p["steps"]}
    assert steps["c1"]["requires_approval"] is True
    malware = builtin["PB-MALWARE-01"]
    forced = {s["id"]: s["requires_approval"] for p in malware["phases"] for s in p["steps"]}
    assert forced["c1"] is True and forced["c2"] is True  # impactful, although the file is silent
    assert (
        h.get("/playbooks/PB-RANSOMWARE-01", world.viewer).json()["title"] == "Suspected ransomware"
    )
    assert h.get("/playbooks/PB-NOPE-01", world.viewer).status_code == 404
    assert h.get("/playbooks").status_code == 401
    actions = {a["name"]: a for a in h.get("/playbook-actions", world.viewer).json()["items"]}
    assert (
        actions["agent.isolate_host"]["impact"]
        and actions["agent.isolate_host"]["executor"] == "none"
    )
    # Syncing again changes nothing.
    with h.sessions() as session:
        again = PlaybookService(session, h.settings).sync_builtin()
    assert again["created"] == 0 and again["updated"] == 0 and again["unchanged"] == 8


def test_import_custom_playbook_rbac_and_validation(world: World) -> None:
    h = world.h
    pid = f"PB-T-{uuid.uuid4().hex[:10].upper()}"
    assert h.post("/playbooks", world.analyst, json={"yaml": custom_yaml(pid)}).status_code == 403
    r = h.post("/playbooks", world.lead, json={"yaml": custom_yaml(pid)})
    assert r.status_code == 201 and r.json()["origin"] == "custom" and r.json()["version"] == 1
    assert h.post("/playbooks", world.lead, json={"yaml": custom_yaml(pid)}).json()["version"] == 1
    changed = custom_yaml(pid).replace("Custom test playbook", "Changed title")
    assert h.post("/playbooks", world.lead, json={"yaml": changed}).json()["version"] == 2
    builtin = custom_yaml("PB-RANSOMWARE-01")
    r = h.post("/playbooks", world.lead, json={"yaml": builtin})
    assert r.status_code == 409 and r.json()["error"]["code"] == "playbook_id_taken"
    for bad in (
        custom_yaml(pid).replace("action: notify.team }", "action: os.system }"),
        "a: &a [1]\nb: *a\n",
        custom_yaml(pid) + "extra_key: 1\n",
        custom_yaml(pid).replace("id: n2", "id: n1"),
    ):
        r = h.post("/playbooks", world.lead, json={"yaml": bad})
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_playbook", r.text
    assert h.post("/playbooks", world.lead, json={"yaml": "x" * 70_000}).status_code == 422


def test_trigger_suggestions(world: World) -> None:
    h = world.h
    r = h.get(f"/alerts/{world.alert_id}/playbooks", world.viewer)
    assert r.status_code == 200
    assert "PB-RANSOMWARE-01" in {p["id"] for p in r.json()["items"]}
    assert h.get(f"/alerts/{world.alert_id}/playbooks", world.outsider).status_code == 404


# ------------------------------------------------------------------ dry run


def test_dry_run_writes_nothing(world: World) -> None:
    h = world.h
    run = world.start()
    before = counts(h)
    r = h.post(
        f"/cases/{world.cid}/playbook-runs",
        world.analyst,
        json={"playbook_id": "PB-RANSOMWARE-01", "alert_id": world.alert_id, "dry_run": True},
    )
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["dry_run"] is True and plan["writes"] == "none" and plan["approvals_needed"] == 1
    c1 = next(s for s in plan["steps"] if s["step_key"] == "c1")
    assert c1["plan"]["would_execute"] is False and c1["plan"]["requires_approval"] is True
    assert "no remote agent" in c1["plan"]["effect"].lower()
    assert plan["notifications"]["channels"] == ["in_app", "slack", "email"]
    for op, key, extra in (
        ("execute", "c1", {"params": {"host": HOST}}),
        ("request", "c1", {"params": {"host": HOST}}),
        ("execute", "c3", {}),
        ("complete", "c2", {}),
    ):
        r = world.step(run, key, world.analyst, op=op, dry_run=True, **extra)
        assert r.status_code == 200 and r.json()["dry_run"] is True, r.text
        assert r.json()["status"] == "pending"
    assert counts(h) == before
    state = h.get(f"/playbook-runs/{run['id']}", world.viewer).json()
    assert {s["status"] for s in state["steps"]} == {"pending"}
    # A viewer cannot even ask for the plan of a run; an outsider does not see the case.
    assert (
        h.post(
            f"/cases/{world.cid}/playbook-runs",
            world.viewer,
            json={"playbook_id": "PB-RANSOMWARE-01", "dry_run": True},
        ).status_code
        == 403
    )
    assert world.step(run, "c9", world.analyst, op="execute", dry_run=True).status_code == 404


# ------------------------------------------------------------------ a full run


def test_run_lifecycle_records_user_time_result_and_alert(world: World) -> None:
    h = world.h
    run = world.start()
    assert run["status"] == "running" and run["alert_id"] == world.alert_id
    assert run["started_by"] == str(world.analyst.id) and run["playbook_sha256"]
    steps = by_key(run)
    assert list(steps) == ["c1", "c2", "c3", "e1", "e2", "r1", "r2"]
    assert all(s["alert_id"] == world.alert_id and s["status"] == "pending" for s in run["steps"])

    # Manual step: who, when, notes.
    r = world.step(run, "c2", world.analyst, op="complete", notes="Disabled jdoe in AD")
    assert r.status_code == 200, r.text
    c2 = by_key(r.json())["c2"]
    assert (c2["status"], c2["outcome"], c2["notes"]) == (
        "done",
        "completed",
        "Disabled jdoe in AD",
    )
    assert c2["completed_by"] == str(world.analyst.id) and c2["completed_at"]
    assert world.step(run, "c2", world.analyst, op="complete").status_code == 409  # finished

    # A real action without approval: exactly one outbox event, and only once.
    r = world.step(run, "c3", world.analyst, op="execute")
    assert r.status_code == 200 and by_key(r.json())["c3"]["outcome"] == "completed", r.text
    assert world.step(run, "c3", world.analyst, op="execute").status_code == 409
    with h.sessions() as session:
        notices = (
            session.execute(
                select(OutboundEvent).where(
                    OutboundEvent.event_type == "playbook.notice",
                    OutboundEvent.payload["run_id"].astext == run["id"],
                )
            )
            .scalars()
            .all()
        )
    assert len(notices) == 1 and notices[0].payload["step_key"] == "c3"

    # An agent action without approval: nothing is executed, and the record says so.
    assert world.step(run, "e1", world.analyst, op="execute").status_code == 422  # host missing
    r = world.step(run, "e1", world.analyst, op="execute", params={"host": HOST})
    e1 = by_key(r.json())["e1"]
    assert (e1["status"], e1["outcome"]) == ("not_executed", "not_executed"), r.text
    assert e1["result"]["reason"] == "no_remote_agent" and e1["result"]["simulated"] is True
    assert e1["completed_by"] is None and e1["updated_by"] == str(world.analyst.id)
    assert r.json()["status"] == "running"
    assert world.step(run, "e1", world.analyst, op="complete").status_code == 422  # notes needed
    r = world.step(run, "e1", world.analyst, op="complete", notes="Imaged RAM with WinPmem by hand")
    e1 = by_key(r.json())["e1"]
    assert (e1["status"], e1["outcome"]) == ("done", "completed_manually")

    # The impactful action: no execution without an approval by a second person.
    r = world.step(run, "c1", world.analyst, op="execute", params={"host": HOST})
    assert r.status_code == 409 and r.json()["error"]["code"] == "approval_required"
    assert world.step(run, "c1", world.analyst, op="complete", notes="x").status_code == 409
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    assert r.status_code == 200, r.text
    c1 = by_key(r.json())["c1"]
    request = c1["request"]
    assert c1["status"] == "awaiting_approval" and request["status"] == "pending"
    assert request["requested_by"] == str(world.analyst.id) and request["params"] == {"host": HOST}
    assert request["alert_id"] == world.alert_id and request["action"] == "agent.isolate_host"
    assert h.post(f"/action-requests/{request['id']}/approve", world.analyst).status_code == 403
    assert h.post(f"/action-requests/{request['id']}/approve", world.analyst2).status_code == 403
    assert h.post(f"/action-requests/{request['id']}/approve", world.viewer).status_code == 403
    r = h.post(f"/action-requests/{request['id']}/approve", world.lead, json={"reason": "ok"})
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    assert r.json()["decided_by"] == str(world.lead.id)
    # The approval covers these parameters only.
    r = world.step(run, "c1", world.analyst, op="execute", params={"host": "OTHER-HOST"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "params_changed"
    r = world.step(run, "c1", world.analyst, op="execute")
    c1 = by_key(r.json())["c1"]
    assert (c1["status"], c1["outcome"]) == ("not_executed", "not_executed"), r.text
    assert c1["request"]["status"] == "finished" and c1["request"]["outcome"] == "not_executed"
    assert c1["request"]["executed_by"] == str(world.analyst.id)
    assert "isolated" not in str(c1["result"]).lower().replace("not executed", "")
    assert world.step(run, "c1", world.analyst, op="execute").status_code == 409  # once
    r = world.step(run, "c1", world.analyst, op="complete", notes="Isolated in the EDR console")
    assert by_key(r.json())["c1"]["outcome"] == "completed_manually"

    assert world.step(run, "e2", world.analyst, op="skip").status_code == 422  # reason needed
    assert (
        world.step(run, "e2", world.analyst, op="skip", notes="No ransom note found").status_code
        == 200
    )
    assert world.step(run, "r1", world.analyst, op="complete").status_code == 200
    r = world.step(run, "r2", world.analyst, op="complete", notes="Rotated")
    done = r.json()
    assert done["status"] == "completed" and done["finished_at"]
    assert {s["status"] for s in done["steps"]} == {"done", "skipped"}
    assert world.step(run, "r2", world.analyst, op="complete").status_code == 409
    assert world.step(run, "zz", world.analyst, op="complete").status_code == 409  # run finished

    listed = h.get(f"/cases/{world.cid}/playbook-runs", world.viewer).json()["items"]
    assert [x["id"] for x in listed] == [run["id"]] and listed[0]["title"] == "Suspected ransomware"
    requests = h.get(f"/cases/{world.cid}/action-requests?status=finished", world.viewer).json()
    assert [x["id"] for x in requests["items"]] == [request["id"]]

    with h.sessions() as session:
        rows = (
            session.execute(
                select(AuditLog).where(
                    AuditLog.object_type == "playbook_run", AuditLog.object_id == run["id"]
                )
            )
            .scalars()
            .all()
        )
    actions = [row.action for row in rows]
    for expected in (
        "playbook.run_started",
        "playbook.step_completed",
        "playbook.step_skipped",
        "playbook.action_requested",
        "playbook.action_approved",
        "playbook.action_executed",
        "playbook.run_completed",
    ):
        assert expected in actions, expected
    assert all(row.detail["alert_id"] == world.alert_id for row in rows)
    assert all(HOST not in str(row.detail) for row in rows)  # parameters only as a hash
    executed = [row for row in rows if row.action == "playbook.action_executed"]
    assert {row.detail["outcome"] for row in executed} == {"completed", "not_executed"}


# ------------------------------------------------------------------ four eyes, RBAC, isolation


def test_four_eyes_in_the_service(world: World) -> None:
    h = world.h
    run = world.start(user=world.lead)
    r = world.step(run, "c1", world.lead, op="request", params={"host": HOST})
    rid = by_key(r.json())["c1"]["request"]["id"]
    r = h.post(f"/action-requests/{rid}/approve", world.lead)
    assert r.status_code == 403 and r.json()["error"]["details"]["rule"] == "four_eyes"
    assert h.post(f"/action-requests/{rid}/approve", world.outsider).status_code == 404
    assert (
        h.post(f"/action-requests/{rid}/reject", world.outsider, json={"reason": "x"}).status_code
        == 404
    )
    assert h.get(f"/playbook-runs/{run['id']}", world.outsider).status_code == 404
    assert h.get(f"/cases/{world.cid}/action-requests", world.outsider).status_code == 404
    r = h.post(f"/action-requests/{rid}/approve", world.lead2)
    assert r.status_code == 200 and r.json()["decided_by"] == str(world.lead2.id)
    assert h.post(f"/action-requests/{rid}/approve", world.lead2).status_code == 409  # decided
    # Viewers read, never change; an admin (no membership needed) may approve.
    assert world.step(run, "c2", world.viewer, op="complete").status_code == 403
    assert (
        h.post(
            f"/cases/{world.cid}/playbook-runs",
            world.viewer,
            json={"playbook_id": "PB-PHISHING-01"},
        ).status_code
        == 403
    )
    run2 = world.start("PB-MALWARE-01")
    r = world.step(run2, "c2", world.analyst, op="request", params={"host": HOST, "pid": 4242})
    rid2 = by_key(r.json())["c2"]["request"]["id"]
    admin = h.make_user(UserRole.admin)
    assert h.post(f"/action-requests/{rid2}/approve", admin).status_code == 200
    # A step that needs no approval cannot be "requested"; unknown params are refused.
    assert (
        world.step(run2, "e1", world.analyst, op="request", params={"host": HOST}).status_code
        == 409
    )
    r = world.step(run2, "c1", world.analyst, op="request", params={"host": HOST, "cmd": "x"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_params"
    assert world.step(run2, "e3", world.analyst, op="execute").status_code == 409  # manual step
    assert world.step(run2, "e3", world.analyst, op="bogus").status_code == 422


def test_reject_withdraw_and_request_again(world: World) -> None:
    h = world.h
    run = world.start()
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    first = by_key(r.json())["c1"]["request"]["id"]
    assert (
        world.step(run, "c1", world.analyst, op="request", params={"host": HOST}).status_code == 409
    )
    assert h.post(f"/action-requests/{first}/reject", world.lead, json={}).status_code == 422
    assert (
        h.post(
            f"/action-requests/{first}/reject", world.analyst2, json={"reason": "no"}
        ).status_code
        == 403
    )
    r = h.post(f"/action-requests/{first}/reject", world.lead, json={"reason": "Wrong host"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert r.json()["decision_reason"] == "Wrong host"
    state = by_key(h.get(f"/playbook-runs/{run['id']}", world.viewer).json())["c1"]
    assert state["status"] == "pending" and state["request"]["status"] == "rejected"
    assert h.post(f"/action-requests/{first}/approve", world.lead).status_code == 409  # frozen
    assert world.step(run, "c1", world.analyst, op="execute").status_code == 409
    # Ask again, then withdraw as the requester.
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    second = by_key(r.json())["c1"]["request"]["id"]
    assert second != first
    r = h.post(f"/action-requests/{second}/reject", world.analyst, json={"reason": "Not needed"})
    assert r.status_code == 200 and r.json()["decided_by"] == str(world.analyst.id)
    assert (
        world.step(run, "c1", world.analyst, op="skip", notes="Host already offline").status_code
        == 200
    )
    listed = h.get(f"/cases/{world.cid}/action-requests", world.viewer).json()["items"]
    assert {x["status"] for x in listed} == {"rejected"} and len(listed) == 2


def test_request_is_idempotent_with_a_key(world: World) -> None:
    h = world.h
    run = world.start()
    headers = {**world.analyst.headers, "Idempotency-Key": "retry-1"}
    url = f"/api/v1/playbook-runs/{run['id']}/steps/c1"
    body = {"op": "request", "params": {"host": HOST}}
    first = h.client.patch(url, headers=headers, json=body)
    again = h.client.patch(url, headers=headers, json=body)
    assert first.status_code == 200 and again.status_code == 200, again.text
    assert (
        by_key(first.json())["c1"]["request"]["id"] == by_key(again.json())["c1"]["request"]["id"]
    )
    with h.sessions() as session:
        n = session.execute(
            select(func.count()).select_from(ActionRequest).where(ActionRequest.run_id == run["id"])
        ).scalar_one()
    assert n == 1


def test_approvals_expire(world: World) -> None:
    h = world.h
    run = world.start()
    now = {"t": datetime.now(UTC)}

    def service(session: Any) -> PlaybookService:
        return PlaybookService(session, h.settings, clock=lambda: now["t"])

    def state() -> tuple[str, list[str]]:
        view = h.get(f"/playbook-runs/{run['id']}", world.viewer).json()
        with h.sessions() as session:
            statuses = (
                session.execute(
                    select(ActionRequest.status)
                    .where(ActionRequest.run_id == run["id"])
                    .order_by(ActionRequest.requested_at)
                )
                .scalars()
                .all()
            )
        return by_key(view)["c1"]["status"], list(statuses)

    run_id = uuid.UUID(run["id"])
    with h.sessions() as session:
        view = service(session).step_op(
            principal(world.analyst), run_id, "c1", META, op="request", params={"host": HOST}
        )
        first = view.requests[-1].id  # type: ignore[union-attr]
    # A pending request that nobody decided in time.
    now["t"] += timedelta(minutes=h.settings.approval_ttl_minutes + 1)
    with h.sessions() as session, pytest.raises(AppError) as err:
        service(session).approve(principal(world.lead), first, META)
    assert err.value.status_code == 409
    with h.sessions() as session:
        row = session.get(ActionRequest, first)
        assert row is not None and row.status == "expired" and row.decided_by is None
        step = session.execute(
            select(PlaybookRunStep).where(
                PlaybookRunStep.run_id == run_id, PlaybookRunStep.step_key == "c1"
            )
        ).scalar_one()
        assert step.status == "pending"
        # An approved request that was not executed in time.
        view = service(session).step_op(
            principal(world.analyst), run_id, "c1", META, op="request", params={"host": HOST}
        )
        second = view.requests[-1].id  # type: ignore[union-attr]
    with h.sessions() as session:
        assert service(session).approve(principal(world.lead), second, META).status == "approved"
    now["t"] += timedelta(minutes=h.settings.approval_ttl_minutes + 1)
    with h.sessions() as session, pytest.raises(AppError) as err:
        service(session).step_op(principal(world.analyst), run_id, "c1", META, op="execute")
    assert err.value.code == "approval_required"
    with h.sessions() as session:
        row = session.get(ActionRequest, second)
        assert row is not None and row.status == "expired"
        assert row.decided_by == world.lead.id and row.executed_at is None
        audited = session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "playbook.action_expired",
                AuditLog.object_id.in_([str(first), str(second)]),
            )
        ).scalar_one()
    assert audited == 2
    # The expiry is also noticed by a plain read (GET), and the step can be requested again.
    now["t"] = datetime.now(UTC)
    assert state() == ("pending", ["expired", "expired"])
    assert (
        world.step(run, "c1", world.analyst, op="request", params={"host": HOST}).status_code == 200
    )


# ------------------------------------------------------------------ at most once


def _race(fn: Any, n: int = 2) -> list[Any]:
    barrier = threading.Barrier(n)
    results: list[Any] = [None] * n

    def worker(i: int) -> None:
        barrier.wait(timeout=10)
        try:
            results[i] = fn(i)
        except Exception as exc:  # noqa: BLE001
            results[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return results


def test_approved_action_executes_at_most_once_under_concurrency(world: World) -> None:
    h = world.h
    run = world.start(world.custom())
    r = world.step(run, "n1", world.analyst, op="request")
    rid = by_key(r.json())["n1"]["request"]["id"]

    def approve(i: int) -> int:
        user = (world.lead, world.lead2)[i]
        return int(h.post(f"/action-requests/{rid}/approve", user).status_code)

    assert sorted(_race(approve)) == [200, 409]  # one decision wins, under the row lock

    def execute(i: int) -> int:
        user = (world.analyst, world.analyst2)[i]
        return int(world.step(run, "n1", user, op="execute").status_code)

    assert sorted(_race(execute, 2)) == [200, 409]
    with h.sessions() as session:
        events = session.execute(
            select(func.count())
            .select_from(OutboundEvent)
            .where(
                OutboundEvent.event_type == "playbook.notice",
                OutboundEvent.payload["run_id"].astext == run["id"],
                OutboundEvent.payload["step_key"].astext == "n1",
            )
        ).scalar_one()
        request = session.get(ActionRequest, uuid.UUID(rid))
        executed = session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "playbook.action_executed",
                AuditLog.object_id == run["id"],
            )
        ).scalar_one()
    assert events == 1 and executed == 1
    assert request is not None and request.status == "finished" and request.outcome == "completed"

    # Two people finishing the last open steps at once: the run completes exactly once.
    assert world.step(run, "n2", world.analyst, op="execute").status_code == 200

    def finish(i: int) -> int:
        user = (world.analyst, world.analyst2)[i]
        return int(world.step(run, "m1", user, op="complete").status_code)

    assert sorted(_race(finish)) == [200, 409]
    assert h.get(f"/playbook-runs/{run['id']}", world.viewer).json()["status"] == "completed"


# ------------------------------------------------------------------ database guard


def _raises(
    engine: Engine, sql: str, params: dict[str, Any], match: str, role: bool = True
) -> None:
    with pytest.raises(DBAPIError, match=match), engine.begin() as conn:
        if role:
            conn.execute(text("SET LOCAL ROLE dfirbench_app"))
        conn.execute(text(sql), params)


def test_database_enforces_four_eyes_for_the_app_role(world: World, db_engine: Engine) -> None:
    """The attacks the Phase 8 review found on reports, tried on action requests: one UPDATE
    that swaps the requester and self-approves, self-approval, skipping the approval, rewriting
    a decision, executing twice, and finishing the step without an executed request."""
    h = world.h
    run = world.start()
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    c1 = by_key(r.json())["c1"]
    rid, step_id = c1["request"]["id"], c1["id"]
    analyst, lead, other = str(world.analyst.id), str(world.lead.id), str(world.lead2.id)
    p = {"r": rid, "s": step_id, "a": analyst, "l": lead, "o": other}

    # A request cannot be born approved.
    _raises(
        db_engine,
        "INSERT INTO action_requests (case_id, run_id, step_id, action, params_sha256, "
        "idempotency_key, status, requested_by, expires_at, decided_by, decided_at) "
        "SELECT case_id, run_id, step_id, action, params_sha256, 'forged-' || id, 'approved', "
        ":a, now() + interval '1 hour', :l, now() FROM action_requests WHERE id = :r",
        p,
        "pending and undecided",
    )
    # The app role cannot touch the requester, the action or its parameters at all...
    for column, value in (
        ("requested_by", ":l"),
        ("params", "'{}'::jsonb"),
        ("params_sha256", "repeat('0', 64)"),
        ("action", "'notify.team'"),
        ("expires_at", "now() + interval '10 years'"),
        ("step_id", "step_id"),
    ):
        _raises(
            db_engine,
            f"UPDATE action_requests SET {column} = {value} WHERE id = :r",
            p,
            "permission denied",
        )
    _raises(db_engine, "DELETE FROM action_requests WHERE id = :r", p, "permission denied")
    # ...and for a role that could (the owner), the trigger compares with OLD: swapping the
    # requester and approving as the original requester in ONE statement is refused.
    _raises(
        db_engine,
        "UPDATE action_requests SET requested_by = :l, status = 'approved', decided_by = :a, "
        "decided_at = now() WHERE id = :r",
        p,
        "immutable",
        role=False,
    )
    # Self-approval.
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'approved', decided_by = requested_by, "
        "decided_at = now() WHERE id = :r",
        p,
        "someone other than the requester",
    )
    # Approval without a decider, or after the expiry time.
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'approved', decided_at = now() WHERE id = :r",
        p,
        "someone other than the requester",
    )
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'approved', decided_by = :l, "
        "decided_at = expires_at + interval '1 second' WHERE id = :r",
        p,
        "before it expires",
    )
    # Skipping the approval: pending -> finished, or expiring early.
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'finished', executed_by = :a, executed_at = now(), "
        "outcome = 'completed' WHERE id = :r",
        p,
        "cannot move from pending to finished",
    )
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'expired', decided_at = now() WHERE id = :r",
        p,
        "has not expired",
    )
    # Recording a decision or an outcome without the transition.
    _raises(
        db_engine,
        "UPDATE action_requests SET decided_by = :l, decided_at = now() WHERE id = :r",
        p,
        "only with a transition",
    )
    # The step cannot be finished (or marked approved) around the request.
    for status, extra in (
        ("approved", ""),
        ("done", ", outcome = 'completed', completed_by = :a, completed_at = now()"),
        ("not_executed", ", outcome = 'not_executed'"),
    ):
        _raises(
            db_engine,
            f"UPDATE playbook_run_steps SET status = '{status}'{extra} WHERE id = :s",
            p,
            "action request|cannot move",
        )
    _raises(
        db_engine,
        "UPDATE playbook_run_steps SET requires_approval = false WHERE id = :s",
        p,
        "permission denied",
    )
    _raises(
        db_engine,
        "UPDATE playbook_run_steps SET requires_approval = false WHERE id = :s",
        p,
        "identity is immutable",
        role=False,
    )

    # A proper approval by a second person passes the same trigger.
    assert h.post(f"/action-requests/{rid}/approve", world.lead).status_code == 200
    # The decision cannot be rewritten afterwards (e.g. to make the requester the approver).
    for sql in (
        "UPDATE action_requests SET decided_by = :o WHERE id = :r",
        "UPDATE action_requests SET decided_by = :a WHERE id = :r",
        "UPDATE action_requests SET decided_at = now() WHERE id = :r",
        "UPDATE action_requests SET status = 'pending', decided_by = NULL, decided_at = NULL "
        "WHERE id = :r",
        "UPDATE action_requests SET status = 'rejected' WHERE id = :r",
    ):
        _raises(db_engine, sql, p, "only with a transition|cannot move|approved")
    _raises(
        db_engine,
        "UPDATE action_requests SET status = 'finished', executed_by = :a, executed_at = now(), "
        "outcome = 'completed', decided_by = :o WHERE id = :r",
        p,
        "four-eyes approval",
    )
    # Execute through the service, then nothing may change any more.
    assert world.step(run, "c1", world.analyst, op="execute").status_code == 200
    for sql in (
        "UPDATE action_requests SET outcome = 'completed' WHERE id = :r",
        "UPDATE action_requests SET status = 'approved' WHERE id = :r",
        "UPDATE action_requests SET executed_by = :l WHERE id = :r",
        "UPDATE action_requests SET result = '{}'::jsonb WHERE id = :r",
    ):
        _raises(db_engine, sql, p, "is finished and cannot change")
    # The CHECK constraints hold even with triggers switched off (owner only).
    with pytest.raises(DBAPIError, match="ck_action_requests_four_eyes"), db_engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(text("UPDATE action_requests SET decided_by = requested_by WHERE id = :r"), p)
    with pytest.raises(DBAPIError, match="ck_action_requests_finished"), db_engine.begin() as conn:
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(text("UPDATE action_requests SET executed_at = NULL WHERE id = :r"), p)
    with h.sessions() as session:
        row = session.get(ActionRequest, uuid.UUID(rid))
        assert row is not None
        assert (row.status, row.requested_by, row.decided_by) == (
            "finished",
            world.analyst.id,
            world.lead.id,
        )


def test_database_guards_runs_and_finished_steps(world: World, db_engine: Engine) -> None:
    run = world.start()
    assert world.step(run, "c2", world.analyst, op="complete", notes="done").status_code == 200
    c2 = by_key(world.h.get(f"/playbook-runs/{run['id']}", world.viewer).json())["c2"]
    p = {"run": run["id"], "s": c2["id"], "u": str(world.lead.id)}
    for sql, match in (
        ("UPDATE playbook_run_steps SET notes = 'rewritten' WHERE id = :s", "is done and cannot"),
        ("UPDATE playbook_run_steps SET status = 'pending', outcome = NULL, completed_by = NULL, "
         "completed_at = NULL WHERE id = :s", "is done and cannot"),
        ("DELETE FROM playbook_run_steps WHERE id = :s", "permission denied"),
        ("UPDATE playbook_runs SET status = 'completed', finished_at = now() WHERE id = :run",
         "still has open steps"),
        ("UPDATE playbook_runs SET alert_id = NULL WHERE id = :run", "permission denied"),
        ("UPDATE playbook_runs SET definition = '{}'::jsonb WHERE id = :run", "permission denied"),
        ("DELETE FROM playbook_runs WHERE id = :run", "permission denied"),
        ("DELETE FROM playbooks WHERE id = 'PB-RANSOMWARE-01'", "permission denied"),
        ("INSERT INTO playbook_runs (case_id, playbook_id, status, finished_at) SELECT case_id, "
         "playbook_id, 'completed', now() FROM playbook_runs WHERE id = :run", "must be running"),
        ("INSERT INTO playbook_run_steps (run_id, case_id, position, phase, step_key, text, kind, "
         "status, outcome, completed_by, completed_at) SELECT run_id, case_id, 99, 'x', 'forged', "
         "'x', 'manual', 'done', 'completed', :u, now() FROM playbook_run_steps WHERE id = :s",
         "must be pending"),
        # An impactful action cannot be inserted without the approval requirement...
        ("INSERT INTO playbook_run_steps (run_id, case_id, position, phase, step_key, text, kind, "
         "action, requires_approval) SELECT run_id, case_id, 98, 'x', 'forged2', 'x', 'action', "
         "'agent.isolate_host', false FROM playbook_run_steps WHERE id = :s",
         "ck_playbook_run_steps_impactful"),
        # ...and a request must be for an open approval step, with that step's action.
        ("INSERT INTO action_requests (case_id, run_id, step_id, action, params_sha256, "
         "idempotency_key, requested_by, expires_at) SELECT case_id, run_id, id, 'notify.team', "
         "repeat('0', 64), 'forged-' || id, :u, now() + interval '1 hour' "
         "FROM playbook_run_steps WHERE id = :s", "must match an open approval step"),
        ("INSERT INTO action_requests (case_id, run_id, step_id, action, params_sha256, "
         "idempotency_key, requested_by, expires_at) SELECT case_id, run_id, id, 'notify.team', "
         "repeat('0', 64), 'forged-' || id, :u, now() + interval '1 hour' "
         "FROM playbook_run_steps WHERE run_id = :run AND step_key = 'c1'",
         "must match an open approval step"),
    ):  # fmt: skip
        _raises(db_engine, sql, p, match)
    _raises(
        db_engine,
        "UPDATE playbook_runs SET started_by = :u WHERE id = :run",
        p,
        "identity is immutable",
        role=False,
    )
    # A cancelled run is frozen, and so are its steps.
    r = world.h.post(
        f"/playbook-runs/{run['id']}/cancel", world.analyst, json={"reason": "wrong one"}
    )
    assert r.status_code == 200
    _raises(db_engine, "UPDATE playbook_runs SET status = 'running', finished_at = NULL "
            "WHERE id = :run", p, "is cancelled and cannot change")  # fmt: skip
    c3 = by_key(r.json())["c3"]
    _raises(
        db_engine,
        "UPDATE playbook_run_steps SET status = 'skipped', outcome = 'skipped', "
        "completed_by = :u, completed_at = now() WHERE id = :c3",
        {**p, "c3": c3["id"]},
        "not running",
    )


def test_app_role_grants_on_response_tables(db_engine: Engine) -> None:
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

    def columns(table: str) -> set[str]:
        with db_engine.connect() as conn:
            return set(
                conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns WHERE table_name = :t "
                        "AND has_column_privilege('dfirbench_app', :t, column_name, 'UPDATE')"
                    ),
                    {"t": table},
                ).scalars()
            )

    assert privileges("playbooks") == {"SELECT", "INSERT", "UPDATE"}
    assert privileges("playbook_runs") == {"SELECT", "INSERT"}
    assert columns("playbook_runs") == {"status", "finished_at"}
    assert privileges("playbook_run_steps") == {"SELECT", "INSERT"}
    assert columns("playbook_run_steps") == {
        "status", "outcome", "result", "notes", "completed_by", "completed_at", "updated_by",
        "updated_at",
    }  # fmt: skip
    assert privileges("action_requests") == {"SELECT", "INSERT"}
    assert columns("action_requests") == {
        "status", "decided_by", "decided_at", "decision_reason", "executed_by", "executed_at",
        "outcome", "result",
    }  # fmt: skip


# ------------------------------------------------------------------ closed case, cancel, notify


def test_closed_case_refuses_changes(world: World) -> None:
    h = world.h
    run = world.start()
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    rid = by_key(r.json())["c1"]["request"]["id"]
    assert (
        h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"}).status_code == 200
    )
    assert world.step(run, "c2", world.analyst, op="complete").status_code == 409
    assert h.post(f"/action-requests/{rid}/approve", world.lead).status_code == 409
    assert (
        h.post(f"/action-requests/{rid}/reject", world.lead, json={"reason": "x"}).status_code
        == 409
    )
    assert (
        h.post(
            f"/playbook-runs/{run['id']}/cancel", world.analyst, json={"reason": "x"}
        ).status_code
        == 409
    )
    r = h.post(
        f"/cases/{world.cid}/playbook-runs", world.analyst, json={"playbook_id": "PB-PHISHING-01"}
    )
    assert r.status_code == 409 and "closed" in r.json()["error"]["message"]
    # Reads still work, and nothing changed.
    state = h.get(f"/playbook-runs/{run['id']}", world.viewer).json()
    assert state["status"] == "running" and by_key(state)["c1"]["request"]["status"] == "pending"
    assert h.get(f"/cases/{world.cid}/action-requests", world.viewer).status_code == 200


def test_cancel_run_closes_pending_requests(world: World) -> None:
    h = world.h
    run = world.start()
    r = world.step(run, "c1", world.analyst, op="request", params={"host": HOST})
    rid = by_key(r.json())["c1"]["request"]["id"]
    assert (
        h.post(f"/playbook-runs/{run['id']}/cancel", world.viewer, json={"reason": "x"}).status_code
        == 403
    )
    assert h.post(f"/playbook-runs/{run['id']}/cancel", world.analyst, json={}).status_code == 422
    r = h.post(
        f"/playbook-runs/{run['id']}/cancel", world.analyst, json={"reason": "Wrong playbook"}
    )
    assert r.status_code == 200 and r.json()["status"] == "cancelled" and r.json()["finished_at"]
    assert by_key(r.json())["c1"]["request"]["status"] == "rejected"
    assert h.post(f"/action-requests/{rid}/approve", world.lead).status_code == 409
    assert world.step(run, "c2", world.analyst, op="complete").status_code == 409
    assert (
        h.post(
            f"/playbook-runs/{run['id']}/cancel", world.analyst, json={"reason": "again"}
        ).status_code
        == 409
    )


def test_run_and_approval_notifications(world: World) -> None:
    h = world.h
    run = world.start(world.custom())  # notify: in_app -> leads of the case
    r = world.step(run, "n1", world.analyst, op="request")
    rid = by_key(r.json())["n1"]["request"]["id"]
    assert h.outbound_dispatched >= 2  # each commit with new events asked the worker to run
    h.deliver()
    with h.sessions() as session:
        rows = (
            session.execute(
                select(Notification).where(Notification.case_id == uuid.UUID(world.cid))
            )
            .scalars()
            .all()
        )
    started = {n.user_id for n in rows if n.kind == "playbook.run_started"}
    asked = {n.user_id for n in rows if n.kind == "playbook.approval_requested"}
    assert started == {world.lead.id, world.lead2.id}
    assert asked == {world.lead.id, world.lead2.id}  # approvers, not the requester
    one = next(n for n in rows if n.kind == "playbook.approval_requested")
    assert one.payload["tab"] == "response" and one.payload["title"].startswith(
        "Approval requested"
    )
    fields = {f["label"]: f["value"] for f in one.payload["fields"]}
    assert fields["Request"] == rid and fields["Action"] == "notify.team"
    # The lead sees and reads it; another user cannot touch it.
    mine = h.get("/notifications?unread_only=true", world.lead).json()
    assert mine["unread"] >= 2 and {n["kind"] for n in mine["items"]} >= {
        "playbook.approval_requested"
    }
    nid = next(n["id"] for n in mine["items"] if n["kind"] == "playbook.approval_requested")
    assert h.post(f"/notifications/{nid}/read", world.analyst).status_code == 404
    assert h.post(f"/notifications/{nid}/read", world.lead).json()["read_at"]
    assert h.post("/notifications/read-all", world.lead).status_code == 204
    assert h.get("/notifications", world.lead).json()["unread"] == 0
    assert h.get("/notifications").status_code == 401
