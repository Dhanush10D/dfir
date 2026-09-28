"""RBAC over the API for all five roles, object-level checks, case lifecycle, and audit rows."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.db.models import UserRole
from tests.integration.harness import CLIENT_IP, Harness, UserCtx

pytestmark = pytest.mark.integration


@dataclass
class World:
    admin: UserCtx
    lead: UserCtx
    analyst: UserCtx
    viewer: UserCtx
    auditor: UserCtx
    outsider: UserCtx
    case: dict[str, Any]
    evidence: dict[str, Any]

    def role(self, name: str) -> UserCtx:
        user: UserCtx = getattr(self, name)
        return user


@pytest.fixture
def world(h: Harness) -> World:
    admin = h.make_user(UserRole.admin)
    lead = h.make_user(UserRole.lead)
    analyst = h.make_user(UserRole.analyst)
    viewer = h.make_user(UserRole.viewer)
    auditor = h.make_user(UserRole.auditor)
    outsider = h.make_user(UserRole.analyst)
    case = h.create_case(lead)
    h.add_member(lead, case["id"], analyst, UserRole.analyst)
    h.add_member(lead, case["id"], viewer, UserRole.viewer)
    evidence = h.stored_evidence(lead, case["id"])
    return World(admin, lead, analyst, viewer, auditor, outsider, case, evidence)


ROLES = ("admin", "lead", "analyst", "viewer", "auditor", "outsider")


def _status(h: Harness, method: str, path: str, user: UserCtx, **kw: Any) -> int:
    response = getattr(h, method)(path, user, **kw)
    return int(response.status_code)


EXPECTED: dict[str, dict[str, int]] = {
    # action: {role: status}
    "create_case": dict(admin=201, lead=201, analyst=201, viewer=403, auditor=403, outsider=201),
    "list_users": dict(admin=200, lead=403, analyst=403, viewer=403, auditor=403, outsider=403),
    "audit_log": dict(admin=200, lead=403, analyst=403, viewer=403, auditor=200, outsider=403),
    "read_case": dict(admin=200, lead=200, analyst=200, viewer=200, auditor=200, outsider=404),
    "update_case": dict(admin=200, lead=200, analyst=200, viewer=403, auditor=403, outsider=404),
    "add_member": dict(admin=200, lead=200, analyst=403, viewer=403, auditor=403, outsider=404),
    "add_evidence": dict(admin=201, lead=201, analyst=201, viewer=403, auditor=403, outsider=404),
    "list_evidence": dict(admin=200, lead=200, analyst=200, viewer=200, auditor=200, outsider=404),
    "read_evidence": dict(admin=200, lead=200, analyst=200, viewer=200, auditor=200, outsider=404),
    "verify": dict(admin=200, lead=200, analyst=200, viewer=403, auditor=200, outsider=404),
    "custody": dict(admin=200, lead=200, analyst=200, viewer=403, auditor=200, outsider=404),
    "download": dict(admin=200, lead=200, analyst=403, viewer=403, auditor=200, outsider=404),
}


def _do(h: Harness, w: World, action: str, user: UserCtx) -> int:
    cid, eid = w.case["id"], w.evidence["id"]
    match action:
        case "create_case":
            return _status(h, "post", "/cases", user, json={"title": "rbac"})
        case "list_users":
            return _status(h, "get", "/users", user)
        case "audit_log":
            return _status(h, "get", "/audit", user)
        case "read_case":
            return _status(h, "get", f"/cases/{cid}", user)
        case "update_case":
            return _status(h, "patch", f"/cases/{cid}", user, json={"description": "x"})
        case "add_member":
            return _status(
                h,
                "post",
                f"/cases/{cid}/members",
                user,
                json={"user_id": str(w.auditor.id), "role": "auditor"},
            )
        case "add_evidence":
            return _status(
                h,
                "post",
                f"/cases/{cid}/evidence",
                user,
                json={"kind": "file", "original_name": "x.bin"},
            )
        case "list_evidence":
            return _status(h, "get", f"/cases/{cid}/evidence", user)
        case "read_evidence":
            return _status(h, "get", f"/evidence/{eid}", user)
        case "verify":
            return _status(h, "post", f"/evidence/{eid}/verify", user)
        case "custody":
            return _status(h, "get", f"/evidence/{eid}/custody", user)
        case "download":
            return _status(h, "get", f"/evidence/{eid}/download", user)
    raise AssertionError(action)


@pytest.mark.parametrize("action", sorted(EXPECTED))
def test_role_matrix_over_api(h: Harness, world: World, action: str) -> None:
    got = {role: _do(h, world, action, world.role(role)) for role in ROLES}
    assert got == EXPECTED[action]


def test_viewer_cannot_upload_or_finalize(h: Harness, world: World) -> None:
    ev = h.create_evidence(world.analyst, world.case["id"])
    assert h.upload(world.viewer, ev["id"], b"x").status_code == 403
    assert h.upload(world.auditor, ev["id"], b"x").status_code == 403
    assert h.upload(world.outsider, ev["id"], b"x").status_code == 404
    assert h.upload(world.analyst, ev["id"], b"x").status_code == 200
    assert h.post(f"/evidence/{ev['id']}/finalize", world.viewer).status_code == 403


def test_case_role_caps_global_role(h: Harness) -> None:
    owner = h.make_user(UserRole.lead)
    capped = h.make_user(UserRole.lead)
    case = h.create_case(owner)
    ev = h.stored_evidence(owner, case["id"])
    h.add_member(owner, case["id"], capped, UserRole.viewer)
    assert h.get(f"/cases/{case['id']}", capped).json()["my_permissions"] == ["case:read"]
    r = h.post(f"/cases/{case['id']}/evidence", capped, json={"kind": "log", "original_name": "a"})
    assert r.status_code == 403
    assert h.get(f"/evidence/{ev['id']}/download", capped).status_code == 403
    # The same user keeps full lead rights on their own case.
    own = h.create_case(capped)
    r = h.post(f"/cases/{own['id']}/evidence", capped, json={"kind": "log", "original_name": "a"})
    assert r.status_code == 201


def test_case_listing_is_scoped(h: Harness, world: World) -> None:
    def ids(user: UserCtx) -> set[str]:
        body = h.get("/cases?limit=200", user).json()
        return {c["id"] for c in body["items"]}

    assert world.case["id"] in ids(world.viewer)
    assert world.case["id"] in ids(world.auditor)
    assert world.case["id"] in ids(world.admin)
    assert world.case["id"] not in ids(world.outsider)


def test_unknown_ids_are_404(h: Harness, world: World) -> None:
    assert h.get(f"/cases/{uuid.uuid4()}", world.admin).status_code == 404
    assert h.get(f"/evidence/{uuid.uuid4()}", world.admin).status_code == 404


def test_case_lifecycle_transitions_and_close(h: Harness, world: World) -> None:
    cid = world.case["id"]

    def move(user: UserCtx, status: str) -> int:
        return int(h.patch(f"/cases/{cid}", user, json={"status": status}).status_code)

    assert move(world.analyst, "containment") == 200  # forward, skipping triage
    assert move(world.analyst, "triage") == 200  # one step back
    assert move(world.analyst, "recovery") == 200
    r = h.patch(f"/cases/{cid}", world.analyst, json={"status": "open"})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invalid_state"
    assert move(world.analyst, "closed") == 409  # only via /close

    pending = h.create_evidence(world.analyst, cid)
    r = h.post(f"/cases/{cid}/close", world.lead, json={"reason": "done"})
    assert r.status_code == 409
    assert r.json()["error"]["details"]["evidence"] == [pending["label"]]
    h.upload(world.analyst, pending["id"], b"late")
    assert h.post(f"/evidence/{pending['id']}/finalize", world.analyst).status_code == 200

    assert h.post(f"/cases/{cid}/close", world.analyst, json={}).status_code == 403
    r = h.post(f"/cases/{cid}/close", world.lead, json={"reason": "done"})
    assert r.status_code == 200 and r.json()["status"] == "closed" and r.json()["closed_at"]
    # Closed cases are read-only; evidence can still be verified (and downloaded by L/U).
    assert h.patch(f"/cases/{cid}", world.analyst, json={"title": "x"}).status_code == 409
    r = h.post(f"/cases/{cid}/evidence", world.lead, json={"kind": "log", "original_name": "a"})
    assert r.status_code == 409
    assert h.post(f"/evidence/{world.evidence['id']}/verify", world.auditor).status_code == 200
    # Reopen needs case:manage.
    assert move(world.analyst, "open") == 403
    assert move(world.lead, "open") == 200


def test_members_crud(h: Harness, world: World) -> None:
    cid = world.case["id"]
    members = {m["email"]: m for m in h.get(f"/cases/{cid}/members", world.viewer).json()}
    assert members[world.lead.email]["case_role"] == "lead"
    assert members[world.viewer.email]["case_role"] == "viewer"
    assert h.delete(f"/cases/{cid}/members/{world.viewer.id}", world.analyst).status_code == 403
    assert h.delete(f"/cases/{cid}/members/{world.viewer.id}", world.lead).status_code == 204
    assert h.get(f"/cases/{cid}", world.viewer).status_code == 404
    assert h.delete(f"/cases/{cid}/members/{world.viewer.id}", world.lead).status_code == 404


def test_case_number_generation_and_validation(h: Harness) -> None:
    lead = h.make_user(UserRole.lead)
    a = h.create_case(lead)
    b = h.create_case(lead)
    assert a["case_number"].startswith("IR-") and a["case_number"] != b["case_number"]
    assert int(b["case_number"].rsplit("-", 1)[1]) == int(a["case_number"].rsplit("-", 1)[1]) + 1
    r = h.post("/cases", lead, json={"title": "x", "case_number": "bad"})
    assert r.status_code == 422
    custom = f"IR-2031-{uuid.uuid4().int % 10**6:06d}"
    assert h.post("/cases", lead, json={"title": "x", "case_number": custom}).status_code == 201
    r = h.post("/cases", lead, json={"title": "x", "case_number": custom})
    assert r.status_code == 409


def test_every_api_request_is_audited(h: Harness, world: World, db_engine: Engine) -> None:
    rid = f"audit-{uuid.uuid4().hex}"
    r = h.client.get(
        f"/api/v1/evidence/{world.evidence['id']}",
        headers={**world.viewer.headers, "X-Request-ID": rid},
    )
    assert r.status_code == 200
    h.client.get("/api/v1/me")  # unauthenticated requests are audited too
    with db_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT user_id, host(ip), method, path, status, action, object_type, object_id "
                "FROM audit_log WHERE detail->>'request_id' = :rid"
            ),
            {"rid": rid},
        ).one()
        anon = conn.execute(
            text(
                "SELECT status FROM audit_log WHERE path = '/api/v1/me' AND user_id IS NULL "
                "ORDER BY id DESC LIMIT 1"
            )
        ).scalar_one()
        health = conn.execute(
            text("SELECT count(*) FROM audit_log WHERE path = '/api/v1/health'")
        ).scalar_one()
    assert row.user_id == world.viewer.id
    assert row.host == CLIENT_IP
    assert (row.method, row.status, row.action) == ("GET", 200, "read")
    assert (row.object_type, row.object_id) == ("evidence", world.evidence["id"])
    assert anon == 401
    assert health == 0


def test_audit_query_filters(h: Harness, world: World) -> None:
    r = h.get(f"/audit?user_id={world.lead.id}&action=case.created", world.auditor)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] >= 1
    assert all(item["action"] == "case.created" for item in body["items"])
    r = h.get(f"/audit?object_type=evidence&object_id={world.evidence['id']}", world.admin)
    actions = {item["action"] for item in r.json()["items"]}
    assert {"evidence.created", "evidence.uploaded", "evidence.finalized"} <= actions
