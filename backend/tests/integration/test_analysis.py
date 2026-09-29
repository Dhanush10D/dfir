"""Phase 4: search language, facets, histogram, context, export, notes, bookmarks, entities,
graph, process tree, summary and the refresh-token cookie, end to end through the API."""

from __future__ import annotations

import csv
import hashlib
import io
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from app.db.models import Event, UserRole
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
EVTX = (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes()
T0 = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)
G = {n: f"{{{n * 8}-{n * 4}-{n * 4}-{n * 4}-{n * 12}}}" for n in "abcdef"}


class World:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.lead = h.make_user(UserRole.lead)
        self.analyst = h.make_user(UserRole.analyst)
        self.analyst2 = h.make_user(UserRole.analyst)
        self.viewer = h.make_user(UserRole.viewer)
        self.outsider = h.make_user(UserRole.analyst)
        self.cid = h.create_case(self.lead, "Analysis case")["id"]
        for user, role in (
            (self.analyst, UserRole.analyst),
            (self.analyst2, UserRole.analyst),
            (self.viewer, UserRole.viewer),
        ):
            h.add_member(self.lead, self.cid, user, role)
        self.other_cid = h.create_case(self.outsider, "Other case")["id"]
        auth = h.stored_evidence(self.analyst, self.cid, AUTH_LOG, original_name="auth.log")
        evtx = h.stored_evidence(
            self.analyst, self.cid, EVTX, original_name="Security.evtx", kind="evtx"
        )
        for ev, parser in ((auth, "linux_auth"), (evtx, "evtx")):
            r = h.post(f"/evidence/{ev['id']}/process", self.analyst, json={"parsers": [parser]})
            assert r.status_code == 202, r.text
        assert {r.outcome for r in h.run_pending()} == {"succeeded"}
        self.add_synthetic()
        self.detect()

    def add_synthetic(self) -> None:
        """Sysmon-like process events (guid chain + a guid cycle), 4688-like pid/ppid events with
        PID reuse, FQDN/short host names and a formula-looking message."""

        def ev(minute: int, **kw: Any) -> Event:
            return Event(
                case_id=uuid.UUID(self.cid),
                ts=T0 + timedelta(minutes=minute),
                source_type="evtx",
                parser_name="synthetic",
                **kw,
            )

        def sysmon(minute: int, pid: int, ppid: int, image: str, guid: str, pguid: str) -> Event:
            return ev(
                minute,
                host="WS-042",
                event_code="1",
                event_category="process",
                action="create",
                pid=pid,
                ppid=ppid,
                process_name=image.rsplit("\\", 1)[-1],
                file_path=image,
                cmdline=f"{image} -x",
                user="CORP\\alice",
                raw={"event_data": {"ProcessGuid": guid, "ParentProcessGuid": pguid}},
            )

        rows = [
            sysmon(1, 100, 4, "C:\\Windows\\explorer.exe", G["a"], G["f"]),
            sysmon(2, 200, 100, "C:\\Office\\WINWORD.EXE", G["b"], G["a"]),
            sysmon(
                3,
                300,
                200,
                "C:\\Windows\\System32\\WindowsPowerShell\\powershell.exe",
                G["c"],
                G["b"],
            ),
            # a guid cycle (hostile data): d -> e -> d
            sysmon(4, 400, 401, "C:\\x\\d.exe", G["d"], G["e"]),
            sysmon(4, 401, 400, "C:\\x\\e.exe", G["e"], G["d"]),
            # 4688-like (no guids): pid 500 is reused; the child must attach to the second one.
            ev(
                5,
                host="WS-042",
                event_code="4688",
                event_category="process",
                action="create",
                pid=500,
                ppid=100,
                process_name="cmd.exe",
            ),
            ev(
                6,
                host="WS-042",
                event_code="4689",
                event_category="process",
                action="terminate",
                pid=500,
                process_name="cmd.exe",
            ),
            ev(
                7,
                host="WS-042",
                event_code="4688",
                event_category="process",
                action="create",
                pid=500,
                ppid=100,
                process_name="rundll32.exe",
            ),
            ev(
                8,
                host="WS-042",
                event_code="4688",
                event_category="process",
                action="create",
                pid=600,
                ppid=500,
                process_name="child.exe",
            ),
            ev(
                9,
                host="WS-042",
                event_code="4104",
                message="=cmd|' /C calc'!A0",
                cmdline="@SUM(1+1)",
                process_name="powershell.exe",
                pid=300,
            ),
            ev(
                10,
                host="ws-042.corp.local",
                event_code="4624",
                event_category="authentication",
                action="logon",
                outcome="success",
                user="alice@corp.local",
                src_ip="10.0.4.17",
            ),
        ]
        with self.h.sessions() as session:
            session.add_all(rows)
            session.commit()

    def detect(self) -> None:
        r = self.h.post(f"/cases/{self.cid}/detect", self.analyst, json={})
        assert r.status_code == 202, r.text
        assert {r.outcome for r in self.h.run_detect_pending()} == {"succeeded"}

    def search(self, query: str, user: UserCtx | None = None, **body: Any) -> Any:
        return self.h.post(
            f"/cases/{self.cid}/events/search", user or self.viewer, json={"query": query, **body}
        )

    def hits(self, query: str, **body: Any) -> list[dict[str, Any]]:
        r = self.search(query, limit=500, **body)
        assert r.status_code == 200, r.text
        return list(r.json()["items"])


@pytest.fixture
def world(h: Harness) -> World:
    return World(h)


def _count(db: Engine, sql: str, **params: Any) -> int:
    with db.connect() as conn:
        return int(conn.execute(text(sql), params).scalar_one())


# ---------------------------------------------------------------------------------- search


def test_search_language_end_to_end(world: World, db_engine: Engine) -> None:
    h = world.h
    assert len(world.hits("host:web01 AND event_code:ssh_failed")) == 3
    assert (
        len(world.hits("host:WEB01 event_code:SSH_FAILED")) == 3
    )  # case-insensitive, implicit AND
    assert {e["src_ip"] for e in world.hits("src_ip:203.0.113.0/24")} == {"203.0.113.50"}
    assert world.hits('"session opened"')  # phrase over message + cmdline (FTS)
    assert len(world.hits("cmdline:*systemctl*")) == 1
    everything = world.hits("")
    assert len(everything) == 22 + 4 + 11
    not_web = world.hits("NOT host:web01")
    assert len(not_web) == len(everything) - 22  # NOT includes rows without the field
    assert world.hits("user:* AND NOT user:deploy")
    ts = world.hits("ts:[2026-09-14T08:00:00Z TO 2026-09-14T08:03:00Z]")
    assert len(ts) == 3
    assert {e["pid"] for e in world.hits("pid:[400 TO 401]")} == {400, 401}
    assert world.hits("attack_tags:T1136*") and world.hits("attack_tags:T1136.001")
    # hostile values are data, never SQL
    for hostile in ('host:"x\' OR 1=1 --"', 'message:"%\' ; DROP TABLE events; --"', "user:'"):
        r = world.search(hostile)
        assert r.status_code == 200 and r.json()["items"] == [], hostile
    assert _count(db_engine, "SELECT count(*) FROM events") > 0
    # errors carry a position
    for bad, pos in (("host:", 5), ("nosuch:x", 0), ("cmdline:*ab", 8), ("(a", 0), ("a AND", 5)):
        r = world.search(bad)
        assert r.status_code == 422, bad
        err = r.json()["error"]
        assert err["code"] == "invalid_query" and err["details"]["position"] == pos, (bad, err)
    assert world.search("x" * 2001).status_code == 422
    # keyset paging
    first = world.search("", limit=10).json()
    second = world.search("", limit=10, cursor=first["next_cursor"]).json()
    assert first["next_cursor"] and not {e["id"] for e in first["items"]} & {
        e["id"] for e in second["items"]
    }
    # time bounds need a zone; RBAC and case scope
    assert world.search("", **{"from": "2026-01-01T00:00:00"}).status_code == 422
    assert world.search("", world.outsider).status_code == 404
    r = h.post(f"/cases/{world.other_cid}/events/search", world.viewer, json={"query": ""})
    assert r.status_code == 404
    assert h.post(f"/cases/{world.cid}/events/search", None, json={}).status_code == 401
    assert _count(db_engine, "SELECT count(*) FROM audit_log WHERE action = 'events.search'") >= 10
    fields = h.get("/search/fields", world.viewer).json()
    assert {"name": "ts", "type": "ts", "ops": ["range"]} in fields


def test_facets_and_histogram_are_bounded(world: World) -> None:
    h, cid = world.h, world.cid
    r = h.post(
        f"/cases/{cid}/events/facets",
        world.viewer,
        json={"query": "", "fields": ["host", "source_type", "attack_tags", "src_ip"], "size": 3},
    )
    assert r.status_code == 200, r.text
    f = r.json()["fields"]
    assert f["host"][0] == {"value": "web01", "count": 22} and len(f["host"]) <= 3
    assert {v["value"] for v in f["source_type"]} >= {"auth_log", "evtx"}
    assert f["attack_tags"] and all(v["value"].startswith("T") for v in f["attack_tags"])
    for body in (
        {"fields": ["nope"]},
        {"fields": []},
        {"fields": ["host"] * 9},
        {"fields": ["host"], "size": 51},
        {"fields": ["host"], "query": "host:"},
    ):
        assert h.post(f"/cases/{cid}/events/facets", world.viewer, json=body).status_code == 422

    r = h.post(f"/cases/{cid}/events/histogram", world.viewer, json={"buckets": 20})
    assert r.status_code == 200, r.text
    hist = r.json()
    assert len(hist["buckets"]) <= 22 and hist["total"] == 37
    assert sum(b["count"] for b in hist["buckets"]) == 37
    assert set(hist["series"]) >= {"auth_log", "evtx"}
    r = h.post(
        f"/cases/{cid}/events/histogram",
        world.viewer,
        json={"query": "host:ws-042", "from": "2026-09-14T08:00:00Z", "to": "2026-09-14T09:00:00Z"},
    )
    hist = r.json()
    assert hist["interval_seconds"] == 60 and hist["total"] == 10, hist  # 1-hour span, 60 buckets
    assert hist["from"] == "2026-09-14T08:00:00Z"
    assert (
        h.post(f"/cases/{cid}/events/histogram", world.viewer, json={"buckets": 5}).status_code
        == 422
    )
    r = h.post(f"/cases/{cid}/events/histogram", world.viewer, json={"query": "host:nothing"})
    assert r.status_code == 200 and r.json()["buckets"] == [] and r.json()["total"] == 0
    r = h.post(f"/cases/{cid}/events/histogram", world.outsider, json={})
    assert r.status_code == 404


def test_context_and_export(world: World, db_engine: Engine) -> None:
    h, cid = world.h, world.cid
    anchor = world.hits("event_code:4689")[0]
    r = h.post(
        f"/cases/{cid}/events/context",
        world.viewer,
        json={"event_id": anchor["id"], "minutes": 2},
    )
    assert r.status_code == 200, r.text
    ctx = r.json()
    assert ctx["anchor"]["id"] == anchor["id"]
    assert {e["event_code"] for e in ctx["items"]} >= {"4688", "4689"}
    assert all(e["host"].lower() == "ws-042" for e in ctx["items"])
    r = h.post(f"/cases/{cid}/events/context", world.viewer, json={"event_id": str(uuid.uuid4())})
    assert r.status_code == 404

    r = h.post(f"/cases/{cid}/events/export", world.viewer, json={"query": ""})
    assert r.status_code == 403  # export needs `investigate`
    r = h.post(
        f"/cases/{cid}/events/export", world.analyst, json={"query": "host:ws-042", "limit": 5}
    )
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["x-export-rows"] == "5" and r.headers["x-export-truncated"] == "true"
    assert r.headers["x-export-sha256"] == hashlib.sha256(r.content).hexdigest()
    r = h.post(f"/cases/{cid}/events/export", world.analyst, json={"query": "event_code:4104"})
    rows = list(csv.DictReader(io.StringIO(r.content.decode())))
    assert rows[0]["message"] == "'=cmd|' /C calc'!A0"  # formula neutralised
    assert rows[0]["cmdline"] == "'@SUM(1+1)"
    r = h.post(
        f"/cases/{cid}/events/export", world.analyst, json={"format": "json", "limit": 100000}
    )
    assert r.status_code == 422
    r = h.post(f"/cases/{cid}/events/export", world.analyst, json={"format": "json"})
    assert r.status_code == 200 and len(r.json()) == 37
    detail = _count(
        db_engine,
        "SELECT count(*) FROM audit_log WHERE action = 'events.exported' "
        "AND detail->>'sha256' = :d",
        d=hashlib.sha256(r.content).hexdigest(),
    )
    assert detail == 1


# ---------------------------------------------------------------------------------- notes


def test_notes_are_versioned_and_retractable(world: World, db_engine: Engine) -> None:
    h, cid = world.h, world.cid
    event = world.hits("event_code:user_created")[0]
    path = f"/cases/{cid}/notes"
    body = {
        "body_md": "<script>alert(1)</script> suspicious",
        "target_type": "event",
        "target_id": event["id"],
        "tags": ["persistence"],
    }
    assert h.post(path, world.viewer, json=body).status_code == 403
    r = h.post(path, world.analyst, json=body)
    assert r.status_code == 201, r.text
    note = r.json()
    assert note["version"] == 1 and note["body_md"] == body["body_md"]  # stored verbatim
    nid = note["id"]
    # target must exist in this case
    other = h.stored_evidence(world.outsider, world.other_cid, b"x\n")
    bad = {"body_md": "x", "target_type": "evidence", "target_id": other["id"]}
    assert h.post(path, world.analyst, json=bad).status_code == 404
    assert (
        h.post(
            path, world.analyst, json={"body_md": "x", "target_type": "event", "target_id": "nope"}
        ).status_code
        == 422
    )
    assert h.get(f"/notes/{nid}", world.outsider).status_code == 404
    # edit: author only, optimistic version
    edit = {"body_md": "v2", "expected_version": 1}
    assert h.patch(f"/notes/{nid}", world.analyst2, json=edit).status_code == 403
    assert (
        h.patch(f"/notes/{nid}", world.analyst, json={**edit, "expected_version": 7}).status_code
        == 409
    )
    r = h.patch(f"/notes/{nid}", world.analyst, json=edit)
    assert r.status_code == 200 and r.json()["version"] == 2
    assert [v["action"] for v in r.json()["versions"]] == ["created", "edited"]
    assert r.json()["versions"][0]["body_md"] == body["body_md"]  # history kept
    # concurrent edits with the same expected version: exactly one wins
    results: list[int] = []
    barrier = threading.Barrier(2)

    def attempt(text_: str) -> None:
        barrier.wait()
        resp = h.patch(
            f"/notes/{nid}", world.analyst, json={"body_md": text_, "expected_version": 2}
        )
        results.append(resp.status_code)

    threads = [threading.Thread(target=attempt, args=(t,)) for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200, 409]
    # retract: author or case manager; listing hides retracted by default
    assert (
        h.post(f"/notes/{nid}/retract", world.analyst2, json={"expected_version": 3}).status_code
        == 403
    )
    r = h.post(f"/notes/{nid}/retract", world.lead, json={"expected_version": 3, "reason": "dup"})
    assert r.status_code == 200 and r.json()["retracted_at"] and r.json()["version"] == 4
    assert (
        h.patch(
            f"/notes/{nid}", world.analyst, json={"body_md": "z", "expected_version": 4}
        ).status_code
        == 409
    )
    listed = h.get(path, world.viewer).json()
    assert listed["total"] == 0
    listed = h.get(path, world.viewer, params={"include_retracted": "true"}).json()
    assert listed["total"] == 1 and listed["items"][0]["id"] == nid
    assert _count(db_engine, "SELECT count(*) FROM note_versions WHERE note_id = :n", n=nid) == 4
    assert _count(db_engine, "SELECT count(*) FROM audit_log WHERE action LIKE 'note.%'") >= 4
    # closed case is read-only
    assert h.post(f"/cases/{cid}/close", world.lead, json={"reason": "done"}).status_code == 200
    assert h.post(path, world.analyst, json={"body_md": "late"}).status_code == 409
    assert h.get(path, world.viewer).status_code == 200


def test_bookmarks(world: World, db_engine: Engine) -> None:
    h, cid = world.h, world.cid
    event = world.hits("event_code:ssh_failed")[0]
    path = f"/cases/{cid}/bookmarks"
    body = {"target_type": "event", "target_id": event["id"], "comment": "first failure"}
    assert h.post(path, world.viewer, json=body).status_code == 403
    assert h.get(path, world.viewer).status_code == 403
    r1 = h.post(path, world.analyst, json=body)
    r2 = h.post(path, world.analyst, json=body)
    assert (r1.status_code, r2.status_code) == (201, 200)
    assert r1.json()["id"] == r2.json()["id"]
    bid = r1.json()["id"]
    listed = h.get(path, world.analyst2).json()
    assert len(listed) == 1 and listed[0]["event"]["id"] == event["id"]
    assert h.get(path, world.analyst2, params={"mine": "true"}).json() == []
    missing_alert = {"target_type": "alert", "target_id": str(uuid.uuid4())}
    assert h.post(path, world.analyst, json=missing_alert).status_code == 404
    assert h.delete(f"{path}/{bid}", world.analyst2).status_code == 403
    assert h.delete(f"/cases/{world.other_cid}/bookmarks/{bid}", world.outsider).status_code == 404
    assert h.delete(f"{path}/{bid}", world.analyst).status_code == 204
    assert h.delete(f"{path}/{bid}", world.analyst).status_code == 404
    assert (
        _count(db_engine, "SELECT count(*) FROM audit_log WHERE action = 'bookmark.deleted'") == 1
    )


# ---------------------------------------------------------------------------------- entities


def test_entity_resolution_and_graph(world: World, db_engine: Engine) -> None:
    h, cid = world.h, world.cid

    def entities(**params: Any) -> list[dict[str, Any]]:
        r = h.get(f"/cases/{cid}/entities", world.viewer, params={"limit": 500, **params})
        assert r.status_code == 200, r.text
        return list(r.json()["items"])

    hosts = {e["canonical"]: e for e in entities(type="host")}
    assert {"web01", "ie8win7", "ws-042"} <= set(hosts)  # WS-042 + ws-042.corp.local merged
    users = {e["canonical"] for e in entities(type="user")}
    # CORP\alice and alice@corp.local are one user; the EVTX SID was merged with its account name
    assert "corp\\alice" in users and "alice@corp.local" not in users
    assert "workgroup\\win-qala5q3kj43$" in users and "S-1-5-18" not in users
    assert {e["canonical"] for e in entities(type="ip")} >= {"203.0.113.50", "10.0.4.17"}
    assert entities(q="corp.local")  # alias search
    assert (
        h.get(f"/cases/{cid}/entities", world.viewer, params={"type": "bogus"}).status_code == 422
    )

    detail = h.get(f"/entities/{hosts['ws-042']['id']}", world.viewer).json()
    aliases = {(a["alias_type"], a["alias"]) for a in detail["aliases"]}
    assert ("fqdn", "ws-042.corp.local") in aliases and ("hostname", "ws-042") in aliases
    assert {n["relation"] for n in detail["neighbours"]} >= {"logged_on", "ran_on", "connected_to"}
    # the pivot query is valid search language and finds the host's events under both names
    pivot = detail["pivot_query"]
    assert len(world.hits(pivot)) == 11
    sid_user = next(e for e in entities(type="user") if e["canonical"].startswith("workgroup\\"))
    sid_aliases = {
        a["alias"] for a in h.get(f"/entities/{sid_user['id']}", world.viewer).json()["aliases"]
    }
    assert "S-1-5-18" in sid_aliases
    assert h.get(f"/entities/{sid_user['id']}", world.outsider).status_code == 404

    g = h.get(f"/cases/{cid}/graph", world.viewer, params={"max_nodes": 3}).json()
    assert len(g["nodes"]) == 3 and g["truncated"] is True
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["src_entity"] in ids and e["dst_entity"] in ids for e in g["edges"])
    g = h.get(
        f"/cases/{cid}/graph",
        world.viewer,
        params={"entity_id": hosts["web01"]["id"], "depth": 1, "types": "user"},
    ).json()
    types = {n["type"] for n in g["nodes"]}
    assert types == {"host", "user"} and len(g["nodes"]) > 1
    for params in ({"max_nodes": 501}, {"depth": 3}, {"types": "nope"}):
        assert h.get(f"/cases/{cid}/graph", world.viewer, params=params).status_code == 422
    assert h.get(f"/cases/{cid}/graph", world.outsider).status_code == 404

    before = _count(db_engine, "SELECT count(*) FROM entities WHERE case_id = :c", c=cid)
    links = _count(db_engine, "SELECT count(*) FROM entity_links WHERE case_id = :c", c=cid)
    world.detect()  # rerun: idempotent
    assert _count(db_engine, "SELECT count(*) FROM entities WHERE case_id = :c", c=cid) == before
    assert _count(db_engine, "SELECT count(*) FROM entity_links WHERE case_id = :c", c=cid) == links
    job = h.get(f"/cases/{cid}/jobs", world.viewer).json()["items"]
    manifest = next(j for j in job if j["kind"] == "detect")
    full = h.get(f"/jobs/{manifest['id']}", world.viewer).json()["run_manifest"]
    assert full["entities"]["entities"] == before and full["entities"]["capped"] is False


def test_process_tree(world: World) -> None:
    h, cid = world.h, world.cid
    r = h.get(f"/cases/{cid}/process-tree", world.viewer, params={"host": "ws-042"})
    assert r.status_code == 200, r.text
    tree = r.json()
    by_name: dict[str, list[dict[str, Any]]] = {}
    for node in tree["nodes"]:
        by_name.setdefault(node["name"] or "?", []).append(node)
    by_key = {n["key"]: n for n in tree["nodes"]}
    ps = by_name["powershell.exe"][0]
    word = by_key[ps["parent"]]
    assert word["name"] == "winword.exe" and "suspicious_parent" in ps["flags"]
    assert by_key[word["parent"]]["name"] == "explorer.exe"
    assert ps["depth"] == 3 and ps["cmdline"].endswith("-x")  # under a synthetic pid-4 root
    assert tree["cycles_broken"] == 1
    # PID reuse: child.exe (ppid 500 at 08:08) attaches to rundll32 (pid 500 since 08:07)
    child = by_name["child.exe"][0]
    assert by_key[child["parent"]]["name"] == "rundll32.exe"
    # explorer's parent pid 4 is not in the data: synthetic parent
    assert by_key[by_key[word["parent"]]["parent"]]["kind"] == "synthetic"
    capped = h.get(
        f"/cases/{cid}/process-tree", world.viewer, params={"host": "WS-042", "max_depth": 1}
    ).json()
    assert capped["depth_capped"] >= 1 and all(n["depth"] <= 1 for n in capped["nodes"])
    linux = h.get(f"/cases/{cid}/process-tree", world.viewer, params={"host": "web01"}).json()
    assert {n["name"] for n in linux["nodes"]} >= {"sshd"}
    assert h.get(f"/cases/{cid}/process-tree", world.viewer).status_code == 422
    assert (
        h.get(f"/cases/{cid}/process-tree", world.outsider, params={"host": "x"}).status_code == 404
    )


def test_summary(world: World) -> None:
    r = world.h.get(f"/cases/{world.cid}/summary", world.viewer)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["events"] == 37 and s["evidence"] == 2 and s["entities"] > 5
    assert s["top_hosts"][0] == {"value": "web01", "count": 22}
    assert sum(s["alerts_by_status"].values()) >= 7 and 0 < s["risk"]["case_risk"] <= 100
    assert world.h.get(f"/cases/{world.cid}/summary", world.outsider).status_code == 404


# ---------------------------------------------------------------------------------- grants


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE note_versions SET body_md = 'x'",
        "DELETE FROM note_versions",
        "DELETE FROM notes",
        "UPDATE notes SET case_id = case_id",
        "UPDATE notes SET author_id = author_id",
        "UPDATE bookmarks SET comment = 'x'",
        "DELETE FROM entities",
        "DELETE FROM entity_links",
        "DELETE FROM entity_aliases",
        "UPDATE entity_aliases SET alias = 'x'",
    ],
)
def test_app_role_grants_on_analysis_tables(app_engine: Engine, statement: str) -> None:
    denied = r"permission denied|append-only"
    with pytest.raises(DBAPIError, match=denied), app_engine.begin() as conn:
        conn.execute(text(statement))


# ---------------------------------------------------------------------------------- cookie


def test_refresh_cookie_flow(h: Harness) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    cookie_mode = {"X-Token-Delivery": "cookie"}
    r = h.client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": user.password},
        headers=cookie_mode,
    )
    assert r.status_code == 200, r.text
    tokens = r.json()["tokens"]
    assert tokens["access_token"] and tokens["refresh_token"] is None
    set_cookie = r.headers["set-cookie"]
    for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/api/v1/auth", "Max-Age="):
        assert attr.lower() in set_cookie.lower(), set_cookie
    refresh = set_cookie.split(";", 1)[0].split("=", 1)[1]
    h.client.cookies.clear()
    jar = {"Cookie": f"dfir_refresh={refresh}"}
    # without the custom header the cookie is ignored (CSRF defence)
    assert h.client.post("/api/v1/auth/refresh", headers=jar).status_code == 401
    r = h.client.post("/api/v1/auth/refresh", headers={**jar, **cookie_mode})
    assert r.status_code == 200 and r.json()["refresh_token"] is None
    rotated = r.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    assert rotated != refresh
    me = h.client.get("/api/v1/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.status_code == 200
    # reuse of the rotated token kills the session family
    r = h.client.post("/api/v1/auth/refresh", headers={**jar, **cookie_mode})
    assert r.status_code == 401 and r.json()["error"]["code"] == "refresh_reused"
    # logout clears the cookie; body mode still works for API clients
    r = h.client.post(
        "/api/v1/auth/logout", headers={"Cookie": f"dfir_refresh={rotated}", **cookie_mode}
    )
    assert r.status_code == 204 and "max-age=0" in r.headers["set-cookie"].lower()
    r = h.client.post("/api/v1/auth/login", json={"email": user.email, "password": user.password})
    assert r.json()["tokens"]["refresh_token"] and "set-cookie" not in r.headers
    assert h.client.post("/api/v1/auth/logout").status_code == 401
    h.client.cookies.clear()
