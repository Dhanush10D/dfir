#!/usr/bin/env python3
"""Phase 4 live smoke test against the running compose stack (stdlib only).

    python scripts/phase4-smoke.py --admin-email E [--admin-password P] [--base URL] [--web URL]

1. an analyst uploads the auth.log and new_user_security.evtx fixtures; parse + detection run;
2. search (language, bad query -> 422 with position, SQL-injection string is inert data, outsider
   -> 404), facets, histogram, context, export (viewer 403; CSV hash matches the header);
3. versioned notes (edit, stale edit -> 409, retract) and idempotent bookmarks;
4. entities from the detection run, entity detail, bounded graph, process tree, case summary;
5. browser token delivery: login with ``X-Token-Delivery: cookie`` sets an HttpOnly/Secure/
   SameSite=Strict refresh cookie (no refresh token in JSON); refresh needs the header;
6. the web container answers with the strict CSP on the SPA, on /assets/* and on /api.
Exits non-zero on the first failed expectation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import urllib.error
import urllib.request
import uuid
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
p3 = _load("phase3_smoke", "phase3-smoke.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user


def raw(
    url: str,
    method: str = "GET",
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, list[str]], bytes]:
    """Plain HTTP call that also returns the response headers (all values per name)."""
    hdrs = {"Accept": "*/*", **(headers or {})}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - local URL
            status, msg, content = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        status, msg, content = exc.code, exc.headers, exc.read()
    out: dict[str, list[str]] = {}
    for key, value in msg.items():
        out.setdefault(key.lower(), []).append(value)
    return status, out, content


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--web", default="http://127.0.0.1:8080")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    args = parser.parse_args()
    api = Api(args.base)
    admin = login(api, args.admin_email, args.admin_password)
    _, lead = make_user(api, admin, "lead")
    analyst_id, analyst = make_user(api, admin, "analyst")
    viewer_id, viewer = make_user(api, admin, "viewer")
    _, outsider = make_user(api, admin, "analyst")
    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 4 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call(
            "POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role}
        )
        expect(status == 200, f"lead adds {role}", body)

    # ---- data: parse two fixtures; detection (with entity resolution) runs automatically
    ids = [
        p2.stored(
            api, analyst, cid, "auth.log", "log", (FIXTURES / "linux" / "auth.log").read_bytes()
        ),
        p2.stored(
            api,
            analyst,
            cid,
            "Security.evtx",
            "evtx",
            (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes(),
        ),
    ]
    for eid in ids:
        status, body, _ = api.call("POST", f"/evidence/{eid}/process", analyst, {})
        expect(status == 202, "parse job queued", body)
    detects = p3.settle(api, analyst, cid)
    expect(all(j["status"] == "succeeded" for j in detects), "parse + detection finished", detects)

    # ---- search
    status, fields, _ = api.call("GET", "/search/fields", viewer)
    expect(
        status == 200 and any(f["name"] == "host" for f in fields), "search field catalogue", fields
    )
    status, facets, _ = api.call(
        "POST",
        f"/cases/{cid}/events/facets",
        viewer,
        {"fields": ["host", "source_type", "user"], "size": 5},
    )
    expect(
        status == 200 and facets["fields"]["host"] and len(facets["fields"]["host"]) <= 5,
        "facets (bounded)",
        facets,
    )
    host = facets["fields"]["host"][0]["value"]
    status, page, _ = api.call(
        "POST", f"/cases/{cid}/events/search", viewer, {"query": f'host:"{host}"', "limit": 50}
    )
    expect(
        status == 200
        and page["items"]
        and all((e["host"] or "").lower() == host.lower() for e in page["items"]),
        f"search host:{host}",
        page,
    )
    status, body, _ = api.call(
        "POST", f"/cases/{cid}/events/search", viewer, {"query": "host:(x OR"}
    )
    expect(
        status == 422
        and body["error"]["code"] == "invalid_query"
        and isinstance(body["error"]["details"].get("position"), int),
        "bad query -> 422 invalid_query with position",
        body,
    )
    status, body, _ = api.call(
        "POST",
        f"/cases/{cid}/events/search",
        viewer,
        {"query": 'message:"x\'; DROP TABLE events; --" OR user:"\' OR 1=1 --"'},
    )
    expect(status == 200 and body["items"] == [], "SQL-injection strings are inert data", body)
    status, body, _ = api.call("POST", f"/cases/{cid}/events/search", outsider, {"query": ""})
    expect(status == 404, "outsider search -> 404", body)

    status, hist, _ = api.call(
        "POST", f"/cases/{cid}/events/histogram", viewer, {"query": "", "buckets": 20}
    )
    expect(
        status == 200
        and hist["total"] > 0
        and 1 <= len(hist["buckets"]) <= 22
        and len(hist["series"]) <= 13,
        "histogram (bounded)",
        hist,
    )
    anchor = page["items"][0]
    status, ctx, _ = api.call(
        "POST",
        f"/cases/{cid}/events/context",
        viewer,
        {"event_id": anchor["id"], "minutes": 60, "limit": 50},
    )
    expect(
        status == 200 and any(e["id"] == anchor["id"] for e in ctx["items"]), "event context", ctx
    )

    export_url = f"{api.base}/cases/{cid}/events/export"
    status, _, _ = raw(export_url, "POST", {"format": "csv"}, {"Authorization": f"Bearer {viewer}"})
    expect(status == 403, "viewer export -> 403", status)
    status, hdrs, content = raw(
        export_url,
        "POST",
        {"query": f'host:"{host}"', "format": "csv", "limit": 100},
        {"Authorization": f"Bearer {analyst}"},
    )
    expect(
        status == 200
        and content.startswith(b"id,ts,")
        and hdrs.get("x-export-sha256", [""])[0] == hashlib.sha256(content).hexdigest(),
        "analyst CSV export (hash header matches the body)",
        {"status": status, "headers": hdrs},
    )

    # ---- notes + bookmarks
    status, note, _ = api.call(
        "POST",
        f"/cases/{cid}/notes",
        analyst,
        {"body_md": "first look", "target_type": "event", "target_id": anchor["id"], "tags": ["t"]},
    )
    expect(status == 201 and note["version"] == 1, "analyst creates a note on an event", note)
    status, body, _ = api.call("POST", f"/cases/{cid}/notes", viewer, {"body_md": "nope"})
    expect(status == 403, "viewer cannot write notes", body)
    status, body, _ = api.call(
        "PATCH", f"/notes/{note['id']}", analyst, {"expected_version": 1, "body_md": "second look"}
    )
    expect(
        status == 200 and body["version"] == 2 and len(body["versions"]) == 2, "note edited", body
    )
    status, body, _ = api.call(
        "PATCH", f"/notes/{note['id']}", analyst, {"expected_version": 1, "body_md": "stale"}
    )
    expect(status == 409, "stale note edit -> 409", body)
    status, body, _ = api.call(
        "POST", f"/notes/{note['id']}/retract", analyst, {"expected_version": 2, "reason": "dup"}
    )
    expect(
        status == 200
        and body["retracted_at"]
        and [v["action"] for v in body["versions"]] == ["created", "edited", "retracted"],
        "note retracted, history kept",
        body,
    )
    bm_body = {"target_type": "event", "target_id": anchor["id"], "comment": "look here"}
    status, bm, _ = api.call("POST", f"/cases/{cid}/bookmarks", analyst, bm_body)
    expect(status == 201, "bookmark created", bm)
    status, again, _ = api.call("POST", f"/cases/{cid}/bookmarks", analyst, bm_body)
    expect(status == 200 and again["id"] == bm["id"], "bookmark POST is idempotent", again)
    status, _, _ = api.call("DELETE", f"/cases/{cid}/bookmarks/{bm['id']}", analyst)
    expect(status == 204, "bookmark deleted", status)

    # ---- entities, graph, process tree, summary
    status, ents, _ = api.call("GET", f"/cases/{cid}/entities?limit=200", viewer)
    types = {e["type"] for e in ents.get("items", [])} if status == 200 else set()
    expect(status == 200 and {"host", "user"} <= types, f"entities resolved: {sorted(types)}", ents)
    user = next(e for e in ents["items"] if e["type"] == "user")
    status, detail, _ = api.call("GET", f"/entities/{user['id']}", viewer)
    expect(status == 200 and detail["pivot_query"], "entity detail with pivot query", detail)
    status, body, _ = api.call("GET", f"/entities/{user['id']}", outsider)
    expect(status == 404, "outsider entity -> 404", body)
    status, graph, _ = api.call("GET", f"/cases/{cid}/graph?max_nodes=5&max_edges=10", viewer)
    expect(
        status == 200 and 0 < len(graph["nodes"]) <= 5 and len(graph["edges"]) <= 10,
        "graph (capped)",
        graph,
    )
    pid_hosts = [e["host"] for e in page["items"] if e.get("pid") is not None and e.get("host")]
    tree_host = pid_hosts[0] if pid_hosts else host
    status, tree, _ = api.call(
        "GET", f"/cases/{cid}/process-tree?host={urllib.request.quote(tree_host)}", viewer
    )
    expect(
        status == 200 and (tree["nodes"] or not pid_hosts), f"process tree for {tree_host}", tree
    )
    status, summary, _ = api.call("GET", f"/cases/{cid}/summary", viewer)
    expect(
        status == 200
        and summary["events"] > 0
        and summary["entities"] > 0
        and summary["top_hosts"],
        "case summary",
        summary,
    )

    # ---- refresh cookie
    email = f"smoke-cookie-{uuid.uuid4().hex[:8]}@dfirbench.test"
    status, body, _ = api.call(
        "POST",
        "/users",
        admin,
        {"email": email, "display_name": "Smoke cookie", "role": "viewer", "password": p1.PASSWORD},
    )
    expect(status == 201, "admin creates cookie user", body)
    mode = {"X-Token-Delivery": "cookie"}
    status, hdrs, content = raw(
        f"{api.base}/auth/login", "POST", {"email": email, "password": p1.PASSWORD}, mode
    )
    tokens = json.loads(content).get("tokens") or {}
    cookie = (hdrs.get("set-cookie") or [""])[0]
    lowered = cookie.lower()
    expect(
        status == 200
        and tokens.get("access_token")
        and tokens.get("refresh_token") is None
        and all(
            a in lowered for a in ("httponly", "secure", "samesite=strict", "path=/api/v1/auth")
        ),
        "cookie login: refresh token only in an HttpOnly/Secure/SameSite=Strict cookie",
        {"cookie": re.sub(r"=[^;]+", "=…", cookie, count=1), "status": status},
    )
    jar = {"Cookie": cookie.split(";", 1)[0]}
    status, _, _ = raw(f"{api.base}/auth/refresh", "POST", headers=jar)
    expect(status == 401, "refresh without X-Token-Delivery ignores the cookie (CSRF)", status)
    status, hdrs, content = raw(f"{api.base}/auth/refresh", "POST", headers={**jar, **mode})
    expect(
        status == 200
        and json.loads(content).get("refresh_token") is None
        and hdrs.get("set-cookie"),
        "cookie refresh rotates the cookie",
        status,
    )

    # ---- web CSP
    status, hdrs, index = raw(f"{args.web}/cases")
    csp = (hdrs.get("content-security-policy") or [""])[0]
    expect(
        status == 200
        and b'<div id="root">' in index
        and "default-src 'self'" in csp
        and "script-src 'self'" in csp
        and "'unsafe-inline'" not in csp
        and "'unsafe-eval'" not in csp
        and "frame-ancestors 'none'" in csp
        and "object-src 'none'" in csp,
        "web SPA route answers with the strict CSP",
        hdrs,
    )
    asset = re.search(rb'src="(/assets/[^"]+\.js)"', index)
    expect(asset is not None, "index references a hashed asset", index[:500])
    assert asset is not None
    status, hdrs, _ = raw(args.web + asset.group(1).decode())
    expect(
        status == 200
        and (hdrs.get("content-security-policy") or [""])[0] == csp
        and hdrs.get("x-content-type-options") == ["nosniff"],
        "assets carry the same security headers",
        hdrs,
    )
    status, hdrs, _ = raw(f"{args.web}/api/v1/health")
    expect(
        status == 200 and (hdrs.get("content-security-policy") or [""])[0] == csp,
        "proxied API carries the CSP",
        hdrs,
    )
    print("PHASE 4 SMOKE PASSED")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
