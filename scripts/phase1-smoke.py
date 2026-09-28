#!/usr/bin/env python3
"""Phase 1 live smoke test + tamper demo against the running compose stack (stdlib only).

    python scripts/phase1-smoke.py --admin-email E --admin-password P [--base http://127.0.0.1:8000]

1. admin logs in and creates lead/analyst/viewer/auditor users;
2. lead creates a case and adds members; analyst creates evidence, stream-uploads a file,
   finalizes and verifies it; the stored SHA-256 equals an independent hashlib digest;
3. RBAC: viewer upload -> 403, analyst download -> 403, outsider read -> 404;
4. auditor downloads the original byte-identical; the audit log shows the download;
5. tamper demo: one custody row is edited in Postgres as the owner with triggers bypassed, and
   POST /evidence/{id}/verify must report ok=false with first_broken_seq == 2.
Exits non-zero on the first failed expectation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Smoke-Test-Passphrase-" + uuid.uuid4().hex[:8]


class Api:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/") + "/api/v1"

    def call(
        self,
        method: str,
        path: str,
        token: str | None = None,
        body: Any = None,
        raw: bytes | None = None,
    ) -> tuple[int, Any, bytes]:
        headers = {"Accept": "application/json"}
        data: bytes | None = None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if raw is not None:
            data = raw
            headers["Content-Type"] = "application/octet-stream"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 - local URL
                content = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            content = exc.read()
            status = exc.code
        try:
            parsed = json.loads(content) if content else None
        except ValueError:
            parsed = None
        return status, parsed, content


def expect(cond: bool, message: str, detail: Any = None) -> None:
    if not cond:
        print(f"FAIL: {message}", file=sys.stderr)
        if detail is not None:
            print(json.dumps(detail, indent=2, default=str)[:4000], file=sys.stderr)
        raise SystemExit(1)
    print(f"ok   {message}")


def login(api: Api, email: str, password: str) -> str:
    status, body, _ = api.call("POST", "/auth/login", body={"email": email, "password": password})
    expect(status == 200 and body and body.get("tokens"), f"login {email}", body)
    return str(body["tokens"]["access_token"])


def make_user(api: Api, admin: str, role: str) -> tuple[str, str]:
    email = f"smoke-{role}-{uuid.uuid4().hex[:8]}@dfirbench.test"
    status, body, _ = api.call(
        "POST",
        "/users",
        admin,
        {"email": email, "display_name": f"Smoke {role}", "role": role, "password": PASSWORD},
    )
    expect(status == 201, f"admin creates {role}", body)
    return str(body["id"]), login(api, email, PASSWORD)


def psql(compose: list[str], sql: str) -> None:
    subprocess.run(  # noqa: S603 - fixed argv
        [*compose, "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-U", "dfir", "-d",
         "dfirbench", "-c", sql],
        check=True,
        capture_output=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    parser.add_argument("--compose-file", default=str(ROOT / "infra" / "compose.yaml"))
    args = parser.parse_args()
    api = Api(args.base)
    compose = ["docker", "compose", "-f", args.compose_file]

    admin = login(api, args.admin_email, args.admin_password)
    _, lead = make_user(api, admin, "lead")
    analyst_id, analyst = make_user(api, admin, "analyst")
    viewer_id, viewer = make_user(api, admin, "viewer")
    _, auditor = make_user(api, admin, "auditor")
    _, outsider = make_user(api, admin, "analyst")

    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 1 smoke"})
    expect(status == 201, f"lead creates case {case and case.get('case_number')}", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call("POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role})
        expect(status == 200, f"lead adds {role} member", body)

    data = os.urandom(3 * 1024 * 1024) + b"\nPhase 1 smoke evidence\n"
    digest = hashlib.sha256(data).hexdigest()
    status, created, _ = api.call(
        "POST",
        f"/cases/{cid}/evidence",
        analyst,
        {"kind": "file", "original_name": "smoke.bin", "expected_sha256": digest,
         "source_host": "SMOKE-01", "acquisition_tool": "phase1-smoke"},
    )
    expect(status == 201, "analyst creates evidence record", created)
    eid = created["evidence"]["id"]
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", viewer, raw=b"nope")
    expect(status == 403, "viewer upload denied (403)", body)
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", analyst, raw=data)
    expect(status == 200 and body["sha256"] == digest, "streamed upload hash == hashlib.sha256", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/finalize", analyst)
    expect(status == 200 and body["ok"] and body["evidence"]["status"] == "stored",
           f"finalize: re-hashed, locked ({body and body.get('retention_mode')})", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/verify", analyst)
    expect(status == 200 and body["ok"] is True, "verify ok (object + chain + signatures)", body)

    status, body, _ = api.call("GET", f"/evidence/{eid}/download", analyst)
    expect(status == 403, "analyst download denied (403)", body)
    status, body, _ = api.call("GET", f"/evidence/{eid}", outsider)
    expect(status == 404, "non-member read hidden (404)", body)
    status, _, content = api.call("GET", f"/evidence/{eid}/download", auditor)
    expect(status == 200 and hashlib.sha256(content).hexdigest() == digest,
           "auditor download byte-identical", None)
    status, body, _ = api.call("GET", f"/audit?object_type=evidence&object_id={eid}&limit=500", auditor)
    actions = {item["action"] for item in (body or {}).get("items", [])}
    expect(status == 200 and {"evidence.download", "evidence.verify", "read"} <= actions,
           "audit log records semantic + HTTP rows", sorted(actions))
    status, body, _ = api.call("GET", "/audit", analyst)
    expect(status == 403, "analyst cannot read the audit log (403)", body)

    # Tamper demo (guide 8.3 rule 6): edit custody seq 2 directly in the database.
    psql(
        compose,
        "BEGIN; SET LOCAL session_replication_role = replica; "
        "UPDATE custody_log SET detail = jsonb_set(detail, '{source_ip}', '\"203.0.113.66\"') "
        f"WHERE evidence_id = '{eid}' AND seq = 2; COMMIT;",
    )
    status, body, _ = api.call("POST", f"/evidence/{eid}/verify", lead)
    chain = (body or {}).get("chain", {})
    expect(status == 200 and body["ok"] is False and chain.get("first_broken_seq") == 2,
           f"tampered custody row detected at seq {chain.get('first_broken_seq')} "
           f"({[p['code'] for p in chain.get('problems', [])]})", body)
    print("PHASE 1 SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
