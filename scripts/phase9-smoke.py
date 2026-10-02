#!/usr/bin/env python3
"""Phase 9 live smoke test against the running compose stack (stdlib only).

    python scripts/phase9-smoke.py --admin-email E [--admin-password P] [--base URL]

The stack must run with ENABLE_ENRICHMENT=true ENRICHMENT_FAKE=true OUTBOUND_ALLOW_HTTP=true
OUTBOUND_ALLOW_HOSTS=api (verify-phase9.sh starts it so): a signature-checking webhook receiver
runs inside the api container (``http://api:<port>/hook``), so nothing leaves the compose network.

1. integrations: secrets are write-only (never in responses, audit rows, delivery logs or logs);
   an address in the metadata range is refused when saved; a webhook to a private address is
   refused at send time and ends ``failed`` without retries;
2. SIEM ingest: a signed delivery creates alerts in the configured case (a malformed item is
   counted), a replay changes nothing, a bad signature / stale timestamp / unknown source all get
   the same 401, an oversized body 413, a closed case 409;
3. the signed outbound webhook reaches the receiver, which verifies ``X-Signature``;
4. playbooks: a dry run writes nothing; an impactful action needs a second person (the requester
   gets 403), runs once, is recorded ``not_executed`` and is completed by hand with notes;
   ``notify.team`` runs; every step records user, time and the triggering alert; RBAC;
5. in-app notifications reach the case lead (alert, approval requested);
6. enrichment (offline fake provider): verdicts are fetched then cached; an indicator without TLP
   (amber) is not sent.
Exits non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import random
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra" / "compose.yaml")]
HOOK_LOG = "/tmp/phase9-hooks.jsonl"  # noqa: S108 - inside the api container (tmpfs)

# Runs inside the api container: accepts POSTs on /hook, verifies the signature and records each
# delivery as one JSON line. Stops by itself after 15 minutes.
RECEIVER = r"""
import hashlib, hmac, http.server, json, os, time
SECRET = os.environ['HOOK_SECRET'].encode()
PORT = int(os.environ['HOOK_PORT'])
LOG = os.environ['HOOK_LOG']
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        ts = self.headers.get('X-Timestamp') or ''
        sig = self.headers.get('X-Signature') or ''
        want = 'sha256=' + hmac.new(SECRET, ts.encode() + b'.' + body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(want, sig) and ts.isdigit() and abs(time.time() - int(ts)) < 300
        with open(LOG, 'a') as f:
            f.write(json.dumps({'ok': ok, 'event': self.headers.get('X-Event'),
                                'delivery': self.headers.get('X-Delivery-Id'),
                                'body': json.loads(body or b'{}')}) + '\n')
        self.send_response(200 if ok else 401)
        self.end_headers()
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(('0.0.0.0', PORT), H)
srv.timeout = 1
end = time.time() + 900
while time.time() < end:
    srv.handle_request()
"""


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", ROOT / "scripts" / "phase1-smoke.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        [*COMPOSE, *args], capture_output=True, text=True, check=check
    )


def psql(sql: str) -> str:
    out = compose("exec", "-T", "postgres", "psql", "-U", "dfir", "-d", "dfirbench", "-At", "-c", sql)
    return out.stdout.strip()


def sign(secret: str, ts: int, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def ingest(api: Any, integration_id: str, secret: str, payload: Any, *, ts: int | None = None,
           signature: str | None = None, raw: bytes | None = None) -> tuple[int, Any]:
    body = raw if raw is not None else json.dumps(payload).encode()
    stamp = int(time.time()) if ts is None else ts
    headers = {
        "Content-Type": "application/json",
        "X-Timestamp": str(stamp),
        "X-Signature": signature or sign(secret, stamp, body),
    }
    req = urllib.request.Request(  # noqa: S310 - local URL
        f"{api.base}/ingest/webhook/{integration_id}", data=body, method="POST", headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            content, status = resp.read(), resp.status
    except urllib.error.HTTPError as exc:
        content, status = exc.read(), exc.code
    try:
        return status, json.loads(content) if content else None
    except ValueError:
        return status, None


def wait_for(what: str, fn: Any, timeout: float = 120) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.monotonic() > deadline:
            expect(False, f"timed out waiting for {what}")
        time.sleep(2)


def hooks() -> list[dict[str, Any]]:
    out = compose("exec", "-T", "api", "sh", "-c", f"cat {HOOK_LOG} 2>/dev/null || true")
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def by_key(run: dict[str, Any]) -> dict[str, Any]:
    return {s["step_key"]: s for s in run["steps"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    args = parser.parse_args()
    p1.ADMIN_PASSWORD = args.admin_password  # make_user re-authenticates for lead/admin
    api = Api(args.base)
    admin = login(api, args.admin_email, args.admin_password)
    lead_id, lead = make_user(api, admin, "lead")
    analyst_id, analyst = make_user(api, admin, "analyst")
    viewer_id, viewer = make_user(api, admin, "viewer")
    _, outsider = make_user(api, admin, "analyst")
    tag = uuid.uuid4().hex[:8]
    hook_secret = f"smoke-hook-{uuid.uuid4().hex}{uuid.uuid4().hex}"
    ingest_secret = f"smoke-ingest-{uuid.uuid4().hex}{uuid.uuid4().hex}"
    vt_key = f"smoke-vt-{uuid.uuid4().hex}"
    secrets = (hook_secret, ingest_secret, vt_key)

    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 9 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call("POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role})
        expect(status == 200, f"lead adds {role}", body)

    # ---- 1. integrations, write-only secrets, SSRF policy
    port = random.randint(20000, 29999)  # noqa: S311 - not security relevant
    compose("exec", "-d", "-e", f"HOOK_SECRET={hook_secret}", "-e", f"HOOK_PORT={port}",
            "-e", f"HOOK_LOG={HOOK_LOG}", "api", "python", "-c", RECEIVER)
    probe = f"import socket; socket.create_connection(('127.0.0.1', {port}), 2).close()"
    wait_for("the webhook receiver to listen",
             lambda: compose("exec", "-T", "api", "python", "-c", probe, check=False).returncode == 0, 60)
    status, body, _ = api.call("GET", "/integrations", lead)
    expect(status == 403, "only admins manage integrations (403)", body)
    status, body, _ = api.call("POST", "/integrations", admin, {
        "type": "webhook_out", "name": f"smoke-meta-{tag}",
        "config": {"url": "http://169.254.169.254/latest/meta-data", "events": ["alert.created"]},
        "secret": {"signing_secret": hook_secret},
    })
    expect(status == 422 and body["error"]["details"]["reason"] == "address_metadata",
           "a cloud metadata address is refused when saved", body)
    status, hook, raw = api.call("POST", "/integrations", admin, {
        "type": "webhook_out", "name": f"smoke-hook-{tag}",
        "config": {"url": f"http://api:{port}/hook", "events": ["alert.created", "playbook.approval_requested"],
                   "case_ids": [cid]},
        "secret": {"signing_secret": hook_secret}, "enabled": True,
    })
    expect(status == 201 and hook["enabled"] and hook["has_secret"], "signed webhook created and enabled", hook)
    expect(hook_secret.encode() not in raw and len(hook["secret_fingerprint"]) == 12,
           "the response carries a fingerprint, never the secret", hook)
    status, private, _ = api.call("POST", "/integrations", admin, {
        "type": "webhook_out", "name": f"smoke-private-{tag}",
        "config": {"url": "https://redis:6379/x", "events": ["alert.created"], "case_ids": [cid]},
        "secret": {"signing_secret": hook_secret}, "enabled": True,
    })
    expect(status == 201, "webhook to a host name that resolves privately is saved (checked at send)", private)
    status, source, _ = api.call("POST", "/integrations", admin, {
        "type": "webhook_in", "name": f"smoke-siem-{tag}", "case_id": cid,
        "secret": {"signing_secret": ingest_secret}, "enabled": True,
    })
    expect(status == 201 and source["case_id"] == cid, "SIEM ingest source bound to the case", source)
    status, vt, _ = api.call("POST", "/integrations", admin, {
        "type": "virustotal", "name": f"smoke-vt-{tag}", "secret": {"api_key": vt_key}, "enabled": True,
    })
    expect(status == 201, "VirusTotal integration (offline fake provider in this stack)", vt)

    # ---- 2. SIEM ingest
    ext = f"siem-{tag}"
    payload = {"alerts": [
        {"id": f"{ext}-1", "title": "Ransomware note dropped <script>x</script>", "severity": "critical",
         "timestamp": "2026-09-30T10:00:00+02:00", "host": "WS-042", "attack": ["T1486"],
         "case_id": str(uuid.uuid4())},
        {"id": f"{ext}-2", "title": "Beacon", "severity": "low"},
        {"title": "no id"},
    ]}
    body_bytes = json.dumps(payload).encode()
    stamp = int(time.time())
    status, result = ingest(api, source["id"], ingest_secret, None, ts=stamp, raw=body_bytes)
    expect(status == 200 and (result["created"], result["errors"]) == (2, 1)
           and result["error_reasons"] == {"missing_id": 1}, "signed delivery: 2 alerts, 1 counted error", result)
    status, again = ingest(api, source["id"], ingest_secret, None, ts=stamp, raw=body_bytes)
    expect(status == 200 and again["duplicate"] and again["created"] == 2, "replay answered idempotently", again)
    answers = {
        "bad signature": ingest(api, source["id"], ingest_secret, payload, signature="sha256=" + "0" * 64),
        "stale timestamp": ingest(api, source["id"], ingest_secret, payload, ts=int(time.time()) - 3600),
        "unknown source": ingest(api, str(uuid.uuid4()), ingest_secret, payload),
        "wrong secret": ingest(api, source["id"], "x" * 40, payload),
    }
    for name, (code, body) in answers.items():
        expect(code == 401 and body["error"]["code"] == "webhook_unauthenticated", f"{name}: uniform 401", body)
    code, body = ingest(api, source["id"], ingest_secret, None, raw=b"[" + b" " * (300 * 1024) + b"]")
    expect(code == 413, "oversized body refused (413)", body)
    status, alerts, _ = api.call("GET", f"/cases/{cid}/alerts", viewer)
    mine = [a for a in alerts["items"] if a.get("rule_id") is None]
    expect(len(mine) == 2, "the alerts are in the configured case", alerts)
    crit = next(a for a in mine if a["severity"] == "critical")
    expect("<script>" in crit["title"], "alert title kept as text (rendered escaped by the UI)", crit)
    status, closed, _ = api.call("POST", "/cases", lead, {"title": "Phase 9 smoke (closed)"})
    status, src2, _ = api.call("POST", "/integrations", admin, {
        "type": "webhook_in", "name": f"smoke-siem2-{tag}", "case_id": closed["id"],
        "secret": {"signing_secret": ingest_secret}, "enabled": True,
    })
    expect(status == 201, "second source", src2)
    status, body, _ = api.call("POST", f"/cases/{closed['id']}/close", lead, {"reason": "smoke"})
    expect(status == 200, "lead closes the second case", body)
    code, body = ingest(api, src2["id"], ingest_secret, payload)
    expect(code == 409, "a closed case refuses ingest (409)", body)

    # ---- 3. signed outbound webhook and SSRF at send time
    received = wait_for("the receiver to get alert.created", lambda: [
        h for h in hooks() if h["event"] == "alert.created" and h["body"]["data"].get("case_id") == cid])
    expect(all(h["ok"] for h in received), "the receiver verified X-Signature on every delivery", received)
    expect("details" not in received[0]["body"]["data"], "no evidence-derived text without include_details",
           received[0])
    status, log, _ = api.call("GET", f"/integrations/{hook['id']}/deliveries", admin)
    expect(status == 200 and any(d["status"] == "delivered" for d in log["outbound"]),
           "delivery log shows delivered", log)

    def private_failed() -> Any:
        _, plog, _ = api.call("GET", f"/integrations/{private['id']}/deliveries", admin)
        rows = plog["outbound"] if plog else []
        return rows if rows and all(d["status"] == "failed" for d in rows) else None

    rows = wait_for("the private-address delivery to fail", private_failed)
    expect(rows[0]["last_error"] == "blocked:address_private" and rows[0]["attempts"] == 1,
           "a private address is refused at send time and ends failed (no retries)", rows)

    # ---- 4. playbooks and four eyes
    status, before, _ = api.call("GET", f"/cases/{cid}/playbook-runs", viewer)
    status, sugg, _ = api.call("GET", f"/alerts/{crit['id']}/playbooks", viewer)
    expect(status == 200 and any(p["id"] == "PB-RANSOMWARE-01" for p in sugg["items"]),
           "the ransomware playbook is suggested for the T1486 alert", sugg)
    start = {"playbook_id": "PB-RANSOMWARE-01", "alert_id": crit["id"]}
    status, plan, _ = api.call("POST", f"/cases/{cid}/playbook-runs", analyst, {**start, "dry_run": True})
    expect(status == 200 and plan["writes"] == "none" and plan["approvals_needed"] >= 1, "dry run returns a plan", plan)
    status, after, _ = api.call("GET", f"/cases/{cid}/playbook-runs", viewer)
    expect(len(after["items"]) == len(before["items"]), "the dry run wrote nothing", after)
    status, body, _ = api.call("POST", f"/cases/{cid}/playbook-runs", viewer, start)
    expect(status == 403, "viewer cannot start a playbook (403)", body)
    status, run, _ = api.call("POST", f"/cases/{cid}/playbook-runs", analyst, start)
    expect(status == 201 and run["alert_id"] == crit["id"], "analyst starts the run for the alert", run)
    rid = run["id"]
    status, body, _ = api.call("GET", f"/playbook-runs/{rid}", outsider)
    expect(status == 404, "outsider cannot see the run (404)", body)
    step_url = f"/playbook-runs/{rid}/steps"
    status, body, _ = api.call("PATCH", f"{step_url}/c1", analyst, {"op": "execute", "params": {"host": "WS-042"}})
    expect(status == 409 and body["error"]["code"] == "approval_required", "impactful action needs approval", body)
    status, run, _ = api.call("PATCH", f"{step_url}/c1", analyst, {"op": "request", "params": {"host": "WS-042"}})
    c1 = by_key(run)["c1"]
    expect(status == 200 and c1["status"] == "awaiting_approval", "analyst requests approval", run)
    req_id = c1["request"]["id"]
    status, body, _ = api.call("POST", f"/action-requests/{req_id}/approve", analyst, {})
    expect(status == 403, "the requester cannot approve (403)", body)
    status, body, _ = api.call("POST", f"/action-requests/{req_id}/approve", viewer, {})
    expect(status == 403, "a viewer cannot approve (403)", body)
    status, body, _ = api.call("POST", f"/action-requests/{req_id}/approve", lead, {"reason": "contain"})
    expect(status == 200 and body["status"] == "approved" and body["decided_by"] == lead_id,
           "a second person (lead) approves", body)
    status, run, _ = api.call("PATCH", f"{step_url}/c1", analyst, {"op": "execute"})
    c1 = by_key(run)["c1"]
    expect(status == 200 and c1["status"] == "not_executed" and c1["outcome"] == "not_executed",
           "the agent action is recorded NOT executed (no remote agent)", c1)
    status, body, _ = api.call("PATCH", f"{step_url}/c1", analyst, {"op": "execute"})
    expect(status == 409, "an approved action runs at most once", body)
    status, body, _ = api.call("PATCH", f"{step_url}/c1", analyst, {"op": "complete"})
    expect(status == 422, "manual completion needs notes", body)
    status, run, _ = api.call("PATCH", f"{step_url}/c1", analyst,
                              {"op": "complete", "notes": "Isolated WS-042 in the EDR console"})
    c1 = by_key(run)["c1"]
    expect(c1["status"] == "done" and c1["outcome"] == "completed_manually" and c1["completed_by"] == analyst_id
           and c1["completed_at"] and c1["alert_id"] == crit["id"], "completed by hand: who, when, alert", c1)
    status, run, _ = api.call("PATCH", f"{step_url}/c3", analyst, {"op": "execute"})
    expect(status == 200 and by_key(run)["c3"]["status"] == "done", "notify.team runs", by_key(run)["c3"])
    status, run, _ = api.call("PATCH", f"{step_url}/c2", viewer, {"op": "complete"})
    expect(status == 403, "viewer cannot complete steps (403)", run)
    status, run, _ = api.call("POST", f"/playbook-runs/{rid}/cancel", analyst, {"reason": "smoke done"})
    expect(status == 200 and run["status"] == "cancelled", "run cancelled with a reason", run)
    status, body, _ = api.call("PATCH", f"{step_url}/c2", analyst, {"op": "complete"})
    expect(status == 409, "a cancelled run is frozen", body)

    # ---- 5. in-app notifications for the case lead
    def lead_kinds() -> Any:
        _, notes, _ = api.call("GET", "/notifications", lead)
        kinds = {n["kind"] for n in (notes or {}).get("items", []) if n.get("case_id") == cid}
        return kinds if {"alert.created", "playbook.approval_requested"} <= kinds else None

    wait_for("in-app notifications for the lead", lead_kinds)
    expect(True, "the case lead got in-app notifications (alert, approval requested)")
    approvals = wait_for("the approval webhook", lambda: [h for h in hooks() if h["event"] == "playbook.approval_requested"
                                                          and h["body"]["data"].get("case_id") == cid])
    expect(all(h["ok"] for h in approvals), "approval request delivered as a signed webhook", approvals)

    # ---- 6. enrichment with the offline fake provider
    status, green, _ = api.call("POST", f"/cases/{cid}/iocs", analyst,
                                {"type": "ip", "value": "198.51.100.77", "tlp": "green"})
    expect(status == 201, "green IOC added", green)
    status, amber, _ = api.call("POST", f"/cases/{cid}/iocs", analyst, {"type": "domain", "value": f"c2-{tag}.example"})
    expect(status == 201, "IOC without TLP added", amber)
    status, body, _ = api.call("POST", f"/cases/{cid}/iocs/enrich", viewer, {})
    expect(status == 403, "viewer cannot enrich (403)", body)
    status, first, _ = api.call("POST", f"/cases/{cid}/iocs/enrich", analyst, {})
    states = {r["ioc_id"]: r["status"] for r in first["results"]}
    expect(status == 200 and states.get(green["id"]) == "fetched" and states.get(amber["id"]) == "skipped_tlp",
           "green IOC enriched, no-TLP (amber) IOC never sent", first)
    status, second, _ = api.call("POST", f"/cases/{cid}/iocs/enrich", analyst, {})
    states = {r["ioc_id"]: r["status"] for r in second["results"]}
    expect(states.get(green["id"]) == "cached", "second lookup comes from the cache", second)
    status, cached, _ = api.call("GET", f"/cases/{cid}/enrichments", viewer)
    expect(status == 200 and any(r["ioc_id"] == green["id"] for r in cached["items"]), "viewer reads cached verdicts", cached)

    # ---- secrets never leave
    status, _, raw = api.call("GET", "/integrations", admin)
    for secret in secrets:
        expect(secret.encode() not in raw, "integration list never returns a secret")
        hits = psql(
            "SELECT (SELECT count(*) FROM audit_log WHERE detail::text LIKE '%" + secret + "%') + "
            "(SELECT count(*) FROM outbound_deliveries WHERE coalesce(last_error, '') LIKE '%" + secret + "%') + "
            "(SELECT count(*) FROM outbound_events WHERE payload::text LIKE '%" + secret + "%') + "
            "(SELECT count(*) FROM integrations WHERE config::text LIKE '%" + secret + "%')"
        )
        expect(hits == "0", "no secret in audit rows, delivery logs, events or plain config", hits)
    logs = compose("logs", "--no-color", "api", "worker").stdout
    expect(not any(s in logs for s in secrets), "no secret in the api or worker logs")
    print("PHASE 9 SMOKE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
