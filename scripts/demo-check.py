#!/usr/bin/env python3
"""Load the demo evidence (data/demo/evidence/) into a running stack and check the outcome.

    python scripts/demo-check.py --admin-email E [--admin-password P] [--base URL]
                                 [--reports-out DIR]

Run it before a live demo to prove the files still produce the expected timeline and alerts, or
to get a ready-made demo case to explore in the UI. It follows the same steps as the walkthrough
in data/demo/README.md:

1. a lead creates the case "Web server compromise (demo)" and adds an analyst;
2. the analyst imports data/demo/evidence/iocs.csv (before any evidence, so every detection run
   that follows already knows the indicators);
3. the analyst uploads auth.log, .bash_history and capture.pcap exactly as the UI does (no
   acquisition time) and starts processing with automatic parser selection, then runs the
   explicit ``yara_scan`` parser on dropper.sh;
4. after the jobs settle, the expected alerts must be there.

With ``--reports-out`` it also writes a technical, an executive and a custody report, has the
analyst submit them, the lead approve and sign them, verifies each signature, and saves the PDFs
into DIR (this is how docs/samples/ was produced). The users are "Demo Lead" and "Demo Analyst"
with random e-mail addresses; the case is left in place so it can be opened in the UI. Exits
non-zero on the first failed expectation.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import io
import os
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "data" / "demo" / "evidence"


def _load(name: str, file: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", "phase1-smoke.py")
Api, expect, login = p1.Api, p1.expect, p1.login

ATTACKER_IP = "203.0.113.45"
# Rules the demo files must trigger (see data/demo/README.md for what each one shows).
EXPECTED = {
    "DFIR-LNX-0001",  # SSH brute force
    "DFIR-LNX-0002",  # SSH success after failures
    "DFIR-LNX-0003",  # root login over SSH
    "DFIR-LNX-0004",  # new Linux user created
    "DFIR-LNX-0011",  # user added to the sudo group
    "DFIR-IOC-0001",  # IOC matches (attacker and exfiltration addresses, domains, script hash)
}
EVIDENCE = (  # (file, evidence kind, process body)
    ("auth.log", "log", {}),
    (".bash_history", "log", {}),
    ("capture.pcap", "pcap", {}),
    ("dropper.sh", "file", {"parsers": ["yara_scan"]}),
)


def make_user(api: Any, admin: str, admin_password: str, role: str) -> tuple[str, str]:
    email = f"demo-{role}-{uuid.uuid4().hex[:6]}@demo.example"
    payload = {
        "email": email,
        "display_name": f"Demo {role.title()}",
        "role": role,
        "password": p1.PASSWORD,
    }
    if role == "lead":  # privileged roles need the admin's re-authentication
        payload["admin_password"] = admin_password
    status, body, _ = api.call("POST", "/users", admin, payload)
    expect(status == 201, f"admin creates {role} {email}", body)
    return str(body["id"]), login(api, email, p1.PASSWORD)


def upload(api: Any, token: str, cid: str, name: str, kind: str) -> str:
    data = (DEMO / name).read_bytes()
    status, body, _ = api.call(
        "POST",
        f"/cases/{cid}/evidence",
        token,
        {"kind": kind, "original_name": name, "size_bytes": len(data)},
    )
    expect(status == 201, f"create evidence {name}", body)
    eid = str(body["evidence"]["id"])
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", token, raw=data)
    expect(status == 200, f"upload {name}", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/finalize", token)
    expect(status == 200 and body["ok"], f"finalize {name} (hash recorded in custody)", body)
    return eid


def settle(api: Any, token: str, cid: str, timeout: float = 600) -> list[dict[str, Any]]:
    """Wait (quietly) until no job is queued or running and detection ran after the last parse."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, body, _ = api.call("GET", f"/cases/{cid}/jobs?limit=500", token)
        if status != 200:
            expect(False, "list jobs", body)
        items = list(body["items"])
        parse_done = [j["finished_at"] for j in items if j["kind"] == "parse" and j["finished_at"]]
        detects = [j for j in items if j["kind"] == "detect"]
        idle = items and all(j["status"] not in ("queued", "running") for j in items)
        if idle and detects and all((detects[0]["started_at"] or "") >= d for d in parse_done):
            print(f"ok   {len(items)} jobs settled")
            return items
        time.sleep(2)
    expect(False, f"jobs settled within {timeout}s")
    raise AssertionError


def search(api: Any, token: str, cid: str, query: str) -> list[dict[str, Any]]:
    status, body, _ = api.call(
        "POST", f"/cases/{cid}/events/search", token, {"query": query, "limit": 500}
    )
    expect(status == 200, f"search {query!r}", body)
    return list(body["items"])


SECTIONS = {
    "technical": {
        "executive_summary": (
            "On 14 September 2026 between 02:10 and 03:05 UTC an external actor at 203.0.113.45 "
            "guessed the password of the `deploy` account on the web server **web01** over SSH, "
            "became root, created the backdoor account `backupsvc` in the `sudo` group, installed "
            "a cron job that downloads a script every ten minutes, and uploaded an archive of the "
            "application's configuration and secrets to 198.51.100.23."
        ),
        "scope": (
            "Host web01 (Ubuntu web server, 10.20.0.15). Evidence: `/var/log/auth.log`, root's "
            "`.bash_history`, a perimeter packet capture for 14 September 02:00-03:30 UTC, and "
            "the dropper script recovered from `/tmp/.x.sh`. Authorization: demo case, synthetic "
            "data only."
        ),
        "affected_assets": (
            "- Host `web01` (10.20.0.15)\n- Account `deploy` (password guessed)\n"
            "- Account `root` (direct SSH login)\n- Account `backupsvc` (created by the attacker)"
        ),
        "root_cause": (
            "Password authentication was enabled for SSH and the `deploy` account had a weak "
            "password; direct root login over SSH was allowed."
        ),
        "impact": (
            "Application secrets in `/var/www/app/.env` and `/var/www/app/config` must be "
            "treated as disclosed (about 56 KB sent over TLS to files.exfil-drop.example)."
        ),
        "actions": (
            "Rotate every secret in the application configuration, remove `backupsvc` and the "
            "cron entry, rebuild web01 from a known-good image, disable SSH password and root "
            "login, block 203.0.113.45 and 198.51.100.23 at the perimeter."
        ),
        "lessons_learned": "Enforce key-only SSH on internet-facing hosts and alert on brute force.",
        "limitations": (
            "The packet capture covers only 02:00-03:30 UTC; TLS contents were not decrypted, so "
            "the archive's exact contents come from the shell history. Shell history can be "
            "edited by an attacker (the last command disabled history recording)."
        ),
    },
    "executive": {
        "summary": (
            "An attacker broke into the public web server web01 early on 14 September 2026 by "
            "guessing a weak password, took full control, and copied the application's "
            "configuration, including passwords and keys, to an outside server."
        ),
        "impact": (
            "The passwords and keys in the copied configuration must be treated as stolen. No "
            "evidence shows access to other servers."
        ),
        "actions": (
            "The server was isolated, the stolen secrets are being rotated, and the server is "
            "being rebuilt. Password logins over SSH are being switched off on all public servers."
        ),
        "decisions": "Approve the emergency maintenance window for rebuilding web01.",
    },
    "custody": {
        "scope": (
            "Custody of the four evidence items of case web01 compromise (demo): auth.log, "
            ".bash_history, capture.pcap and dropper.sh."
        ),
        "examiner": "Prepared by the demo analyst; every hash was verified by the platform.",
        "limitations": "Synthetic demo evidence; no physical media were involved.",
    },
}


def make_report(
    api: Any,
    analyst: str,
    lead: str,
    cid: str,
    kind: str,
    findings: list[dict[str, Any]],
    out: Path,
) -> None:
    title = {
        "technical": "web01 compromise: technical report",
        "executive": "web01 compromise: executive summary",
        "custody": "web01 compromise: chain of custody",
    }[kind]
    status, rep, _ = api.call(
        "POST", f"/cases/{cid}/reports", analyst, {"kind": kind, "title": title}
    )
    expect(status == 201, f"create {kind} report (snapshot)", rep)
    rid = rep["id"]
    update: dict[str, Any] = {"expected_revision": rep["revision"], "sections": SECTIONS[kind]}
    if kind == "technical":
        update["findings"] = findings
    status, rep, _ = api.call("PATCH", f"/reports/{rid}", analyst, update)
    expect(status == 200, f"edit {kind} report", rep)
    status, rep, _ = api.call(
        "POST", f"/reports/{rid}/submit", analyst, {"expected_revision": rep["revision"]}
    )
    expect(
        status == 200 and rep["status"] == "in_review", f"QA passes, {kind} report submitted", rep
    )
    status, rep, _ = api.call("POST", f"/reports/{rid}/approve", lead)
    expect(status == 200 and rep["status"] == "approved", f"lead approves {kind} report", rep)
    status, rep, _ = api.call("POST", f"/reports/{rid}/sign", lead)
    expect(status == 200 and rep["status"] == "signed", f"lead signs {kind} report", rep)
    status, ver, _ = api.call("GET", f"/reports/{rid}/verify", analyst)
    expect(status == 200 and ver["ok"], f"{kind} report signature verifies", ver)
    status, _, pdf = api.call("GET", f"/reports/{rid}/download?format=pdf", analyst)
    expect(status == 200 and pdf.startswith(b"%PDF"), f"download {kind} PDF", None)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{kind}-report.pdf").write_bytes(pdf)
    print(f"     saved {out / f'{kind}-report.pdf'} ({len(pdf)} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-email", required=True)
    parser.add_argument("--admin-password", default=os.environ.get("DFIR_ADMIN_PASSWORD"))
    parser.add_argument("--reports-out", type=Path, help="also sign the three sample reports here")
    args = parser.parse_args()
    expect(all((DEMO / f).is_file() for f, _, _ in EVIDENCE), "demo files present (make_demo.py)")

    api = Api(args.base)
    admin = login(api, args.admin_email, args.admin_password)
    _, lead = make_user(api, admin, args.admin_password, "lead")
    analyst_id, analyst = make_user(api, admin, args.admin_password, "analyst")

    status, case, _ = api.call(
        "POST",
        "/cases",
        lead,
        {
            "title": "Web server compromise (demo)",
            "severity": "high",
            "description": "Synthetic demo case: SSH brute force on web01, backdoor account, data theft.",
        },
    )
    expect(status == 201, "lead creates the demo case", case)
    cid = case["id"]
    status, body, _ = api.call(
        "POST", f"/cases/{cid}/members", lead, {"user_id": analyst_id, "role": "analyst"}
    )
    expect(status == 200, "lead adds the analyst", body)

    ioc_text = (DEMO / "iocs.csv").read_text(encoding="utf-8")
    status, body, _ = api.call(
        "POST", f"/cases/{cid}/iocs/import", analyst, {"format": "csv", "content": ioc_text}
    )
    rows = len(list(csv.DictReader(io.StringIO(ioc_text))))
    expect(
        status == 200 and body.get("created", 0) + body.get("updated", 0) == rows,
        "import iocs.csv",
        body,
    )

    evidence: dict[str, str] = {}
    for name, kind, process in EVIDENCE:
        evidence[name] = upload(api, analyst, cid, name, kind)
        status, body, _ = api.call("POST", f"/evidence/{evidence[name]}/process", analyst, process)
        expect(status == 202, f"processing queued for {name}", body)
    failed = [j for j in settle(api, analyst, cid) if j["status"] != "succeeded"]
    expect(not failed, "every job succeeded", failed)

    status, body, _ = api.call("GET", f"/cases/{cid}/alerts?limit=500", analyst)
    expect(status == 200, "list alerts", body)
    found = list(body["items"])
    fired: dict[str, int] = {}
    for alert in found:
        fired[alert["rule_id"]] = fired.get(alert["rule_id"], 0) + 1
    for rule, count in sorted(fired.items()):
        title = next(a["title"] for a in found if a["rule_id"] == rule)
        print(f"     alert {rule} x{count}: {title}")
    expect(set(fired) >= EXPECTED, f"expected rules fired ({len(found)} alerts)", sorted(fired))
    hits = search(api, analyst, cid, f"ip:{ATTACKER_IP}")
    expect(len(hits) >= 30, f"timeline: {len(hits)} events involve {ATTACKER_IP}", None)
    yara = search(api, analyst, cid, "source_type:yara")
    expect(bool(yara), "YARA match on dropper.sh in the timeline", None)

    if args.reports_out:
        brute = next(a for a in found if a["rule_id"] == "DFIR-LNX-0002")
        group = next(a for a in found if a["rule_id"] == "DFIR-LNX-0011")
        accepted = search(api, analyst, cid, f"event_code:ssh_accepted AND ip:{ATTACKER_IP}")
        upload_cmd = search(api, analyst, cid, "source_type:shell_history AND cmdline:*exfil*")
        findings = [
            {
                "title": "SSH password guessed after 24 attempts",
                "body": "24 failed SSH logins from 203.0.113.45 in four minutes, then an accepted "
                "password login for `deploy` at 02:14:05 UTC.",
                "confidence": "high",
                "attack": ["T1110"],
                "refs": [
                    {"type": "alert", "id": brute["id"]},
                    {"type": "event", "id": accepted[0]["id"]},
                    {"type": "evidence", "id": evidence["auth.log"]},
                ],
            },
            {
                "title": "Backdoor account backupsvc added to sudo",
                "body": "The attacker created `backupsvc` and added it to the `sudo` group at 02:21 UTC.",
                "confidence": "high",
                "attack": ["T1136.001", "T1098"],
                "refs": [{"type": "alert", "id": group["id"]}],
            },
            {
                "title": "Application secrets uploaded to an external server",
                "body": "root archived `/var/www/app/.env` and the config directory and uploaded it "
                "with curl to files.exfil-drop.example (198.51.100.23); the capture shows a 56 KB "
                "TLS upload at 02:33:40 UTC.",
                "confidence": "medium",
                "attack": ["T1048"],
                "refs": [{"type": "event", "id": e["id"]} for e in upload_cmd[:1]]
                + [{"type": "evidence", "id": evidence["capture.pcap"]}],
            },
        ]
        for kind in ("technical", "executive", "custody"):
            make_report(api, analyst, lead, cid, kind, findings, args.reports_out)

    print(f"DEMO CHECK PASSED: case {case['case_number']} -> http://127.0.0.1:8080/cases/{cid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
