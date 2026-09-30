#!/usr/bin/env python3
"""Phase 8 live smoke test against the running compose stack (stdlib only, plus the offline
verifier run as ``python -m app.reports.verify`` from ``backend/``).

    python scripts/phase8-smoke.py --admin-email E [--admin-password P] [--base URL]

The stack must run with ENABLE_AI=true and LLM_PROVIDER=fake (verify-phase8.sh starts it so).

1. auth.log is parsed and detected in the worker; an event is bookmarked and an IOC added;
2. a technical report takes its snapshot; QA blocks submission until every finding cites
   evidence; stale edits get 409; the analyst submits, cannot approve; a lead approves and signs
   (artifacts go to the MinIO artifacts bucket);
3. /verify is ok; every download matches the signed manifest and carries the sandbox CSP; the
   seal and the artifacts verify offline with the CLI;
4. an AI draft (offline provider) is accepted and applied to a new version, labelled AI-drafted;
5. tampering with a stored artifact in MinIO makes /verify fail and the download is refused;
6. RBAC: viewer cannot create/edit, outsider gets 404;
7. the evidence export package verifies offline and adds an ``exported`` custody entry.
Exits non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "backend" / "tests" / "fixtures"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "infra" / "compose.yaml")]
HOSTILE = '<script>alert("smoke")</script>'


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", ROOT / "scripts" / "phase1-smoke.py")
p2 = _load("phase2_smoke", ROOT / "scripts" / "phase2-smoke.py")
p3 = _load("phase3_smoke", ROOT / "scripts" / "phase3-smoke.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user


def fetch(api: Any, method: str, path: str, token: str) -> tuple[int, dict[str, str], bytes]:
    """Like Api.call but also returns the response headers (downloads)."""
    req = urllib.request.Request(  # noqa: S310 - local URL
        api.base + path, method=method, headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def verify_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "app.reports.verify", *args],
        cwd=ROOT / "backend",
        capture_output=True,
        text=True,
        check=False,
    )


def tamper_artifact(key: str) -> None:
    code = (
        "import io\n"
        "from app.config import get_settings\n"
        "from app.storage import make_minio_client\n"
        "s = get_settings()\n"
        "c = make_minio_client(s)\n"
        f"k = {key!r}\n"
        "data = c.get_object(s.artifacts_bucket, k).read() + b'<!-- tampered -->'\n"
        "c.put_object(s.artifacts_bucket, k, io.BytesIO(data), len(data))\n"
        "print('tampered', k)\n"
    )
    subprocess.run(  # noqa: S603 - fixed argv
        [*COMPOSE, "exec", "-T", "api", "python", "-c", code], check=True, capture_output=True
    )


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
    _, outsider = make_user(api, admin, "analyst")

    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 8 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call("POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role})
        expect(status == 200, f"lead adds {role}", body)
    eid = p2.stored(api, analyst, cid, "auth.log", "log", (FIXTURES / "linux" / "auth.log").read_bytes())
    status, body, _ = api.call("POST", f"/evidence/{eid}/process", analyst, {"parsers": ["linux_auth"]})
    expect(status == 202, "parse job queued", body)
    p3.settle(api, analyst, cid)
    alerts = p3.alerts(api, viewer, cid)
    expect(bool(alerts), "detection produced alerts", alerts)
    events = p2.timeline(api, viewer, cid)
    expect(bool(events), "timeline has events", None)
    status, body, _ = api.call(
        "POST", f"/cases/{cid}/bookmarks", analyst, {"target_type": "event", "target_id": events[0]["id"]}
    )
    expect(status == 201, "bookmark an event", body)
    status, body, _ = api.call("POST", f"/cases/{cid}/iocs", analyst, {"type": "ip", "value": "203.0.113.50"})
    expect(status == 201, "add an IOC", body)

    # Create + snapshot
    status, rep, _ = api.call("POST", f"/cases/{cid}/reports", viewer, {"kind": "technical"})
    expect(status == 403, "viewer cannot create reports (403)", rep)
    status, rep, _ = api.call("POST", f"/cases/{cid}/reports", analyst, {"kind": "technical"})
    expect(status == 201 and rep["status"] == "draft", "analyst creates a technical report", rep)
    rid = rep["id"]
    expect(rep["counts"]["evidence"] == 1 and rep["counts"]["key_events"] >= 1, "snapshot counted", rep["counts"])
    status, body, _ = api.call("GET", f"/reports/{rid}", outsider)
    expect(status == 404, "outsider cannot see the report (404)", body)

    # Edit, QA gate, optimistic concurrency
    sections = {sd["name"]: f"{sd['title']}: text {HOSTILE}" for sd in rep["section_defs"]}
    unsupported = [{"title": "Brute force", "body": "no evidence yet"}]
    status, rep, _ = api.call(
        "PATCH", f"/reports/{rid}", analyst, {"expected_revision": 0, "sections": sections, "findings": unsupported}
    )
    expect(status == 200 and rep["revision"] == 1, "sections and a finding saved", rep)
    status, body, _ = api.call("PATCH", f"/reports/{rid}", analyst, {"expected_revision": 0, "title": "x"})
    expect(status == 409 and body["error"]["code"] == "stale_revision", "stale edit refused (409)", body)
    status, body, _ = api.call("POST", f"/reports/{rid}/submit", analyst, {"expected_revision": 1})
    codes = {e["code"] for e in body["error"]["details"]["errors"]} if status == 409 else set()
    expect("finding_without_evidence" in codes, "QA blocks a finding without evidence", body)
    finding = {
        "title": "Brute force against SSH",
        "body": "Repeated failures then a success.",
        "confidence": "high",
        "attack": ["T1110"],
        "refs": [
            {"type": "event", "id": events[0]["id"]},
            {"type": "alert", "id": alerts[0]["id"]},
            {"type": "evidence", "id": eid},
        ],
    }
    status, rep, _ = api.call("PATCH", f"/reports/{rid}", analyst, {"expected_revision": 1, "findings": [finding]})
    expect(status == 200 and len(rep["findings"][0]["refs"]) == 3, "finding cites event, alert, evidence", rep)
    status, rep, _ = api.call("POST", f"/reports/{rid}/submit", analyst, {"expected_revision": rep["revision"]})
    expect(status == 200 and rep["status"] == "in_review" and rep["qa"]["ok"], "QA passes, submitted", rep)
    status, body, _ = api.call("POST", f"/reports/{rid}/approve", analyst)
    expect(status == 403, "analyst cannot approve (403)", body)
    status, rep, _ = api.call("POST", f"/reports/{rid}/approve", lead)
    expect(status == 200 and rep["status"] == "approved", "lead approves (four eyes)", rep)
    status, rep, _ = api.call("POST", f"/reports/{rid}/sign", lead)
    expect(status == 200 and rep["status"] == "signed" and rep["signature"], "lead signs", rep)
    manifest = rep["manifest"]
    expect(len(manifest["artifacts"]) == 6, "six artifacts sealed", manifest)

    # Verify online, downloads, offline
    status, ver, _ = api.call("GET", f"/reports/{rid}/verify", viewer)
    expect(status == 200 and ver["ok"], "signed report verifies (stored hashes, signature, re-render)", ver)
    expected = {a["name"]: a["sha256"] for a in manifest["artifacts"]}
    names = {"html": "report.html", "pdf": "report.pdf", "json": "report.json",
             "stix": "iocs.stix.json", "csv": "iocs.csv", "timeline": "timeline.csv"}
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        for fmt, name in names.items():
            status, headers, data = fetch(api, "GET", f"/reports/{rid}/download?format={fmt}", viewer)
            expect(status == 200, f"download {fmt}", data[:300])
            expect(hashlib.sha256(data).hexdigest() == expected[name], f"{name} matches the manifest", None)
            expect("sandbox" in headers.get("content-security-policy", ""), f"{fmt} served with a sandbox CSP", headers)
            (out / name).write_bytes(data)
        html = (out / "report.html").read_text(encoding="utf-8")
        expect("<script" not in html.lower() and "&lt;script&gt;" in html, "hostile text escaped in HTML", None)
        status, headers, seal = fetch(api, "GET", f"/reports/{rid}/download?format=seal", viewer)
        expect(status == 200, "download seal.json", seal[:300])
        (out / "seal.json").write_bytes(seal)
        pem = json.loads(seal)["public_key_pem"]
        status, keys, _ = api.call("GET", "/signing-keys", viewer)
        expect(status == 200 and any(k["public_key"] == pem for k in keys), "seal key is the published custody key", keys)
        (out / "custody.pub.pem").write_text(pem, encoding="ascii")
        key_args = ["--public-key", str(out / "custody.pub.pem"), "--key-id", rep["key_id"]]
        res = verify_cli("report", str(out / "seal.json"), "--dir", str(out), *key_args)
        expect(res.returncode == 0, "offline CLI verifies the seal and all artifacts", res.stdout + res.stderr)
        (out / "report.pdf").write_bytes((out / "report.pdf").read_bytes() + b"%x")
        res = verify_cli("report", str(out / "seal.json"), "--dir", str(out), *key_args)
        expect(res.returncode == 1, "offline CLI detects a changed file", res.stdout)

        # Evidence export package
        status, headers, pkg = fetch(api, "POST", f"/evidence/{eid}/export-package", analyst)
        expect(status == 200 and headers["content-type"] == "application/zip", "export package", pkg[:300])
        (out / "package.zip").write_bytes(pkg)
        res = verify_cli("package", str(out / "package.zip"), *key_args)
        expect(res.returncode == 0, "package verifies offline (hashes, signature, custody chain)", res.stdout + res.stderr)
    status, chain, _ = api.call("GET", f"/evidence/{eid}/custody", analyst)
    last = chain["entries"][-1]
    expect(
        last["action"] == "exported" and last["detail"]["package_sha256"] == hashlib.sha256(pkg).hexdigest(),
        "export recorded in custody with the package hash",
        last,
    )
    status, body, _ = api.call("POST", f"/evidence/{eid}/export-package", viewer)
    expect(status == 403, "viewer cannot export packages (403)", body)

    # New version + AI draft (accepted, labelled)
    status, v2, _ = api.call("POST", f"/reports/{rid}/versions", analyst)
    expect(status == 201 and v2["version"] == 2 and v2["status"] == "draft", "new version v2", v2)
    status, draft, _ = api.call("POST", f"/ai/reports/{v2['id']}/draft", analyst, {"section": "executive_summary"})
    expect(status == 200 and draft["interaction"]["status"] == "valid", "AI draft validated", draft)
    iid = draft["interaction"]["id"]
    apply = {"interaction_id": iid, "expected_revision": v2["revision"]}
    status, body, _ = api.call("POST", f"/reports/{v2['id']}/sections/executive_summary/apply-ai", analyst, apply)
    expect(status == 409, "an unreviewed AI draft cannot be applied", body)
    status, body, _ = api.call("POST", f"/ai/interactions/{iid}/review", lead, {"decision": "accept"})
    expect(status == 200 and body["accepted"], "lead accepts the draft", body)
    status, v2, _ = api.call("POST", f"/reports/{v2['id']}/sections/executive_summary/apply-ai", analyst, apply)
    expect(status == 200 and v2["sections"]["executive_summary"]["origin"] == "ai_approved", "draft applied", v2)
    status, headers, page = fetch(api, "GET", f"/reports/{v2['id']}/preview", viewer)
    expect(status == 200 and b"AI-drafted, approved by" in page, "AI text labelled in the preview", page[:300])

    # Tamper the stored artifact in MinIO
    key = f"reports/{cid}/{rep['family_id']}/v1/report.html"
    tamper_artifact(key)
    status, ver, _ = api.call("GET", f"/reports/{rid}/verify", lead)
    expect(status == 200 and not ver["ok"] and {p["code"] for p in ver["problems"]} == {"artifact_mismatch"},
           "tampered artifact detected by verify", ver)
    status, headers, data = fetch(api, "GET", f"/reports/{rid}/download?format=html", viewer)
    expect(status == 409, "tampered artifact is not served (409)", data[:300])
    status, audit, _ = api.call("GET", f"/audit?action=report.sign&object_id={rid}", admin)
    expect(status == 200 and audit["total"] == 1, "signing audited", audit)
    print("PHASE 8 SMOKE PASSED")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
