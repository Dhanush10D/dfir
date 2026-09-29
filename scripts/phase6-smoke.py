#!/usr/bin/env python3
"""Phase 6 live smoke test against the running compose stack (stdlib only).

    python scripts/phase6-smoke.py --admin-email E [--admin-password P] [--base URL]

1. the synthetic fixtures (registry hives, Amcache, Prefetch MAM, LNK, Chromium/Firefox history,
   PE, pcap, wtmp, journal JSON, shell history) are uploaded and auto-processed in the worker
   image; each job succeeds with the event count of its golden file and the events are in the
   timeline;
2. the FAT12 image goes through the real Sleuth Kit (mmls + fls) in the worker image: README.TXT
   and the deleted file show up, and the run manifest records the image's sleuthkit version;
3. YARA is explicit-only (viewer 403; analyst request matches EICAR + Mimikatz); Zeek is not in
   the image and fails the job with a clear message; Volatility 3 runs offline and fails cleanly
   on a non-memory image; bad Volatility params are 422;
4. a Windows-style triage bundle derives every member the new parsers recognize, all derived parse
   jobs succeed, a reprocess reuses them; derived custody verifies. Exits non-zero on failure.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "backend" / "tests" / "fixtures"
DEEP = FIXTURES / "deep" / "bin"
GOLDEN = FIXTURES / "golden"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p1 = _load("phase1_smoke", ROOT / "scripts" / "phase1-smoke.py")
p2 = _load("phase2_smoke", ROOT / "scripts" / "phase2-smoke.py")
p3 = _load("phase3_smoke", ROOT / "scripts" / "phase3-smoke.py")
make_bundles = _load("make_bundles", FIXTURES / "bundles" / "make_bundles.py")
Api, expect, login, make_user = p1.Api, p1.expect, p1.login, p1.make_user

AUTO = [
    # (fixture, kind, parser, golden)
    ("SYSTEM", "file", "registry_hive", "deep_registry_system"),
    ("NTUSER.DAT", "file", "registry_hive", "deep_registry_ntuser"),
    ("Amcache.hve", "file", "amcache", "deep_amcache"),
    ("EVIL.EXE-MAM.pf", "file", "prefetch", "deep_prefetch_v30"),
    ("evil.lnk", "file", "lnk", "deep_lnk"),
    ("History", "file", "browser", "deep_browser_chromium"),
    ("places.sqlite", "file", "browser", "deep_browser_firefox"),
    ("sample.exe", "file", "pe_static", "deep_pe_static"),
    ("capture.pcap", "pcap", "pcap", "deep_pcap"),
    ("wtmp", "log", "wtmp", "deep_wtmp"),
    ("journal.json", "log", "journal_json", "deep_journal_json"),
    (".bash_history", "log", "shell_history", "deep_shell_bash"),
]
BUNDLE_MEMBERS = [
    ("files/registry/SYSTEM", "SYSTEM"),
    ("files/registry/SOFTWARE", "SOFTWARE"),
    ("files/registry/Amcache.hve", "Amcache.hve"),
    ("files/prefetch/EVIL.EXE-1A2B3C4D.pf", "EVIL.EXE-MAM.pf"),
    ("files/users/alice/NTUSER.DAT", "NTUSER.DAT"),
    ("files/users/alice/recent/evil.lnk", "evil.lnk"),
    ("files/users/alice/ConsoleHost_history.txt", "ConsoleHost_history.txt"),
    ("browser/alice/chrome/Default/History", "History"),
    ("browser/alice/firefox/abcd.default/places.sqlite", "places.sqlite"),
]


def upload(api: Any, token: str, cid: str, name: str, data: bytes, kind: str) -> str:
    status, body, _ = api.call(
        "POST",
        f"/cases/{cid}/evidence",
        token,
        {"kind": kind, "original_name": name, "expected_sha256": hashlib.sha256(data).hexdigest()},
    )
    expect(status == 201, f"create evidence {name}", body)
    eid = str(body["evidence"]["id"])
    status, body, _ = api.call("PUT", f"/evidence/{eid}/upload", token, raw=data)
    expect(status == 200, f"upload {name}", body)
    status, body, _ = api.call("POST", f"/evidence/{eid}/finalize", token)
    expect(status == 200 and body["ok"], f"finalize {name}", body)
    return eid


def process(api: Any, token: str, eid: str, body: dict[str, Any]) -> dict[str, Any]:
    status, resp, _ = api.call("POST", f"/evidence/{eid}/process", token, body)
    expect(status == 202, f"process queued {body}", resp)
    return dict(p2.wait_job(api, token, resp["jobs"][0]["id"], timeout=300))


def bundle_bytes() -> bytes:
    members = [(path, (DEEP / src).read_bytes()) for path, src in BUNDLE_MEMBERS]
    files = [make_bundles.entry(p, d, p.split("/", 1)[0]) for p, d in members]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, data in members:
            zf.writestr(make_bundles.info(path), data)
        zf.writestr(make_bundles.info("manifest.json"), make_bundles.manifest(files))
    return buf.getvalue()


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
    status, case, _ = api.call("POST", "/cases", lead, {"title": "Phase 6 smoke"})
    expect(status == 201, "lead creates case", case)
    cid = case["id"]
    for uid, role in ((analyst_id, "analyst"), (viewer_id, "viewer")):
        status, body, _ = api.call(
            "POST", f"/cases/{cid}/members", lead, {"user_id": uid, "role": role}
        )
        expect(status == 200, f"lead adds {role}", body)

    # ---- 1: every pure parser in the worker image, auto-detected, golden counts
    for fixture, kind, parser_name, golden in AUTO:
        eid = upload(api, analyst, cid, fixture, (DEEP / fixture).read_bytes(), kind)
        job = process(api, analyst, eid, {})
        want = json.loads((GOLDEN / f"{golden}.json").read_text(encoding="utf-8"))["counts"]
        counts = (job.get("run_manifest") or {}).get("counts", {})
        expect(
            job["parser"] == parser_name
            and job["status"] == "succeeded"
            and counts.get("events_emitted") == want["events_emitted"]
            and counts.get("inserted") == want["events_emitted"],
            f"{fixture}: {parser_name} succeeded with {want['events_emitted']} events",
            job,
        )
    p3.settle(api, analyst, cid)
    events = p2.timeline(api, viewer, cid, "source_type=registry")
    expect(any(e["event_code"] == "run_key" for e in events), "registry events in the timeline")

    # ---- 2: real Sleuth Kit on the FAT12 image
    fat = upload(api, analyst, cid, "fat12.img", (DEEP / "fat12.img").read_bytes(), "disk_image")
    job = process(api, analyst, fat, {})
    manifest = job.get("run_manifest") or {}
    expect(
        job["parser"] == "tsk_fs" and job["status"] == "succeeded",
        "fat12.img: tsk_fs (mmls + fls) succeeded in the worker image",
        job,
    )
    expect("sleuthkit" in manifest.get("tools", {}), "run manifest records sleuthkit", manifest)
    fs_events = p2.timeline(api, analyst, cid, f"evidence_id={fat}")
    names = {e["file_path"] for e in fs_events}
    expect("/README.TXT" in names, "README.TXT in the file-system timeline", sorted(names))
    expect(
        any("deleted" in e["tags"] for e in fs_events),
        "deleted FAT entry tagged 'deleted'",
        [(e["file_path"], e["tags"]) for e in fs_events],
    )

    # ---- 3: explicit engines and failures
    sample = upload(
        api, analyst, cid, "dropper.txt", (DEEP / "eicar_mimikatz.txt").read_bytes(), "file"
    )
    status, body, _ = api.call("POST", f"/evidence/{sample}/process", analyst, {})
    expect(status == 422, "YARA is never auto-selected (no parser for a text file)", body)
    status, body, _ = api.call(
        "POST", f"/evidence/{sample}/process", viewer, {"parsers": ["yara_scan"]}
    )
    expect(status == 403, "viewer cannot start a YARA scan", body)
    job = process(api, analyst, sample, {"parsers": ["yara_scan"]})
    rules = {e["event_code"] for e in p2.timeline(api, analyst, cid, f"evidence_id={sample}")}
    expect(
        job["status"] == "succeeded" and rules == {"EICAR_Test_File", "Mimikatz_Strings"},
        "YARA matched EICAR and Mimikatz",
        (job, rules),
    )
    pcap = upload(api, analyst, cid, "zeek.pcap", (DEEP / "capture.pcap").read_bytes(), "pcap")
    job = process(api, analyst, pcap, {"parsers": ["zeek"]})
    expect(
        job["status"] == "failed" and "'zeek' is not installed" in (job["error"] or ""),
        "zeek (optional engine) fails with a clear message",
        job,
    )
    mem = upload(api, analyst, cid, "host.mem", b"\x00" * (1024 * 1024), "memory")
    status, body, _ = api.call(
        "POST",
        f"/evidence/{mem}/process",
        analyst,
        {"parsers": ["volatility"], "params": {"plugins": ["windows.pslist; id"]}},
    )
    expect(status == 422, "volatility plugins outside the allowlist are rejected", body)
    job = process(api, analyst, mem, {"parsers": ["volatility"], "params": {"plugins": ["info"]}})
    expect(
        job["status"] == "failed" and "Volatility could not analyse" in (job["error"] or ""),
        "Volatility 3 (offline) fails cleanly on a non-memory image",
        job,
    )

    # ---- 4: a Windows triage bundle derives every recognized member
    raw = bundle_bytes()
    bid = upload(api, analyst, cid, "triage_ws01.zip", raw, "triage_bundle")
    job = process(api, analyst, bid, {})
    counts = (job.get("run_manifest") or {}).get("counts", {})
    expect(
        job["status"] == "succeeded" and counts.get("ingested") == len(BUNDLE_MEMBERS),
        f"bundle derived all {len(BUNDLE_MEMBERS)} members: {counts}",
        job,
    )
    p3.settle(api, analyst, cid)
    status, jobs, _ = api.call("GET", f"/cases/{cid}/jobs?limit=500", analyst)
    status, items, _ = api.call("GET", f"/cases/{cid}/evidence", analyst)
    derived = {e["id"] for e in items["items"] if e["parent_evidence_id"] == bid}
    parse_jobs = [j for j in jobs["items"] if j["evidence_id"] in derived and j["kind"] == "parse"]
    expect(
        len(parse_jobs) == len(BUNDLE_MEMBERS)
        and all(j["status"] == "succeeded" for j in parse_jobs),
        "every derived member parsed",
        [(j["parser"], j["status"], j["error"]) for j in parse_jobs],
    )
    one = sorted(derived)[0]
    status, body, _ = api.call("POST", f"/evidence/{one}/verify", analyst)
    expect(status == 200 and body["ok"] is True, "derived item custody verifies", body)
    status, body, _ = api.call("POST", f"/jobs/{job['id']}/reprocess", analyst)
    expect(status == 202, "bundle reprocess queued", body)
    rerun = p2.wait_job(api, analyst, body["id"], timeout=300)
    expect(
        rerun["status"] == "succeeded" and rerun["run_manifest"]["counts"].get("derived_new") == 0,
        "reprocess reused the derived items",
        rerun,
    )
    p3.settle(api, analyst, cid)
    print("PHASE 6 SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
