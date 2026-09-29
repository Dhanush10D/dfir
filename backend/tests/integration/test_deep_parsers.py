"""Phase 6: deep parsers through the real pipeline (API -> jobs -> ProcessingService -> events)
and bundle reprocessing that derives the artifacts the new parsers recognize. Fake vault, no
broker, no external engines (the tool wrappers are covered by unit tests with fake binaries)."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import Any

import pytest

from app.db.models import UserRole
from app.services import bundles as bundles_module
from tests.fixtures.bundles.make_bundles import entry, info, manifest
from tests.integration.harness import Harness, UserCtx

pytestmark = pytest.mark.integration

DEEP = Path(__file__).resolve().parents[1] / "fixtures" / "deep" / "bin"
AUTH_LOG = (Path(__file__).resolve().parents[1] / "fixtures" / "linux" / "auth.log").read_bytes()
WINDOWS_MEMBERS = [
    ("files/registry/SYSTEM", "SYSTEM", "registry_hive"),
    ("files/registry/SOFTWARE", "SOFTWARE", "registry_hive"),
    ("files/registry/Amcache.hve", "Amcache.hve", "amcache"),
    ("files/prefetch/EVIL.EXE-1A2B3C4D.pf", "EVIL.EXE-MAM.pf", "prefetch"),
    ("files/users/alice/NTUSER.DAT", "NTUSER.DAT", "registry_hive"),
    ("files/users/alice/recent/evil.lnk", "evil.lnk", "lnk"),
    ("files/users/alice/ConsoleHost_history.txt", "ConsoleHost_history.txt", "shell_history"),
    ("browser/alice/chrome/Default/History", "History", "browser"),
    ("browser/alice/firefox/abcd.default/places.sqlite", "places.sqlite", "browser"),
    ("logs/var/log/auth.log", None, "linux_auth"),
    ("files/home/bob/.bash_history", ".bash_history", "shell_history"),
    ("logs/var/log/wtmp", "wtmp", "wtmp"),
    ("logs/journal/journal_14d.json", "journal.json", "journal_json"),
]


@pytest.fixture
def analyst(h: Harness) -> UserCtx:
    return h.make_user(UserRole.analyst)


def _bundle_bytes() -> bytes:
    members = [
        (path, AUTH_LOG if src is None else (DEEP / src).read_bytes())
        for path, src, _ in WINDOWS_MEMBERS
    ]
    files = [entry(p, d, p.split("/", 1)[0]) for p, d in members]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, data in members:
            zf.writestr(info(path), data)
        zf.writestr(info("manifest.json"), manifest(files))
    return buf.getvalue()


def _derived(h: Harness, user: UserCtx, case_id: str, bundle_id: str) -> dict[str, dict[str, Any]]:
    items = h.get(f"/cases/{case_id}/evidence", user).json()["items"]
    return {e["original_name"]: e for e in items if e["parent_evidence_id"] == bundle_id}


def test_bundle_reprocess_derives_newly_parseable_members(
    h: Harness, analyst: UserCtx, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = h.create_case(analyst)
    data = _bundle_bytes()
    bundle = h.stored_evidence(
        analyst,
        case["id"],
        data,
        kind="triage_bundle",
        original_name="triage.zip",
        source_host="ws01",
    )
    # 1. Ingest as Phase 5 did: only the Phase 2 parsers existed.
    real_detect = bundles_module.detect

    def phase5_detect(
        head: bytes, filename: str, path: Path | None = None
    ) -> list[tuple[str, float]]:
        return [(n, s) for n, s in real_detect(head, filename, path) if n in ("evtx", "linux_auth")]

    monkeypatch.setattr(bundles_module, "detect", phase5_detect)
    r = h.post(f"/evidence/{bundle['id']}/process", analyst, json={})
    assert r.status_code == 202, r.text
    job_id = r.json()["jobs"][0]["id"]
    [first] = h.run_bundle_pending()
    assert first.outcome == "succeeded", first
    assert list(_derived(h, analyst, case["id"], bundle["id"])) == ["logs/var/log/auth.log"]
    h.run_pending()

    # 2. Phase 6: reprocess the same bundle; the new parsers now claim the other members.
    monkeypatch.setattr(bundles_module, "detect", real_detect)
    r = h.post(f"/jobs/{job_id}/reprocess", analyst)
    assert r.status_code == 202, r.text
    [rerun] = h.run_bundle_pending()
    assert rerun.outcome == "succeeded", rerun
    assert rerun.counts["derived_new"] == len(WINDOWS_MEMBERS) - 1
    derived = _derived(h, analyst, case["id"], bundle["id"])
    assert sorted(derived) == sorted(p for p, _, _ in WINDOWS_MEMBERS)
    assert derived["logs/var/log/wtmp"]["kind"] == "log"

    # Every derived member goes through the ordinary parse pipeline with the expected parser.
    results = h.run_pending()
    assert results and all(r.outcome == "succeeded" for r in results), [
        r.as_dict() for r in results
    ]
    jobs = h.get(f"/cases/{case['id']}/jobs", analyst).json()["items"]
    parsers = {
        j["evidence_id"]: j["parser"]
        for j in jobs
        if j["kind"] == "parse" and j["status"] == "succeeded"
    }
    for path, _, parser in WINDOWS_MEMBERS:
        assert parsers[derived[path]["id"]] == parser, path

    # Events are in the timeline with their source types.
    r = h.post(f"/cases/{case['id']}/events/search", analyst, json={"limit": 500})
    assert r.status_code == 200, r.text
    events = r.json()["items"]
    source_types = {e["source_type"] for e in events}
    assert {
        "registry",
        "amcache",
        "prefetch",
        "lnk",
        "browser",
        "shell_history",
        "wtmp",
        "journal",
    } <= source_types
    prefetch = [e for e in events if e["source_type"] == "prefetch"]
    assert {e["process_name"] for e in prefetch} == {"EVIL.EXE"} and len(prefetch) == 2
    assert any(e["event_code"] == "run_key" for e in events)

    # A third run reuses everything (no duplicates).
    r = h.post(f"/jobs/{job_id}/reprocess", analyst)
    assert r.status_code == 202, r.text
    [third] = h.run_bundle_pending()
    assert third.outcome == "succeeded" and third.counts["derived_new"] == 0


def test_explicit_parsers_and_manifest_tool_versions(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    sample = h.stored_evidence(
        analyst,
        case["id"],
        (DEEP / "eicar_mimikatz.txt").read_bytes(),
        kind="file",
        original_name="dropper.txt",
    )
    # YARA is never auto-selected; nothing else claims this text file either.
    r = h.post(f"/evidence/{sample['id']}/process", analyst, json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "no_parser", r.text
    r = h.post(f"/evidence/{sample['id']}/process", analyst, json={"parsers": ["yara_scan"]})
    assert r.status_code == 202, r.text
    [result] = h.run_pending()
    assert result.outcome == "succeeded" and result.counts["events_emitted"] == 2
    job = h.get(f"/jobs/{r.json()['jobs'][0]['id']}", analyst).json()
    manifest = job["run_manifest"]
    assert manifest["tools"]["libyara"] and len(manifest["assumptions"]["rule_pack_sha256"]) == 64
    assert manifest["limits"]["tool_timeout_s"] > 0

    pe = h.stored_evidence(
        analyst,
        case["id"],
        (DEEP / "sample.exe").read_bytes(),
        kind="file",
        original_name="sample.exe",
    )
    r = h.post(f"/evidence/{pe['id']}/process", analyst, json={})
    assert r.status_code == 202 and r.json()["jobs"][0]["parser"] == "pe_static", r.text
    [result] = h.run_pending()
    assert result.outcome == "succeeded"


def test_engine_missing_fails_the_job_cleanly(h: Harness, analyst: UserCtx, tmp_path: Path) -> None:
    h.settings = h.settings.model_copy(update={"tool_search_path": str(tmp_path)})
    case = h.create_case(analyst)
    cap = h.stored_evidence(
        analyst,
        case["id"],
        (DEEP / "capture.pcap").read_bytes(),
        kind="pcap",
        original_name="c.pcap",
    )
    r = h.post(f"/evidence/{cap['id']}/process", analyst, json={"parsers": ["zeek"]})
    assert r.status_code == 202, r.text
    [result] = h.run_pending()
    assert result.outcome == "failed"
    assert "'zeek' is not installed in this worker image" in (result.error or "")
    # The default pcap parser works without any engine.
    r = h.post(f"/evidence/{cap['id']}/process", analyst, json={"parsers": ["pcap"]})
    [result] = h.run_pending()
    assert result.outcome == "succeeded" and result.counts["events_emitted"] == 7


def test_volatility_params_validated_by_the_api(h: Harness, analyst: UserCtx) -> None:
    case = h.create_case(analyst)
    mem = h.stored_evidence(
        analyst, case["id"], b"\x00" * 4096, kind="memory", original_name="host.mem"
    )
    for params in ({"plugins": ["windows.pslist; id"]}, {"os": "solaris"}, {"symbols": "/etc"}):
        r = h.post(
            f"/evidence/{mem['id']}/process",
            analyst,
            json={"parsers": ["volatility"], "params": params},
        )
        assert r.status_code == 422, (params, r.text)
    r = h.post(
        f"/evidence/{mem['id']}/process",
        analyst,
        json={"parsers": ["volatility"], "params": {"os": "linux", "plugins": ["pslist"]}},
    )
    assert r.status_code == 202, r.text
    assert r.json()["jobs"][0]["params"] == {"os": "linux", "plugins": ["pslist"]}
    assert json.dumps(r.json()["jobs"][0]["params"])  # stored canonical params
    assert uuid.UUID(r.json()["jobs"][0]["id"])
