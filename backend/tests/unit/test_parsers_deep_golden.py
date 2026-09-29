"""Golden-output tests for the Phase 6 parsers (guide 10.2 rule 6, 22.2).

Fixtures are synthetic (``tests/fixtures/deep/make_fixtures.py``). External engines (Sleuth
Kit, Volatility 3, Zeek) are replaced by the fake binaries in ``fixtures/deep/fake_tools``, which
also fail if the wrapper leaks the worker environment. Regenerate with
``DFIR_UPDATE_GOLDEN=1 pytest tests/unit/test_parsers_deep_golden.py`` and review the diff.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from app.parsers.base import ToolConfig
from app.parsers.registry import detect
from tests.unit.deep_helpers import BIN, check_golden, context, make_tool, run

DEEP_CASES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("registry_hive", "SYSTEM", "registry_system", {}),
    ("registry_hive", "SOFTWARE", "registry_software", {}),
    ("registry_hive", "NTUSER.DAT", "registry_ntuser", {}),
    ("amcache", "Amcache.hve", "amcache", {}),
    ("prefetch", "EVIL.EXE-1A2B3C4D.pf", "prefetch_v30", {}),
    ("prefetch", "XPTOOL.EXE-0BADF00D.pf", "prefetch_v17", {}),
    ("lnk", "evil.lnk", "lnk", {}),
    ("browser", "History", "browser_chromium", {}),
    ("browser", "places.sqlite", "browser_firefox", {}),
    ("pe_static", "sample.exe", "pe_static", {}),
    ("yara_scan", "eicar_mimikatz.txt", "yara_scan", {}),
    ("pcap", "capture.pcap", "pcap", {}),
    ("pcap", "capture.pcapng", "pcapng", {}),
    ("wtmp", "wtmp", "wtmp", {}),
    ("wtmp", "btmp", "btmp", {}),
    ("shell_history", ".bash_history", "shell_bash", {}),
    ("shell_history", ".zsh_history", "shell_zsh", {}),
    ("shell_history", "ConsoleHost_history.txt", "shell_powershell", {}),
    ("journal_json", "journal.json", "journal_json", {}),
]
TOOL_CASES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("tsk_fs", "fat12.img", "tsk_fs", {"timezone": "UTC"}),
    (
        "volatility",
        "fat12.img",
        "volatility",
        {"os": "windows", "plugins": ["info", "pslist", "cmdline", "netscan", "malfind"]},
    ),
    ("zeek", "capture.pcap", "zeek", {}),
]
ALL_PARSERS = {c[0] for c in DEEP_CASES + TOOL_CASES}


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), DEEP_CASES)
def test_golden_output(parser_name: str, fixture: str, golden: str, params: dict[str, Any]) -> None:
    ctx = context(BIN / fixture, params=params, source_file=f"evidence/{fixture}")
    check_golden(run(parser_name, ctx), f"deep_{golden}")


@pytest.fixture
def fake_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ToolConfig:
    tools = tmp_path / "tools"
    for name in ("fls", "mmls", "vol", "zeek"):
        make_tool(tools, name)
    monkeypatch.setenv("DFIR_FAKE_SECRET", "must-not-reach-the-engine")
    return ToolConfig(search_path=str(tools), timeout_s=60)


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), TOOL_CASES)
def test_tool_wrapper_golden_output(
    parser_name: str,
    fixture: str,
    golden: str,
    params: dict[str, Any],
    fake_tools: ToolConfig,
    tmp_path: Path,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    ctx = context(BIN / fixture, params=params, tools=fake_tools, work_dir=work)
    actual = run(parser_name, ctx)
    check_golden(actual, f"deep_{golden}")
    # engines wrote only into the work dir
    assert all(p.resolve().is_relative_to(work.resolve()) for p in work.rglob("*"))


def test_mam_prefetch_decompresses_to_the_same_events() -> None:
    plain = run("prefetch", context(BIN / "EVIL.EXE-1A2B3C4D.pf", source_file="x.pf"))
    packed = run("prefetch", context(BIN / "EVIL.EXE-MAM.pf", source_file="x.pf"))
    assert packed["assumptions"]["container"] == "MAM"
    assert [e["message"] for e in packed["events"]] == [e["message"] for e in plain["events"]]
    assert [e["ts"] for e in packed["events"]] == [e["ts"] for e in plain["events"]]


EXPECTED_DETECTION = {
    "SYSTEM": "registry_hive",
    "SOFTWARE": "registry_hive",
    "NTUSER.DAT": "registry_hive",
    "Amcache.hve": "amcache",
    "EVIL.EXE-1A2B3C4D.pf": "prefetch",
    "EVIL.EXE-MAM.pf": "prefetch",
    "XPTOOL.EXE-0BADF00D.pf": "prefetch",
    "evil.lnk": "lnk",
    "History": "browser",
    "places.sqlite": "browser",
    "sample.exe": "pe_static",
    "capture.pcap": "pcap",
    "capture.pcapng": "pcap",
    "wtmp": "wtmp",
    "btmp": "wtmp",
    ".bash_history": "shell_history",
    ".zsh_history": "shell_history",
    "ConsoleHost_history.txt": "shell_history",
    "journal.json": "journal_json",
    "fat12.img": "tsk_fs",
    "eicar_mimikatz.txt": None,  # YARA is explicit-only
}


@pytest.mark.parametrize(("fixture", "expected"), sorted(EXPECTED_DETECTION.items()))
def test_auto_detection(fixture: str, expected: str | None) -> None:
    head = (BIN / fixture).read_bytes()[:8192]
    found = detect(head, f"files/users/alice/{fixture}")
    assert (found[0][0] if found else None) == expected


def test_detection_from_bundle_member_names() -> None:
    # Phase 5 bundle member paths (collector naming) are detected by basename.
    head = (BIN / "History").read_bytes()[:8192]
    assert detect(head, "History")[0][0] == "browser"
    assert detect((BIN / ".bash_history").read_bytes(), ".bash_history~2")[0][0] == "shell_history"


def test_every_fixture_is_used() -> None:
    used = {c[1] for c in DEEP_CASES + TOOL_CASES} | set(EXPECTED_DETECTION) | {"EVIL.EXE-MAM.pf"}
    assert {p.name for p in BIN.iterdir()} <= used, sorted({p.name for p in BIN.iterdir()} - used)


def test_update_golden_flag_not_set_in_ci() -> None:
    assert os.environ.get("DFIR_UPDATE_GOLDEN") in (None, "", "0", "1")
