"""Evidence kind identification (upload form auto-detect) on the committed fixtures."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.parsers.identify import HEAD_BYTES, TAIL_BYTES, identify

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _identify(path: Path) -> tuple[str, str | None]:
    data = path.read_bytes()
    found = identify(path.name, data[:HEAD_BYTES], data[-TAIL_BYTES:])
    return found.kind, found.parser


@pytest.mark.parametrize(
    ("fixture", "kind", "parser"),
    [
        ("evtx/new_user_security.evtx", "evtx", "evtx"),
        ("linux/auth.log", "log", "linux_auth"),
        ("deep/bin/capture.pcap", "pcap", "pcap"),
        ("deep/bin/capture.pcapng", "pcap", "pcap"),
        ("deep/bin/journal.json", "log", "journal_json"),
        ("deep/bin/wtmp", "log", "wtmp"),
        ("deep/bin/.bash_history", "log", "shell_history"),
        ("deep/bin/ConsoleHost_history.txt", "log", "shell_history"),
        ("deep/bin/SYSTEM", "file", "registry_hive"),
        ("deep/bin/NTUSER.DAT", "file", "registry_hive"),
        ("deep/bin/Amcache.hve", "file", "amcache"),
        ("deep/bin/EVIL.EXE-1A2B3C4D.pf", "file", "prefetch"),
        ("deep/bin/EVIL.EXE-MAM.pf", "file", "prefetch"),
        ("deep/bin/evil.lnk", "file", "lnk"),
        ("deep/bin/History", "file", "browser"),
        ("deep/bin/places.sqlite", "file", "browser"),
        ("deep/bin/fat12.img", "disk_image", "tsk_fs"),
        ("logs/access.log", "log", "web_access"),
        ("logs/pfirewall.log", "log", "w3c"),
        ("logs/u_ex260914.log", "log", "w3c"),
        ("logs/siem_export.csv", "log", "csv_events"),
        ("logs/edr_netconn.tsv", "log", "csv_events"),
        ("bundles/good.zip", "triage_bundle", None),
        ("bundles/mismatch.zip", "triage_bundle", None),
    ],
)
def test_fixtures_get_the_kind_their_parser_needs(
    fixture: str, kind: str, parser: str | None
) -> None:
    assert _identify(FIXTURES / fixture) == (kind, parser)


def test_bundle_manifest_found_through_the_tail_only() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("logs/big.log", bytes(200_000))  # pushes the central directory past the head
        zf.writestr("manifest.json", b"{}")
    data = buf.getvalue()
    assert identify("x.zip", data[:HEAD_BYTES], data[-TAIL_BYTES:]).kind == "triage_bundle"
    assert identify("x.zip", data[:HEAD_BYTES]).kind == "file"  # no tail: plain ZIP


def test_plain_zip_and_unknown_bytes_are_files_without_a_parser() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes/manifest.json", b"{}")  # not at the root: not a bundle
    found = identify("archive.zip", buf.getvalue())
    assert (found.kind, found.parser) == ("file", None)
    assert "ZIP" in found.description
    found = identify("blob.bin", b"\x00\x01\x02 nothing known")
    assert (found.kind, found.parser, found.confidence) == ("file", None, 0.0)
