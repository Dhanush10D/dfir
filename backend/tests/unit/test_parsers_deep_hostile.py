"""Hostile-input and limit tests for the Phase 6 parsers (no Docker, no network).

Every parser must either raise ``ParserInputError`` (whole input unusable) or finish with balanced
accounting, whatever bytes it is given; structures are bounded (cycles, counts, big-data
segments, decompression), SQLite views are refused, and limits/timeouts apply.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.parsers.base import ParseLimits, ParserInputError, ToolConfig
from app.parsers.regf import Hive, RegfError
from app.parsers.timeconv import TimestampError, filetime, iso_utc, prtime, unix_seconds, webkit
from app.parsers.xpress import XpressError, decompress_huffman
from tests.unit.deep_helpers import BIN, DEEP, context, run

sys.path.insert(0, str(DEEP))
from make_fixtures import ft, xpress_compress
from regwriter import RegKey, build_hive

FUZZ = settings(
    max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


def parse_bytes(tmp_path: Path, parser: str, data: bytes, name: str, **kw: Any) -> dict[str, Any]:
    path = tmp_path / "evidence.bin"
    if path.exists():
        path.chmod(0o600)
        path.unlink()
    path.write_bytes(data)
    return run(parser, context(path, source_file=name, **kw))


def mutate(data: bytes, flips: list[tuple[int, int]], start: int = 0) -> bytes:
    buf = bytearray(data)
    for offset, value in flips:
        buf[start + offset % max(len(buf) - start, 1)] = value
    return bytes(buf)


# ---------------------------------------------------------------------- time conversions


def test_timestamp_conversions() -> None:
    assert filetime(0) is None and webkit(0) is None and prtime(0) is None
    assert unix_seconds(0) is None
    conv = filetime(ft(1767348000))
    assert conv is not None and conv.ts.isoformat() == "2026-01-02T10:00:00+00:00"
    assert conv.original == f"filetime:{ft(1767348000)}"
    for bad in (
        lambda: filetime(-1),
        lambda: filetime(2**64),
        lambda: webkit(10**20),
        lambda: prtime(-5),
    ):
        with pytest.raises(TimestampError):
            bad()
    for value in (float("nan"), float("inf"), "12", True, 10**15):
        with pytest.raises(TimestampError):
            unix_seconds(value)
    with pytest.raises(TimestampError):
        iso_utc("2026-01-02T10:00:00")  # naive
    assert iso_utc("2026-01-02T12:00:00+02:00").ts.isoformat() == "2026-01-02T10:00:00+00:00"


# ---------------------------------------------------------------------- LZXPRESS Huffman


def test_xpress_round_trip_multi_block() -> None:
    data = (b"prefetch" * 5000 + bytes(range(256)) * 300 + b"\x00" * 70_000)[:200_000]
    assert decompress_huffman(xpress_compress(data), len(data)) == data


def test_xpress_rejects_corrupt_input() -> None:
    data = b"hello hello hello" * 10
    packed = xpress_compress(data)
    with pytest.raises(XpressError):
        decompress_huffman(bytes(256) + packed[256:], len(data))  # empty Huffman table
    with pytest.raises(XpressError):
        decompress_huffman(packed[:100], len(data))  # truncated table
    with pytest.raises(XpressError):
        decompress_huffman(packed, len(data) * 1000)  # input ends long before the declared size
    # first symbol a match (offset 1) with nothing decoded yet -> offset before start of output
    lengths = bytearray(256)
    for s in range(0, 254):
        lengths[s // 2] |= 8 << (4 * (s % 2))
    for s in (254, 255, 256, 257):
        lengths[s // 2] |= 9 << (4 * (s % 2))
    stream = bytes(lengths) + struct.pack("<HH", 0b1111111100000000, 0)  # code 510 = symbol 256
    with pytest.raises(XpressError):
        decompress_huffman(stream, 10)


@FUZZ
@given(st.binary(min_size=0, max_size=600), st.integers(0, 70_000))
def test_xpress_fuzz_never_hangs_or_overflows(data: bytes, size: int) -> None:
    with contextlib.suppress(XpressError):
        out = decompress_huffman(data, size)
        assert len(out) == size


# ---------------------------------------------------------------------- regf reader


def _hive(root: RegKey) -> bytes:
    return build_hive(root, "\\REGISTRY\\MACHINE\\SYSTEM", ft(1767348000))


def test_regf_big_data_value(tmp_path: Path) -> None:
    root = RegKey("ROOT", ft(1767348000))
    root.key("Select", ft(1767348000)).binary("Big", bytes(range(256)) * 200)  # 51200 bytes
    path = tmp_path / "hive"
    path.write_bytes(_hive(root))
    with Hive(path, max_bytes=10**7) as hive:
        select = hive.open("select")
        assert select is not None
        value = select.value("big")
        assert value is not None and value.data == bytes(range(256)) * 200


def test_regf_big_data_segment_past_eof_terminates(tmp_path: Path) -> None:
    root = RegKey("ROOT", ft(1767348000))
    root.key("Select", ft(1767348000)).binary("Big", b"A" * 40000)
    data = bytearray(_hive(root))
    db = data.index(b"db\x03\x00", 4096)
    seg_list = struct.unpack_from("<I", data, db + 4)[0]
    struct.pack_into("<I", data, 4096 + seg_list + 4, 0x7FFFFFF0)  # first segment beyond EOF
    path = tmp_path / "hive"
    path.write_bytes(bytes(data))
    with Hive(path, max_bytes=10**7) as hive:
        select = hive.open("Select")
        assert select is not None
        with pytest.raises(RegfError):
            list(select.values())


def test_regf_cycle_and_huge_counts(tmp_path: Path) -> None:
    root = RegKey("ROOT", ft(1767348000))
    root.key("A\\B\\C", ft(1767348000)).dword("X", 1)
    root.key("A\\B", ft(1767348000)).dword("Y", 2)
    data = bytearray(_hive(root))
    root_offset = struct.unpack_from("<I", data, 36)[0]
    lf = data.index(b"lf\x01\x00", 4096)  # first list written = B's (children are written first)
    struct.pack_into("<I", data, lf + 4, root_offset)  # B -> root: a cycle
    path = tmp_path / "hive"
    path.write_bytes(bytes(data))
    with Hive(path, max_bytes=10**7) as hive:
        names: list[str] = []

        def walk(key: Any) -> None:
            for sub in key.subkeys():
                names.append(sub.path)
                walk(sub)

        walk(hive.root)
        assert hive.cycles == 1 and names == ["A", "A\\B"]
        b = hive.open("A\\B")
        assert b is not None
        b_offset = b.offset
    struct.pack_into("<I", data, 4096 + b_offset + 4 + 36, 0xFFFFFFFF)  # absurd value count
    path.write_bytes(bytes(data))
    with Hive(path, max_bytes=10**7) as hive:
        key = hive.open("A\\B")
        assert key is not None
        with pytest.raises(RegfError):
            list(key.values())


def test_regf_refuses_bad_files(tmp_path: Path) -> None:
    path = tmp_path / "hive"
    path.write_bytes(b"regf" + bytes(100))
    with pytest.raises(RegfError):
        Hive(path, max_bytes=10**7)
    path.write_bytes((BIN / "SYSTEM").read_bytes())
    with pytest.raises(RegfError):
        Hive(path, max_bytes=1000)
    result = None
    with pytest.raises(ParserInputError):
        result = parse_bytes(tmp_path, "registry_hive", b"regf" + bytes(5000), "SYSTEM")
    assert result is None


def test_registry_mru_value_names_with_odd_digits(tmp_path: Path) -> None:
    root = RegKey("ROOT", ft(1767348000))
    typed = root.key(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", ft(1767348000)
    )
    typed.sz("url3", "C:\\ok").sz("url²", "C:\\sup").sz("url" + "9" * 5000, "C:\\long")
    data = build_hive(root, "\\??\\C:\\Users\\eve\\ntuser.dat", ft(1767348000))
    result = parse_bytes(tmp_path, "registry_hive", data, "NTUSER.DAT")
    assert result["counts"]["errors"] == 0
    positions = {
        e["raw"]["value"]: e["raw"]["mru_position"]
        for e in result["events"]
        if e["event_code"] == "typed_path"
    }
    assert positions == {"C:\\ok": 2, "C:\\sup": -1, "C:\\long": -1}


@FUZZ
@given(st.lists(st.tuples(st.integers(0, 4000), st.integers(0, 255)), min_size=1, max_size=30))
def test_registry_fuzz(tmp_path: Path, flips: list[tuple[int, int]]) -> None:
    for fixture, parser in (
        ("SYSTEM", "registry_hive"),
        ("NTUSER.DAT", "registry_hive"),
        ("Amcache.hve", "amcache"),
    ):
        data = mutate((BIN / fixture).read_bytes(), flips, start=4096)
        with contextlib.suppress(ParserInputError):
            parse_bytes(tmp_path, parser, data, fixture)


# ---------------------------------------------------------------------- binary formats


@FUZZ
@given(st.lists(st.tuples(st.integers(0, 10_000), st.integers(0, 255)), min_size=1, max_size=20))
def test_binary_formats_fuzz(tmp_path: Path, flips: list[tuple[int, int]]) -> None:
    for fixture, parser in (
        ("EVIL.EXE-1A2B3C4D.pf", "prefetch"),
        ("EVIL.EXE-MAM.pf", "prefetch"),
        ("evil.lnk", "lnk"),
        ("capture.pcap", "pcap"),
        ("capture.pcapng", "pcap"),
        ("wtmp", "wtmp"),
        ("sample.exe", "pe_static"),
        ("journal.json", "journal_json"),
    ):
        data = mutate((BIN / fixture).read_bytes(), flips)
        with contextlib.suppress(ParserInputError):
            parse_bytes(tmp_path, parser, data, fixture)


# ---------------------------------------------------------------------- numeric fields in text


# ``str.isdigit`` accepts "²" (``int()`` does not) and ``int()`` refuses more than 4300 digits.
# Superscripts two/three/one, then Arabic-Indic, Extended Arabic-Indic, NKo and Devanagari digits.
ODD_DIGITS = (0xB2, 0xB3, 0xB9, 0x663, 0x6F5, 0x7C9, 0x966)
HOSTILE_NUMBERS = st.one_of(
    st.text(alphabet="0123456789" + "".join(map(chr, ODD_DIGITS)), max_size=40),
    st.integers(min_value=0, max_value=10**30).map(str),
    st.integers(4290, 6000).map(lambda n: "9" * n),
    st.integers(4290, 6000).map(lambda n: "٣" * n),
)


def _events_by_line(result: dict[str, Any]) -> set[str]:
    return {e["source_record_id"] for e in result["events"]}


def test_shell_history_hostile_numbers_cost_one_record(tmp_path: Path) -> None:
    lines = [
        ": 1767347700:0;whoami",
        ": 1700000000:" + "9" * 5000 + ";ls",  # elapsed beyond int()'s digit limit
        ": " + "9" * 20 + ":0;uname -a",  # 20 digits parse, but beyond any datetime
        ": 1767347800:3;id",
        ": ²:0;cat /etc/shadow",  # not ASCII digits: not zsh extended format, a plain command
    ]
    result = parse_bytes(
        tmp_path, "shell_history", "\n".join(lines).encode(), "home/eve/.zsh_history"
    )
    assert result["counts"] == {"records_read": 5, "events_emitted": 3, "skipped": 0, "errors": 2}
    assert _events_by_line(result) == {"1", "4", "5"}
    reasons = {(s["location"], s["reason"]) for s in result["error_samples"]}
    assert reasons == {("line 2", "bad_zsh_record"), ("line 3", "bad_timestamp")}
    by_key = {e["source_record_id"]: e for e in result["events"]}
    assert by_key["4"]["cmdline"] == "id" and by_key["4"]["raw"]["elapsed_s"] == 3
    assert "time_inferred" in by_key["5"]["tags"]


def test_journal_hostile_numbers_cost_one_record(tmp_path: Path) -> None:
    ok = {"__REALTIME_TIMESTAMP": "1767347950000000", "SYSLOG_IDENTIFIER": "sshd"}
    records: list[dict[str, Any]] = [
        {**ok, "MESSAGE": "first", "_PID": "812"},
        {**ok, "__REALTIME_TIMESTAMP": "²", "MESSAGE": "superscript time"},
        {**ok, "__REALTIME_TIMESTAMP": "9" * 5000, "MESSAGE": "huge time"},
        {**ok, "MESSAGE": "odd pid", "_PID": "²"},
        {**ok, "MESSAGE": "huge pid", "_PID": "٣" * 5000},
        {  # the auth classifier's port field: 5000 Arabic-Indic digits match \d+
            **ok,
            "MESSAGE": "Accepted password for bob from 198.51.100.7 port " + "٣" * 5000 + " ssh2",
        },
        {**ok, "MESSAGE": "last"},
    ]
    data = "\n".join(json.dumps(r, ensure_ascii=False) for r in records).encode()
    result = parse_bytes(tmp_path, "journal_json", data, "journal.json")
    assert result["counts"] == {"records_read": 7, "events_emitted": 5, "skipped": 0, "errors": 2}
    assert _events_by_line(result) == {"1", "4", "5", "6", "7"}
    assert {s["reason"] for s in result["error_samples"]} == {"bad_timestamp"}
    by_key = {e["source_record_id"]: e for e in result["events"]}
    assert by_key["1"]["pid"] == 812
    assert by_key["4"]["pid"] is None and by_key["5"]["pid"] is None
    assert by_key["6"]["event_code"] == "ssh_accepted"
    assert by_key["6"]["src_port"] is None and by_key["6"]["user"] == "bob"


def test_linux_auth_hostile_port_costs_nothing(tmp_path: Path) -> None:
    lines = [
        "2026-01-02T10:00:00+00:00 web01 sshd[1]: Accepted password for bob from 198.51.100.7 "
        "port " + "٣" * 5000 + " ssh2",
        "<38>1 2026-01-02T10:00:01+00:00 web01 sshd ² - - Accepted password for amy from "
        "198.51.100.8 port 22 ssh2",
    ]
    result = parse_bytes(tmp_path, "linux_auth", "\n".join(lines).encode(), "auth.log")
    assert result["counts"]["events_emitted"] == 2 and result["counts"]["errors"] == 0
    assert [e["src_port"] for e in result["events"]] == [None, 22]
    assert [e["pid"] for e in result["events"]] == [1, None]


@FUZZ
@given(st.lists(st.tuples(HOSTILE_NUMBERS, HOSTILE_NUMBERS), min_size=1, max_size=6))
def test_shell_history_fuzz(tmp_path: Path, pairs: list[tuple[str, str]]) -> None:
    fixture = (BIN / ".zsh_history").read_text(encoding="utf-8").splitlines()
    lines = [f": {a}:{b};cmd{i}" for i, (a, b) in enumerate(pairs)] + [f"#{pairs[0][0]}"]
    for name in (".zsh_history", ".bash_history"):
        result = parse_bytes(tmp_path, "shell_history", "\n".join(lines + fixture).encode(), name)
        anchor = str(len(lines) + 1)  # the fixture's valid first line always parses
        assert anchor in _events_by_line(result)


@FUZZ
@given(HOSTILE_NUMBERS, HOSTILE_NUMBERS, HOSTILE_NUMBERS, st.text(max_size=60))
def test_journal_json_fuzz(tmp_path: Path, ts: str, pid: str, port: str, text: str) -> None:
    hostile = {
        "__REALTIME_TIMESTAMP": ts,
        "_PID": pid,
        "_UID": port,
        "SYSLOG_IDENTIFIER": "sshd",
        "MESSAGE": f"Accepted password for {text} from 198.51.100.7 port {port} ssh2",
    }
    lines = [json.dumps(hostile, ensure_ascii=False)]
    anchor = {**hostile, "__REALTIME_TIMESTAMP": "1767347950000000"}
    lines.append(json.dumps(anchor, ensure_ascii=False))
    lines += (BIN / "journal.json").read_text(encoding="utf-8").splitlines()
    result = parse_bytes(tmp_path, "journal_json", "\n".join(lines).encode(), "journal.json")
    assert {"2", "3"} <= _events_by_line(result)


# ---------------------------------------------------------------------- pcap record sizes


def test_pcap_oversized_caplen_is_refused_not_read(tmp_path: Path) -> None:
    from app.parsers.pcap import MAX_PACKET_BYTES

    capture = (BIN / "capture.pcap").read_bytes()
    first_len = struct.unpack_from("<I", capture, 24 + 8)[0]
    first = capture[: 24 + 16 + first_len]  # file header + the first packet
    huge = struct.pack("<IIII", 1767347900, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"\x00" * 64
    result = parse_bytes(tmp_path, "pcap", first + huge, "capture.pcap")
    assert result["assumptions"]["incomplete"] == "capture_truncated"
    assert {"location": "after packet 1", "reason": "capture_truncated"}.items() <= (
        result["error_samples"][0].items()
    )
    assert result["error_samples"][0]["detail"] == "RecordTooLargeError"
    assert result["assumptions"]["packets"] == 1
    # a packet of exactly the cap is still read
    edge = struct.pack("<IIII", 1767347900, 0, MAX_PACKET_BYTES, MAX_PACKET_BYTES)
    result = parse_bytes(
        tmp_path, "pcap", first + edge + b"\x00" * MAX_PACKET_BYTES, "capture.pcap"
    )
    assert result["assumptions"]["packets"] == 2 and "incomplete" not in result["assumptions"]


def test_pcapng_oversized_block_is_refused_not_read(tmp_path: Path) -> None:
    capture = (BIN / "capture.pcapng").read_bytes()
    shb_len = struct.unpack_from("<I", capture, 4)[0]
    idb_len = struct.unpack_from("<I", capture, shb_len + 4)[0]
    head = capture[: shb_len + idb_len]
    huge = struct.pack("<II", 6, 0xFFFFFFF0) + b"\x00" * 64  # enhanced packet block, 4 GiB
    result = parse_bytes(tmp_path, "pcap", head + huge, "capture.pcapng")
    assert result["assumptions"]["incomplete"] == "capture_truncated"
    assert result["error_samples"][0]["detail"] == "RecordTooLargeError"


def test_pe_header_library_errors_are_input_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pefile

    for exc in (struct.error("x"), ValueError("x"), IndexError("x"), AttributeError("x")):

        def boom(*args: Any, exc: Exception = exc, **kwargs: Any) -> Any:
            raise exc

        monkeypatch.setattr(pefile, "PE", boom)
        with pytest.raises(ParserInputError, match=type(exc).__name__):
            run("pe_static", context(BIN / "sample.exe"))


def test_lnk_library_failure_is_one_counted_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import LnkParse3

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise KeyError("broken extra block")

    monkeypatch.setattr(LnkParse3, "lnk_file", boom)
    result = run("lnk", context(BIN / "evil.lnk"))
    assert result["counts"]["errors"] == 1 and result["counts"]["events_emitted"] == 2
    assert result["error_samples"][0]["reason"] == "lnk_structure_unreadable"
    assert "lnk_structure_unreadable" not in result["warnings"]


@FUZZ
@given(st.lists(st.tuples(st.integers(100, 24_000), st.integers(0, 255)), min_size=1, max_size=20))
def test_browser_fuzz(tmp_path: Path, flips: list[tuple[int, int]]) -> None:
    data = mutate((BIN / "History").read_bytes(), flips, start=100)
    with contextlib.suppress(ParserInputError):
        parse_bytes(tmp_path, "browser", data, "History")


def test_prefetch_mam_size_bomb_refused(tmp_path: Path) -> None:
    bomb = b"MAM\x04" + struct.pack("<I", 1 << 30) + bytes(300)
    with pytest.raises(ParserInputError, match="16 MiB"):
        parse_bytes(tmp_path, "prefetch", bomb, "x.pf")
    with pytest.raises(ParserInputError, match="algorithm"):
        parse_bytes(tmp_path, "prefetch", b"MAM\x02" + bytes(12), "x.pf")


def test_sqlite_views_and_non_browser_dbs_are_refused(tmp_path: Path) -> None:
    db = tmp_path / "view.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE real_urls(id INTEGER, url TEXT);"
        "CREATE VIEW urls AS SELECT * FROM real_urls;"
        "CREATE VIEW visits AS SELECT 1 AS id;"
    )
    conn.close()
    with pytest.raises(ParserInputError, match="no browser history tables"):
        run("browser", context(db, source_file="History"))
    # the immutable read-only open created no journal/WAL files next to the evidence
    assert sorted(p.name for p in tmp_path.iterdir()) == ["view.sqlite"]


def test_structured_size_limit(tmp_path: Path) -> None:
    small = ParseLimits(max_structured_bytes=512)
    for fixture, parser in (
        ("History", "browser"),
        ("sample.exe", "pe_static"),
        ("SYSTEM", "registry_hive"),
    ):
        with pytest.raises(ParserInputError):
            run(parser, context(BIN / fixture, limits=small))


def test_record_cap_marks_the_run_incomplete() -> None:
    result = run("pcap", context(BIN / "capture.pcap", limits=ParseLimits(max_records=2)))
    assert result["assumptions"]["incomplete"] == "record_cap"


# ---------------------------------------------------------------------- YARA


def test_yara_rules_are_trusted_config_only(tmp_path: Path) -> None:
    extra = tmp_path / "rules"
    extra.mkdir()
    (extra / "inc.yar").write_text('include "../../secret.yar"\nrule x { condition: true }\n')
    with pytest.raises(ParserInputError, match="do not compile"):
        run(
            "yara_scan",
            context(BIN / "eicar_mimikatz.txt", tools=ToolConfig(yara_rules_dirs=(str(extra),))),
        )
    (extra / "inc.yar").write_text('rule Site_Rule { strings: $a = "gentilkiwi" condition: $a }\n')
    result = run(
        "yara_scan",
        context(BIN / "eicar_mimikatz.txt", tools=ToolConfig(yara_rules_dirs=(str(extra),))),
    )
    assert "Site_Rule" in {e["event_code"] for e in result["events"]}
    with pytest.raises(ParserInputError, match="not a directory"):
        run(
            "yara_scan",
            context(
                BIN / "eicar_mimikatz.txt",
                tools=ToolConfig(yara_rules_dirs=(str(tmp_path / "nope"),)),
            ),
        )


def test_yara_size_cap_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import yara

    from app.parsers import yara_scan

    with pytest.raises(ParserInputError, match="YARA_MAX_FILE_MB"):
        run("yara_scan", context(BIN / "sample.exe", tools=ToolConfig(yara_max_file_bytes=10)))

    class SlowRules:
        def match(self, *args: Any, **kwargs: Any) -> Any:
            assert kwargs["timeout"] == 7
            raise yara.TimeoutError("timeout")

    monkeypatch.setattr(yara_scan, "compile_rules", lambda dirs: (SlowRules(), {"rules": 1}))
    result = run("yara_scan", context(BIN / "sample.exe", tools=ToolConfig(yara_timeout_s=7)))
    assert result["assumptions"]["incomplete"] == "yara_timeout"
    assert result["counts"] == {"records_read": 1, "events_emitted": 0, "skipped": 0, "errors": 1}
