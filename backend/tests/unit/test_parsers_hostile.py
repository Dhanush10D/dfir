"""Parsers against malformed and hostile input: every record is accounted for, nothing crashes,
memory stays bounded (line/decompression limits), timestamps are UTC with the original kept."""

from __future__ import annotations

import contextlib
import gzip
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from app.parsers.base import Event, ParseContext, ParseLimits, ParserInputError, ParseStats
from app.parsers.registry import detect, get_parser
from app.parsers.textio import iter_lines

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EVTX_SAMPLE = (FIXTURES / "evtx" / "security_short_selected.evtx").read_bytes()
REF = datetime(2026, 1, 3, tzinfo=UTC)


def parse(
    tmp_path: Path, parser: str, data: bytes, name: str = "input", **ctx_kw: object
) -> tuple[list[Event], ParseStats]:
    path = tmp_path / name
    path.write_bytes(data)
    ctx_kw.setdefault("reference_time", REF)
    ctx = ParseContext(path=path, evidence_id="e", case_id="c", source_file=name, **ctx_kw)  # type: ignore[arg-type]
    events = list(get_parser(parser).parse(ctx))
    ctx.stats.events_emitted = len(events)
    assert ctx.stats.balanced, ctx.stats.counts()
    for event in events:
        assert event.ts.tzinfo is not None and event.ts.utcoffset() is not None
        assert event.ts_original
    return events, ctx.stats


# ------------------------------------------------------------------------------ detection


def test_detection() -> None:
    assert detect(EVTX_SAMPLE[:8192], "x.bin")[0][0] == "evtx"
    auth = (FIXTURES / "linux" / "auth.log").read_bytes()
    assert detect(auth, "auth.log")[0][0] == "linux_auth"
    assert detect(gzip.compress(auth), "auth.log.1.gz")[0][0] == "linux_auth"
    assert detect(b"\x00\x01\x02 random binary" * 100, "blob") == []
    assert detect(b"hello\nworld\n", "notes.txt") == []


# ------------------------------------------------------------------------------ linux_auth


def test_gzip_input_matches_plain(tmp_path: Path) -> None:
    data = (FIXTURES / "linux" / "auth.log").read_bytes()
    plain, _ = parse(tmp_path, "linux_auth", data, "auth.log")
    zipped, stats = parse(tmp_path, "linux_auth", gzip.compress(data), "auth.log.gz")
    assert [(e.ts, e.message, e.record_key) for e in plain] == [
        (e.ts, e.message, e.record_key) for e in zipped
    ]
    assert stats.assumptions["compression"] == "gzip"


def test_overlong_lines_are_counted_not_buffered(tmp_path: Path) -> None:
    line = b"Jan  2 09:12:44 web01 sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2\n"
    data = line + b"A" * 300_000 + b"\n" + line + b"B" * 300_000  # last one without newline
    limits = ParseLimits(max_line_bytes=1024)
    events, stats = parse(tmp_path, "linux_auth", data, limits=limits)
    assert len(events) == 2 and stats.errors == 2
    assert [s["reason"] for s in stats.error_samples] == ["line_too_long", "line_too_long"]
    assert [e.record_key for e in events] == ["line:1", "line:3"]


def test_gzip_bomb_is_stopped(tmp_path: Path) -> None:
    bomb = gzip.compress(b"\n" * (40 * 1024 * 1024))  # 40 MiB of newlines, ~40 KiB compressed
    limits = ParseLimits(max_decompression_ratio=50, ratio_check_after_bytes=1024 * 1024)
    _, stats = parse(tmp_path, "linux_auth", bomb, limits=limits)
    assert stats.assumptions["incomplete"] == "decompression_limit"
    assert stats.bytes_read < 3 * 1024 * 1024
    limits = ParseLimits(max_decompressed_bytes=2 * 1024 * 1024)
    _, stats = parse(tmp_path, "linux_auth", bomb, limits=limits)
    assert stats.assumptions["incomplete"] == "decompression_limit"


def test_truncated_gzip_is_partial(tmp_path: Path) -> None:
    data = gzip.compress((FIXTURES / "linux" / "auth.log").read_bytes())
    events, stats = parse(tmp_path, "linux_auth", data[: len(data) // 2])
    assert stats.assumptions["incomplete"] == "decompression_error"
    assert len(events) < 22


def test_timezone_dst_and_year_rollover(tmp_path: Path) -> None:
    data = (
        b"Dec 31 23:59:59 h sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2\n"
        b"Jan  1 00:00:01 h sshd[1]: Accepted password for a from 192.0.2.1 port 2 ssh2\n"
        b"Mar 29 02:30:00 h cron[2]: non-existent wall time in Berlin\n"
        b"Oct 25 02:30:00 h cron[2]: ambiguous wall time in Berlin\n"
    )
    events, stats = parse(tmp_path, "linux_auth", data, timezone="Europe/Berlin", year=2025)
    assert events[0].ts == datetime(2025, 12, 31, 22, 59, 59, tzinfo=UTC)
    assert events[1].ts == datetime(2025, 12, 31, 23, 0, 1, tzinfo=UTC)  # 2026-01-01 local
    assert events[0].ts_original == "Dec 31 23:59:59"
    assert stats.assumptions["year_rollovers"] == 1
    assert stats.warnings["ambiguous_local_time"] == 1
    assert stats.warnings["nonexistent_local_time"] == 1


def test_year_inference_needs_a_reference(tmp_path: Path) -> None:
    data = b"Jan  2 09:12:44 web01 sshd[1]: hello\n2026-01-02T09:00:00Z web01 app: iso line\n"
    events, stats = parse(tmp_path, "linux_auth", data, reference_time=None)
    assert len(events) == 1 and stats.errors == 1  # the ISO line needs no year
    assert stats.error_samples[0]["reason"] == "bad_timestamp"


def test_bad_values_never_crash(tmp_path: Path) -> None:
    data = (
        b"Feb 30 10:00:00 h app: impossible date\n"
        b"Jan  2 25:61:61 h app: impossible time\n"
        b"2026-13-40T99:00:00Z h app: bad iso\n"
        b"<999>1 - h app - - - no timestamp\n"
        b"Jan  2 09:12:44 h sshd[99999999999999]: Accepted password for x from 999.1.1.1 port "
        b"99999 ssh2\n"
        b"Jan  2 09:12:44 h app: nul \x00 byte and bad utf8 \xff\xfe\n"
    )
    events, stats = parse(tmp_path, "linux_auth", data, year=2026)
    assert stats.errors == 4
    assert len(events) == 2
    weird = events[0]
    assert weird.pid is None and weird.src_ip is None and weird.src_port is None
    assert stats.warnings["invalid_utf8_replaced"] == 1


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(st.binary(max_size=4096))
def test_linux_auth_fuzz(tmp_path: Path, data: bytes) -> None:
    parse(tmp_path, "linux_auth", data, year=2026, limits=ParseLimits(max_line_bytes=256))


def test_iter_lines_offsets(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_bytes(b"a\r\nbb\n\nccc")
    stats = ParseStats()
    lines = list(iter_lines(path, ParseLimits(), stats, lambda _: None))
    assert [(ln.number, ln.offset, ln.data) for ln in lines] == [
        (1, 0, b"a"),
        (2, 3, b"bb"),
        (3, 6, b""),
        (4, 7, b"ccc"),
    ]


# ------------------------------------------------------------------------------ evtx


def _record_offsets() -> list[int]:
    from Evtx.Evtx import Evtx

    path = FIXTURES / "evtx" / "security_short_selected.evtx"
    with Evtx(str(path)) as log:
        return [int(r.offset()) for c in log.chunks() for r in c.records()]


def test_evtx_corrupt_record_body_is_one_error(tmp_path: Path) -> None:
    off = _record_offsets()[2]
    data = bytearray(EVTX_SAMPLE)
    data[off + 0x18 + 10 : off + 0x18 + 40] = b"\xff" * 30
    events, stats = parse(tmp_path, "evtx", bytes(data))
    assert len(events) == 6 and stats.errors == 1
    assert stats.warnings["chunk_checksum_mismatch"] == 1


def test_evtx_corrupt_record_header_counts_unreachable_records(tmp_path: Path) -> None:
    off = _record_offsets()[3]
    data = bytearray(EVTX_SAMPLE)
    data[off + 4 : off + 8] = (0x7FFFFFFF).to_bytes(4, "little")  # absurd record size
    events, stats = parse(tmp_path, "evtx", bytes(data))
    assert len(events) == 3 and stats.errors == 4
    assert stats.error_samples[0]["reason"] == "records_unreachable"
    assert stats.assumptions["incomplete"] == "records_unreachable"


def test_evtx_truncated_file(tmp_path: Path) -> None:
    events, stats = parse(tmp_path, "evtx", EVTX_SAMPLE[:5000])
    assert events == [] and stats.errors == 1
    assert stats.assumptions["incomplete"] == "chunk_missing"
    with pytest.raises(ParserInputError):
        parse(tmp_path, "evtx", b"ElfFile\x00" + b"\x00" * 100)
    with pytest.raises(ParserInputError):
        parse(tmp_path, "evtx", b"not an evtx file at all" * 300)


def test_evtx_xml_uses_defusedxml() -> None:
    from defusedxml import DTDForbidden

    from app.parsers.evtx import _record_xml

    bomb = '<!DOCTYPE x [<!ENTITY a "aaaa">]><Event>&a;</Event>'
    with pytest.raises(DTDForbidden):
        _record_xml(bomb, ParseStats(), "t")


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    st.lists(st.tuples(st.integers(4096, len(EVTX_SAMPLE) - 1), st.integers(0, 255)), max_size=40)
)
def test_evtx_fuzz_mutations(tmp_path: Path, flips: list[tuple[int, int]]) -> None:
    data = bytearray(EVTX_SAMPLE)
    for offset, value in flips:
        data[offset] = value
    with contextlib.suppress(ParserInputError):
        parse(tmp_path, "evtx", bytes(data))


def test_textio_head_text_bounds() -> None:
    from app.parsers.textio import head_text

    assert head_text(gzip.compress(b"x" * 100_000))[:5] == b"xxxxx"
    assert len(head_text(gzip.compress(b"x" * 100_000))) <= 8192
    assert head_text(b"\x1f\x8bgarbage") == b""


def test_linux_auth_unwraps_rsyslog_repeated_messages(tmp_path: Path) -> None:
    data = (
        b"Jan  2 10:00:00 web01 sshd[100]: message repeated 5 times: "
        b"[ Failed password for root from 203.0.113.9 port 5555 ssh2]\n"
    )
    (event,), _ = parse(tmp_path, "linux_auth", data, "auth.log")
    assert event.event_code == "ssh_failed" and event.src_ip == "203.0.113.9"
    assert event.raw["repeated"] == 5
