"""Parser sandbox protocol (Phase 10): lossless events, strict decoding of untrusted lines."""

from __future__ import annotations

import json
import math
import uuid
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from app.parsers.base import Event, ParseLimits, ParseStats, ToolConfig
from app.parsers.normalize import NormalizationError, clean_event, to_row
from app.parsers.registry import get_parser
from app.sandbox.protocol import (
    MAX_LINE_BYTES,
    ExitInfo,
    LimitsSpec,
    ProtocolError,
    SandboxRequest,
    ToolsSpec,
    decode_event,
    decode_progress,
    decode_result,
    encode_event,
    encode_progress,
    encode_result,
    merge_stats,
)
from tests.unit.deep_helpers import BIN, context, make_tool
from tests.unit.test_parsers_deep_golden import DEEP_CASES, TOOL_CASES
from tests.unit.test_parsers_golden import CASES, FIXTURES

IDS = {"case_id": "c", "evidence_id": "e", "job_id": "j", "parser_name": "p", "parser_version": "1"}


def _row(event: Event) -> tuple[dict[str, Any], int]:
    return to_row(event, **IDS)


def _round_trip(event: Event) -> Event:
    line = encode_event(event)
    assert line.startswith(b"E") and line.endswith(b"\n") and line.count(b"\n") == 1
    return decode_event(line.rstrip(b"\n"))


def _same_rows(events: list[Event]) -> int:
    for event in events:
        assert _row(_round_trip(event))[0] == _row(event)[0]
    return len(events)


# ------------------------------------------------------------------ equivalence with in-process


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), CASES)
def test_phase2_parsers_round_trip_without_loss(
    parser_name: str, fixture: str, golden: str, params: dict[str, Any]
) -> None:
    path = FIXTURES / fixture
    ctx = context(path, params=params)
    events = list(get_parser(parser_name).parse(ctx))
    assert _same_rows(events) > 0


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), DEEP_CASES)
def test_deep_parsers_round_trip_without_loss(
    parser_name: str, fixture: str, golden: str, params: dict[str, Any]
) -> None:
    ctx = context(BIN / fixture, params=params, source_file=f"evidence/{fixture}")
    events = list(get_parser(parser_name).parse(ctx))
    assert _same_rows(events) > 0


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), TOOL_CASES)
def test_tool_parsers_round_trip_without_loss(
    parser_name: str, fixture: str, golden: str, params: dict[str, Any], tmp_path: Path
) -> None:
    tools = tmp_path / "tools"
    for name in ("fls", "mmls", "vol", "zeek"):
        make_tool(tools, name)
    work = tmp_path / "work"
    work.mkdir()
    cfg = ToolConfig(search_path=str(tools), timeout_s=60)
    ctx = context(BIN / fixture, params=params, tools=cfg, work_dir=work)
    events = list(get_parser(parser_name).parse(ctx))
    assert _same_rows(events) > 0


def test_every_registered_parser_is_covered() -> None:
    from app.parsers.registry import all_parsers

    covered = {c[0] for c in CASES + DEEP_CASES + TOOL_CASES}
    assert covered == set(all_parsers())


def _hostile_event(**overrides: Any) -> Event:
    values: dict[str, Any] = {
        "ts": datetime(2026, 3, 1, 10, 0, 0, 123456, tzinfo=timezone(timedelta(hours=5.5))),
        "source_type": "x" * 100,
        "message": "nul\x00here \ud800 lone" + "m" * 40_000,
        "record_key": "offset:42",
        "host": "h" * 300,
        "user": None,
        "pid": 2**40,
        "ppid": True,
        "src_port": 70000,
        "dst_port": 443,
        "src_ip": "not-an-ip",
        "dst_ip": "2001:db8::1",
        "cmdline": "\x01\x02" * 10,
        "tags": ["a", None, 5, "t" * 300] + ["x"] * 100,
        "raw": {
            1: b"bytes",
            "nested": [[[[{"deep": {"er": list(range(5))}}]]]],
            "nan": math.nan,
            "inf": -math.inf,
            "big": 10**30,
            "when": datetime(2026, 1, 1, tzinfo=UTC),
            "set": {1, 2},
            "s": "\ud801" + "y" * 70_000,
        },
    }
    values.update(overrides)
    return Event(**values)


def test_hostile_values_round_trip_to_identical_rows() -> None:
    event = _hostile_event()
    assert _row(_round_trip(event))[0] == _row(event)[0]


def test_oversized_raw_is_summarised_identically() -> None:
    event = _hostile_event(raw={f"k{i}": "z" * 60_000 for i in range(12)})
    row, _ = _row(_round_trip(event))
    assert row["raw"]["_truncated"] is True
    assert row == _row(event)[0]
    assert len(encode_event(event)) < MAX_LINE_BYTES


def test_deep_raw_round_trips() -> None:
    deep: Any = "leaf"
    for _ in range(60):
        deep = [deep]
    event = _hostile_event(raw={"d": deep})
    assert _row(_round_trip(event))[0] == _row(event)[0]


def test_clean_event_is_idempotent() -> None:
    once = clean_event(_hostile_event())
    assert clean_event(once) == once


def test_naive_timestamp_still_fails_normalisation() -> None:
    event = _hostile_event(ts=datetime(2026, 1, 1, 0, 0))
    decoded = _round_trip(event)
    with pytest.raises(NormalizationError):
        _row(decoded)


def test_non_datetime_ts_is_refused_at_encoding() -> None:
    with pytest.raises(TypeError):
        encode_event(_hostile_event(ts="2026-01-01"))


# ------------------------------------------------------------------ strict decoding


def _event_body() -> dict[str, Any]:
    line = encode_event(_hostile_event(message="m", raw={}))
    body: dict[str, Any] = json.loads(line[1:])
    return body


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(extra=1),
        lambda b: b.pop("message"),
        lambda b: b.update(ts="yesterday"),
        lambda b: b.update(ts=12),
        lambda b: b.update(ts="2026-01-01T00:00:00+00:00" + "0" * 80),
        lambda b: b.update(host=5),
        lambda b: b.update(pid="12"),
        lambda b: b.update(pid=True),
        lambda b: b.update(tags="abc"),
        lambda b: b.update(tags=[1]),
        lambda b: b.update(tags=["t"] * 65),
    ],
)
def test_decode_rejects_malformed_events(mutate: Any) -> None:
    body = _event_body()
    mutate(body)
    with pytest.raises(ProtocolError):
        decode_event(b"E" + json.dumps(body).encode())


@pytest.mark.parametrize(
    "line",
    [
        b"",
        b"X{}",
        b"E",
        b"E{not json",
        b"E\xff\xfe",
        b"E[]",
        b"E" + b"[" * 100_000,
        b"E" + b'{"pid": 1' + b"9" * 5000 + b"}",
        b"E" + b"x" * (MAX_LINE_BYTES + 1),
    ],
    ids=["empty", "kind", "bare", "json", "utf8", "list", "deep", "bigint", "long"],
)
def test_decode_rejects_garbage(line: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode_event(line)


# ------------------------------------------------------------------ result, progress, exit


def _stats() -> ParseStats:
    stats = ParseStats(records_read=10, skipped=1, errors=2, bytes_read=999)
    stats.warn("checksum", location="offset:1", detail="bad")
    stats.error("line:3", "too_long", "x" * 50)
    stats.assumptions["incomplete"] = "record_cap"
    return stats


def test_result_round_trip_and_merge() -> None:
    line = encode_result("ok", _stats(), 7)
    result = decode_result(line.rstrip(b"\n"))
    assert result.status == "ok" and result.yielded == 7
    assert result.stats.records_read == 10 and result.stats.errors == 3
    assert result.stats.warnings["checksum"] == 1
    worker = ParseStats(events_emitted=7)
    worker.error("sandbox:line:9", "sandbox_bad_output")
    merge_stats(worker, result.stats)
    assert worker.records_read == 10 and worker.errors == 4 and worker.events_emitted == 7
    assert worker.assumptions == {"incomplete": "record_cap"}
    assert worker.error_samples[0]["reason"] == "sandbox_bad_output"


def test_result_carries_only_safe_error_types_and_bounded_messages() -> None:
    line = encode_result("crash", ParseStats(), 0, error_type="evil type; rm -rf")
    assert decode_result(line.rstrip(b"\n")).error_type is None
    line = encode_result("input_error", ParseStats(), 0, message="m" * 10_000)
    message = decode_result(line.rstrip(b"\n")).message
    assert message is not None and len(message) < 2100


def test_huge_samples_are_dropped_but_counts_kept() -> None:
    stats = _stats()
    stats.assumptions["blob"] = ["v" * 60_000 for _ in range(30)]
    line = encode_result("ok", stats, 7)
    assert len(line) <= 1024 * 1024
    result = decode_result(line.rstrip(b"\n"))
    assert result.stats.records_read == 10
    assert result.stats.assumptions["incomplete"] == "record_cap"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(status="fine"),
        lambda b: b.update(records_read=-1),
        lambda b: b.update(records_read=True),
        lambda b: b.update(records_read=2**63),
        lambda b: b.update(warnings={"a": "1"}),
        lambda b: b.update(warnings={str(i): 1 for i in range(1001)}),
        lambda b: b.update(error_samples=[{}] * 51),
        lambda b: b.update(error_samples=["x"]),
        lambda b: b.update(assumptions=[]),
        lambda b: b.update(error_type="a b"),
        lambda b: b.pop("yielded"),
    ],
)
def test_decode_rejects_malformed_results(mutate: Any) -> None:
    body = json.loads(encode_result("ok", _stats(), 1)[1:])
    mutate(body)
    with pytest.raises(ProtocolError):
        decode_result(b"R" + json.dumps(body).encode())


def test_progress_encoding() -> None:
    assert decode_progress(encode_progress(0.5)) == 0.5
    assert decode_progress(encode_progress(7.0)) == 1.0
    for bad in (b"P", b"Pnan", b"P-1", b"P2", b"P0.5x", b"P" + b"0" * 40):
        assert decode_progress(bad) is None


def test_exit_record_round_trip_and_validation() -> None:
    info = ExitInfo("ok", 0, 12, 100, 3, "a" * 64, True)
    assert ExitInfo.decode(info.encode()) == info
    body = json.loads(info.encode())
    for key, value in (("reason", "won"), ("sha256", "zz"), ("returncode", "0"), ("v", 2)):
        bad = dict(body, **{key: value})
        with pytest.raises(ProtocolError):
            ExitInfo.decode(json.dumps(bad).encode())
    with pytest.raises(ProtocolError):
        ExitInfo.decode(b"{" + b" " * 20_000 + b"}")


def test_request_round_trip_and_validation() -> None:
    request = SandboxRequest(
        job_id=uuid.uuid4(),
        parser="linux_auth",
        evidence_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        source_file="auth.log",
        reference_time=datetime(2026, 1, 1, tzinfo=UTC),
        params={"timezone": "UTC"},
        limits=LimitsSpec.of(ParseLimits()),
        tools=ToolsSpec.of(ToolConfig(yara_rules_dirs=("/rules",))),
        timeout_s=60,
        max_output_bytes=1024,
    )
    again = SandboxRequest.decode(request.encode())
    assert again == request
    assert again.limits.to_limits() == ParseLimits()
    assert again.tools.to_tools().yara_rules_dirs == ("/rules",)
    body = json.loads(request.encode())
    for key, value in (("parser", "../x"), ("extra", 1), ("timeout_s", 0)):
        with pytest.raises(ProtocolError):
            SandboxRequest.decode(json.dumps(dict(body, **{key: value})).encode())
    body["reference_time"] = "2026-01-01T00:00:00"
    with pytest.raises(ProtocolError):
        SandboxRequest.decode(json.dumps(body).encode())
    with pytest.raises(ProtocolError):
        SandboxRequest.decode(b" " * (300 * 1024))
