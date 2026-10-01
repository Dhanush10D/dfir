"""Files and line format shared by the worker, the sandbox server and the parser child (pure).

Spool layout (one job at a time, see ``client.SandboxSlot``)::

    <in>/<job dir>/evidence.bin   worker: verified copy of the original (0400)
    <in>/<job dir>/request.json   worker: SandboxRequest
    <in>/<job dir>/ready          worker: written last; the server only picks up ready jobs
    <in>/<job dir>/cancel         worker: ask the server to stop the child
    <out>/<job dir>/              server: created when the job starts (the claim)
    <out>/<job dir>/events.jsonl  server: the child's E/R lines, capped
    <out>/<job dir>/progress      server: last progress fraction
    <out>/<job dir>/exit.json     server: written after the child and all its descendants are gone

The ``in`` volume is read-only inside the sandbox. Child stdout lines:

* ``E{json}``: one event, already cleaned by ``normalize.clean_event`` (idempotent), so the
  worker's ``to_row`` stores exactly what in-process parsing would store;
* ``P0.1234``: progress (0..1), at most a few per second;
* ``R{json}``: the final result (status and parse statistics); must be the last line.

Everything the worker reads back is untrusted: ``decode_event`` / ``decode_result`` /
``ExitInfo.decode`` check sizes, keys and types and raise ``ProtocolError``.
"""

from __future__ import annotations

import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.parsers.base import MAX_SAMPLES, Event, ParseLimits, ParseStats, ToolConfig
from app.parsers.normalize import MAX_TAGS, clean_event, clean_json, clean_text

VERSION = 1
REQUEST_FILE = "request.json"
EVIDENCE_FILE = "evidence.bin"
READY_FILE = "ready"
CANCEL_FILE = "cancel"
EVENTS_FILE = "events.jsonl"
PROGRESS_FILE = "progress"
EXIT_FILE = "exit.json"

MAX_REQUEST_BYTES = 256 * 1024
MAX_EXIT_BYTES = 16 * 1024
MAX_PROGRESS_BYTES = 32
MAX_LINE_BYTES = 4 * 1024 * 1024  # an event line: cleaned fields + raw (<= 512 KiB) fit easily
MAX_RESULT_BYTES = 1024 * 1024
MAX_MESSAGE_CHARS = 2000
MAX_WARNING_CODES = 1000
MAX_INT = 2**62

JOB_DIR = re.compile(r"^job-[0-9a-f]{32}$")
_ERROR_TYPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$")

ExitReason = Literal[
    "ok",  # the child wrote its result and exited 0
    "timeout",  # wall clock (SANDBOX_MAX_RUN_S / request timeout) reached
    "cancelled",  # the worker wrote the cancel marker
    "output_limit",  # events.jsonl would exceed the output cap
    "protocol",  # a malformed or oversized line, or a line after the result
    "killed",  # ended by a signal (memory/CPU limit, OOM killer)
    "child_error",  # exited without a result
    "bad_request",  # request.json unreadable or invalid
    "failed_start",  # the child could not be started
]
EXIT_REASONS: frozenset[str] = frozenset(get_args(ExitReason))
ResultStatus = Literal["ok", "input_error", "crash"]


class ProtocolError(ValueError):
    """Untrusted sandbox data did not match the protocol."""


# ---------------------------------------------------------------------------------------------
# request (worker -> sandbox)
# ---------------------------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LimitsSpec(_Strict):
    max_line_bytes: int = Field(ge=1)
    max_decompressed_bytes: int = Field(ge=1)
    max_decompression_ratio: int = Field(ge=1)
    ratio_check_after_bytes: int = Field(ge=1)
    max_structured_bytes: int = Field(ge=1)
    max_records: int = Field(ge=1)
    max_depth: int = Field(ge=1)

    @classmethod
    def of(cls, limits: ParseLimits) -> LimitsSpec:
        return cls(**{f.name: getattr(limits, f.name) for f in fields(ParseLimits)})

    def to_limits(self) -> ParseLimits:
        return ParseLimits(**self.model_dump())


class ToolsSpec(_Strict):
    search_path: str | None = Field(default=None, max_length=4096)
    timeout_s: int = Field(ge=1)
    max_output_bytes: int = Field(ge=1)
    yara_rules_dirs: tuple[str, ...] = Field(default=(), max_length=16)
    yara_timeout_s: int = Field(ge=1)
    yara_max_file_bytes: int = Field(ge=1)
    volatility_symbols_dir: str | None = Field(default=None, max_length=4096)
    sqlite_timeout_s: int = Field(ge=1)

    @classmethod
    def of(cls, tools: ToolConfig) -> ToolsSpec:
        return cls(**{f.name: getattr(tools, f.name) for f in fields(ToolConfig)})

    def to_tools(self) -> ToolConfig:
        return ToolConfig(**self.model_dump())


class SandboxRequest(_Strict):
    """What the child needs to build a ``ParseContext``. Written by the (trusted) worker."""

    v: Literal[1] = 1
    job_id: uuid.UUID
    parser: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    evidence_id: uuid.UUID
    case_id: uuid.UUID
    source_file: str = Field(max_length=1024)
    host_hint: str | None = Field(default=None, max_length=1024)
    timezone: str = Field(default="UTC", max_length=64)
    year: int | None = Field(default=None, ge=1, le=9999)
    reference_time: datetime | None = None
    reference_source: str = Field(default="none", max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    limits: LimitsSpec
    tools: ToolsSpec
    timeout_s: int = Field(ge=1)
    max_output_bytes: int = Field(ge=1)

    @field_validator("reference_time")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("reference_time must be timezone-aware")
        return value

    def encode(self) -> bytes:
        return self.model_dump_json().encode("utf-8")

    @classmethod
    def decode(cls, data: bytes) -> SandboxRequest:
        if len(data) > MAX_REQUEST_BYTES:
            raise ProtocolError("request too large")
        try:
            return cls.model_validate_json(data)
        except (ValidationError, ValueError) as exc:
            raise ProtocolError(f"invalid request: {type(exc).__name__}") from exc


# ---------------------------------------------------------------------------------------------
# events (child -> worker, untrusted)
# ---------------------------------------------------------------------------------------------

_INT_FIELDS = ("pid", "ppid", "src_port", "dst_port")
_STR_FIELDS = tuple(
    f.name for f in fields(Event) if f.name not in {"ts", "tags", "raw", *_INT_FIELDS}
)
_EVENT_KEYS = frozenset({"ts", "tags", "raw", *_INT_FIELDS, *_STR_FIELDS})


def _loads(payload: bytes) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ProtocolError(f"not JSON: {type(exc).__name__}") from exc


def _dumps(body: Any) -> bytes:
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def encode_event(event: Event) -> bytes:
    """One ``E`` line. ``record_key``/``source_file`` stay as the parser set them (event id)."""
    if not isinstance(event.ts, datetime):
        raise TypeError("event ts is not a datetime")
    clean = clean_event(event)
    body: dict[str, Any] = {"ts": event.ts.isoformat()}
    for name in _STR_FIELDS:
        value = getattr(clean, name)
        body[name] = value if value is None or isinstance(value, str) else str(value)
    for name in _INT_FIELDS:
        body[name] = getattr(clean, name)
    body["tags"] = clean.tags
    body["raw"] = clean.raw
    return b"E" + _dumps(body) + b"\n"


def decode_event(line: bytes) -> Event:
    if len(line) > MAX_LINE_BYTES or not line.startswith(b"E"):
        raise ProtocolError("not an event line")
    body = _loads(line[1:])
    if not isinstance(body, dict) or set(body) != _EVENT_KEYS:
        raise ProtocolError("event keys differ from the protocol")
    ts_text = body["ts"]
    if not isinstance(ts_text, str) or len(ts_text) > 64:
        raise ProtocolError("bad ts")
    try:
        ts = datetime.fromisoformat(ts_text)
    except ValueError as exc:
        raise ProtocolError("bad ts") from exc
    values: dict[str, Any] = {}
    for name in _STR_FIELDS:
        value = body[name]
        if value is not None and not isinstance(value, str):
            raise ProtocolError(f"bad {name}")
        values[name] = value
    for name in _INT_FIELDS:
        value = body[name]
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise ProtocolError(f"bad {name}")
        values[name] = value
    tags = body["tags"]
    if (
        not isinstance(tags, list)
        or len(tags) > MAX_TAGS
        or not all(isinstance(t, str) for t in tags)
    ):
        raise ProtocolError("bad tags")
    return Event(ts=ts, tags=list(tags), raw=body["raw"], **values)


# ---------------------------------------------------------------------------------------------
# result (child -> worker, untrusted)
# ---------------------------------------------------------------------------------------------


@dataclass
class ChildResult:
    status: ResultStatus
    message: str | None
    error_type: str | None
    yielded: int
    stats: ParseStats


def _result_body(
    status: ResultStatus,
    stats: ParseStats,
    yielded: int,
    message: str | None,
    error_type: str | None,
    *,
    samples: bool = True,
) -> dict[str, Any]:
    warnings = dict(sorted(stats.warnings.items())[:MAX_WARNING_CODES])
    return {
        "status": status,
        "message": clean_text(message, MAX_MESSAGE_CHARS) if message else None,
        "error_type": error_type if error_type and _ERROR_TYPE.fullmatch(error_type) else None,
        "yielded": yielded,
        "records_read": stats.records_read,
        "skipped": stats.skipped,
        "errors": stats.errors,
        "bytes_read": stats.bytes_read,
        "warnings": {str(clean_text(str(k), 256)): int(v) for k, v in warnings.items()},
        "error_samples": clean_json(stats.error_samples[:MAX_SAMPLES]) if samples else [],
        "warning_samples": clean_json(stats.warning_samples[:MAX_SAMPLES]) if samples else [],
        "assumptions": clean_json(stats.assumptions),
    }


def encode_result(
    status: ResultStatus,
    stats: ParseStats,
    yielded: int,
    *,
    message: str | None = None,
    error_type: str | None = None,
) -> bytes:
    body = _result_body(status, stats, yielded, message, error_type)
    data = _dumps(body)
    if len(data) + 2 > MAX_RESULT_BYTES:  # oversized samples/assumptions: keep the counts
        body = _result_body(status, stats, yielded, message, error_type, samples=False)
        incomplete = stats.assumptions.get("incomplete")
        body["assumptions"] = {"incomplete": clean_json(incomplete)} if incomplete else {}
        body["assumptions"]["_truncated"] = True
        data = _dumps(body)
    return b"R" + data + b"\n"


def _count(body: dict[str, Any], name: str) -> int:
    value = body[name]
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_INT:
        raise ProtocolError(f"bad {name}")
    return value


def _samples(body: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = body[name]
    if not isinstance(value, list) or len(value) > MAX_SAMPLES:
        raise ProtocolError(f"bad {name}")
    out: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or len(item) > 16:
            raise ProtocolError(f"bad {name}")
        out.append(clean_json(item))
    return out


_RESULT_KEYS = frozenset(
    {
        "status",
        "message",
        "error_type",
        "yielded",
        "records_read",
        "skipped",
        "errors",
        "bytes_read",
        "warnings",
        "error_samples",
        "warning_samples",
        "assumptions",
    }
)


def decode_result(line: bytes) -> ChildResult:
    if len(line) > MAX_RESULT_BYTES or not line.startswith(b"R"):
        raise ProtocolError("not a result line")
    body = _loads(line[1:])
    if not isinstance(body, dict) or set(body) != _RESULT_KEYS:
        raise ProtocolError("result keys differ from the protocol")
    status = body["status"]
    if status not in ("ok", "input_error", "crash"):
        raise ProtocolError("bad status")
    message = body["message"]
    if message is not None and (not isinstance(message, str) or len(message) > 4 * 1024):
        raise ProtocolError("bad message")
    error_type = body["error_type"]
    if error_type is not None and (
        not isinstance(error_type, str) or not _ERROR_TYPE.fullmatch(error_type)
    ):
        raise ProtocolError("bad error_type")
    warnings = body["warnings"]
    if not isinstance(warnings, dict) or len(warnings) > MAX_WARNING_CODES:
        raise ProtocolError("bad warnings")
    counter: Counter[str] = Counter()
    for code, n in warnings.items():
        if (
            len(code) > 300
            or isinstance(n, bool)
            or not isinstance(n, int)
            or not 0 <= n <= MAX_INT
        ):
            raise ProtocolError("bad warnings")
        counter[code] = n
    assumptions = body["assumptions"]
    if not isinstance(assumptions, dict):
        raise ProtocolError("bad assumptions")
    stats = ParseStats(
        records_read=_count(body, "records_read"),
        events_emitted=0,
        skipped=_count(body, "skipped"),
        errors=_count(body, "errors"),
        warnings=counter,
        error_samples=_samples(body, "error_samples"),
        warning_samples=_samples(body, "warning_samples"),
        assumptions=clean_json(assumptions),
        bytes_read=_count(body, "bytes_read"),
    )
    return ChildResult(
        status=status,
        message=clean_text(message, MAX_MESSAGE_CHARS) if message else None,
        error_type=error_type,
        yielded=_count(body, "yielded"),
        stats=stats,
    )


def merge_stats(into: ParseStats, child: ParseStats) -> None:
    """Add the child's parser statistics to the worker's (which counts emitted events itself)."""
    into.records_read += child.records_read
    into.skipped += child.skipped
    into.errors += child.errors
    into.bytes_read += child.bytes_read
    into.warnings.update(child.warnings)
    room = MAX_SAMPLES - len(into.error_samples)
    into.error_samples.extend(child.error_samples[: max(room, 0)])
    room = MAX_SAMPLES - len(into.warning_samples)
    into.warning_samples.extend(child.warning_samples[: max(room, 0)])
    into.assumptions.update(child.assumptions)


# ---------------------------------------------------------------------------------------------
# progress and exit record (server -> worker)
# ---------------------------------------------------------------------------------------------


def encode_progress(fraction: float) -> bytes:
    return b"P" + f"{min(max(fraction, 0.0), 1.0):.4f}".encode("ascii") + b"\n"


def decode_progress(data: bytes) -> float | None:
    """A fraction from a ``P`` line payload or the progress file; None when malformed."""
    text = data.strip()
    if text.startswith(b"P"):
        text = text[1:]
    if not 0 < len(text) <= 16 or not re.fullmatch(rb"[01](\.[0-9]{1,10})?", text):
        return None
    value = float(text)
    return value if 0.0 <= value <= 1.0 else None


@dataclass(frozen=True)
class ExitInfo:
    """Written by the server once the child and every process it started are gone."""

    reason: str
    returncode: int | None
    duration_ms: int
    output_bytes: int
    lines: int
    sha256: str
    result_seen: bool

    def encode(self) -> bytes:
        return _dumps(
            {
                "v": VERSION,
                "reason": self.reason,
                "returncode": self.returncode,
                "duration_ms": self.duration_ms,
                "bytes": self.output_bytes,
                "lines": self.lines,
                "sha256": self.sha256,
                "result_seen": self.result_seen,
            }
        )

    @classmethod
    def decode(cls, data: bytes) -> ExitInfo:
        if len(data) > MAX_EXIT_BYTES:
            raise ProtocolError("exit record too large")
        body = _loads(data)
        keys = {"v", "reason", "returncode", "duration_ms", "bytes", "lines", "sha256"}
        if not isinstance(body, dict) or set(body) != keys | {"result_seen"}:
            raise ProtocolError("exit record keys differ from the protocol")
        if body["v"] != VERSION or body["reason"] not in EXIT_REASONS:
            raise ProtocolError("bad exit record")
        code = body["returncode"]
        if code is not None and (isinstance(code, bool) or not isinstance(code, int)):
            raise ProtocolError("bad returncode")
        sha = body["sha256"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ProtocolError("bad sha256")
        if not isinstance(body["result_seen"], bool):
            raise ProtocolError("bad result_seen")
        return cls(
            reason=str(body["reason"]),
            returncode=code,
            duration_ms=_count(body, "duration_ms"),
            output_bytes=_count(body, "bytes"),
            lines=_count(body, "lines"),
            sha256=sha,
            result_seen=body["result_seen"],
        )

    def summary(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "returncode": self.returncode,
            "duration_ms": self.duration_ms,
            "output_bytes": self.output_bytes,
            "lines": self.lines,
            "output_sha256": self.sha256,
        }
