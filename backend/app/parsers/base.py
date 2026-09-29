"""Parser plugin interface (guide 10.2).

Rules every parser follows (and the tests enforce):

1. Pure and streaming: yield events one by one; never read a whole file into memory.
2. No network, no database, no writes: the input path is a read-only copy in the job's scratch dir.
3. Never raise on a single bad record: count it in ``ctx.stats`` (``error``/``skip``) and continue.
   ``records_read == events_emitted + skipped + errors`` always holds at the end of a run.
4. Every timestamp is timezone-aware UTC; the string as found goes to ``ts_original``.
5. Every event carries a ``record_key`` that is stable for the same input bytes (a file offset or a
   line number), so ids are deterministic and reprocessing is idempotent.
6. Evidence content is hostile: bound line lengths and decompression, never use content in paths,
   never log it (warnings carry locations and ``repr``-escaped, truncated snippets only).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

MAX_SAMPLES = 50  # error/warning samples kept for the run manifest
SNIPPET_CHARS = 120


class ParserInputError(Exception):
    """The input as a whole is unusable (wrong format, unreadable header): a permanent failure."""


def snippet(value: bytes | str) -> str:
    """Safe, bounded representation of hostile content for manifests (escapes control chars)."""
    text = value[:SNIPPET_CHARS] if isinstance(value, bytes | str) else ""
    rendered = repr(text)
    return rendered + ("..." if len(value) > SNIPPET_CHARS else "")


@dataclass
class Event:
    """One normalized event (Appendix A). ``ts`` MUST be timezone-aware."""

    ts: datetime
    source_type: str
    message: str
    record_key: str  # stable per input record, e.g. "offset:4608" or "line:17"
    host: str | None = None
    user: str | None = None
    event_code: str | None = None
    event_category: str | None = None
    action: str | None = None
    outcome: str | None = None
    process_name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    cmdline: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    registry_key: str | None = None
    source_file: str | None = None
    source_record_id: str | None = None
    ts_original: str | None = None
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseStats:
    """Counters every parser maintains; the runner adds ``events_emitted``."""

    records_read: int = 0
    events_emitted: int = 0
    skipped: int = 0
    errors: int = 0
    warnings: Counter[str] = field(default_factory=Counter)
    error_samples: list[dict[str, Any]] = field(default_factory=list)
    warning_samples: list[dict[str, Any]] = field(default_factory=list)
    assumptions: dict[str, Any] = field(default_factory=dict)
    bytes_read: int = 0

    def read(self, n: int = 1) -> None:
        self.records_read += n

    def error(self, location: str, reason: str, detail: str | None = None, n: int = 1) -> None:
        """``n`` records at ``location`` could not be turned into events."""
        self.errors += n
        if len(self.error_samples) < MAX_SAMPLES:
            sample: dict[str, Any] = {"location": location, "reason": reason}
            if n != 1:
                sample["records"] = n
            if detail is not None:
                sample["detail"] = detail
            self.error_samples.append(sample)

    def skip(self, location: str, reason: str) -> None:
        """A record that is deliberately not an event (e.g. a blank line)."""
        self.skipped += 1
        self.warnings[f"skipped:{reason}"] += 1
        if len(self.warning_samples) < MAX_SAMPLES:
            self.warning_samples.append({"location": location, "code": f"skipped:{reason}"})

    def warn(self, code: str, location: str | None = None, detail: str | None = None) -> None:
        """Something noteworthy that did not cost a record (checksum mismatch, DST ambiguity)."""
        self.warnings[code] += 1
        if len(self.warning_samples) < MAX_SAMPLES:
            sample: dict[str, Any] = {"code": code}
            if location is not None:
                sample["location"] = location
            if detail is not None:
                sample["detail"] = detail
            self.warning_samples.append(sample)

    @property
    def balanced(self) -> bool:
        return self.records_read == self.events_emitted + self.skipped + self.errors

    def counts(self) -> dict[str, int]:
        return {
            "records_read": self.records_read,
            "events_emitted": self.events_emitted,
            "skipped": self.skipped,
            "errors": self.errors,
        }


@dataclass(frozen=True)
class ParseLimits:
    max_line_bytes: int = 64 * 1024
    max_decompressed_bytes: int = 4 * 1024**3
    max_decompression_ratio: int = 200
    ratio_check_after_bytes: int = 16 * 1024 * 1024


def _no_progress(_: float) -> None:
    return None


@dataclass
class ParseContext:
    path: Path  # read-only scratch copy of the evidence; never derived from evidence content
    evidence_id: str
    case_id: str
    source_file: str  # sanitized original file name (display/provenance only, never a path)
    host_hint: str | None = None
    timezone: str = "UTC"  # IANA zone for sources without an offset (syslog)
    year: int | None = None  # explicit year for sources without one (syslog)
    reference_time: datetime | None = None  # acquisition/upload time (tz-aware): year inference
    reference_source: str = "none"  # where reference_time came from, recorded in the manifest
    params: Mapping[str, Any] = field(default_factory=dict)
    stats: ParseStats = field(default_factory=ParseStats)
    limits: ParseLimits = field(default_factory=ParseLimits)
    # Called with 0..1 as input is consumed. The runner uses it to flush, heartbeat and check for
    # cancellation, so it may raise (e.g. JobCancelledError) - parsers must let that propagate.
    progress: Callable[[float], None] = _no_progress


class Parser(Protocol):
    name: str
    version: str
    description: str
    source_types: tuple[str, ...]

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        """Confidence 0.0-1.0 from the first bytes (and, weakly, the file name)."""

    def parse(self, ctx: ParseContext) -> Iterable[Event]:
        """Yield events; account for every record in ``ctx.stats``."""

    def tool_versions(self) -> dict[str, str]:
        """Versions of the libraries/engines used, for the run manifest."""
