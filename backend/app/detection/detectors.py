"""Built-in detectors referenced by rules as ``detection: {detector: <name>, params: {...}}``.

*Source* detectors (anti-forensics, guide 11.6) see one source at a time - one file of one
evidence item - in **record order** (EVTX ``EventRecordID``, line number for text logs), which is
what reveals deleted records, clock jumps and gaps; timestamps alone cannot. Each keeps O(1) state
per source plus bounded samples. The *event* detector ``ioc_match`` runs in the timestamp-ordered
pass with the case's IOC index (see :mod:`app.detection.ioc`).

All thresholds are parameters with strict bounds, so a rule cannot make a detector unbounded.
"""

from __future__ import annotations

import statistics
from array import array
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.detection.fields import parse_duration

MAX_SAMPLES = 50
MAX_DELTAS = 200_000
MAX_CANDIDATES = 1000

Ref = tuple[Any, datetime]  # (event id, event ts)


@dataclass(frozen=True)
class SourceInfo:
    evidence_id: str
    source_file: str | None
    acquired_at: datetime | None = None


@dataclass
class Finding:
    """One alert-worth result of a source detector (aggregated per source)."""

    refs: list[Ref]
    details: dict[str, Any]
    host: str | None = None


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _duration(minimum: int, maximum: int) -> Callable[[str], str]:
    def check(value: str) -> str:
        parse_duration(value, minimum=minimum, maximum=maximum)
        return value

    return check


class RecordGapParams(_Params):
    min_missing: int = Field(default=1, ge=1, le=1_000_000)


class OutOfOrderParams(_Params):
    tolerance: str = "10m"

    @field_validator("tolerance")
    @classmethod
    def _tol(cls, value: str) -> str:
        return _duration(1, 7 * 86400)(value)


class TimeGapParams(_Params):
    min_gap: str = "12h"
    factor: float = Field(default=50.0, ge=1.0, le=100_000.0)
    min_events: int = Field(default=10, ge=2, le=1_000_000)

    @field_validator("min_gap")
    @classmethod
    def _gap(cls, value: str) -> str:
        return _duration(60, 365 * 86400)(value)


class TruncationParams(_Params):
    min_gap: str = "24h"

    @field_validator("min_gap")
    @classmethod
    def _gap(cls, value: str) -> str:
        return _duration(60, 365 * 86400)(value)


class IocParams(_Params):
    pass


class SourceState:
    """Per-source detector state: ``feed`` record-ordered events, then ``finish``."""

    def __init__(self, params: Any, source: SourceInfo) -> None:
        self.params = params
        self.source = source
        self.prev: Mapping[str, Any] | None = None
        self.host: str | None = None

    def feed(self, event: Mapping[str, Any]) -> None:
        if self.host is None and event.get("host"):
            self.host = str(event["host"])
        self._feed(event)
        self.prev = event

    def _feed(self, event: Mapping[str, Any]) -> None:
        raise NotImplementedError

    def finish(self) -> list[Finding]:
        raise NotImplementedError


def _ref(event: Mapping[str, Any]) -> Ref:
    return (event["id"], event["ts"])


class RecordGapState(SourceState):
    """Missing ``EventRecordID`` ranges (records deleted or unreadable) - guide DFIR-WIN-0027."""

    def __init__(self, params: RecordGapParams, source: SourceInfo) -> None:
        super().__init__(params, source)
        self.gaps: list[dict[str, Any]] = []
        self.refs: list[Ref] = []
        self.gap_count = 0
        self.missing = 0

    def _feed(self, event: Mapping[str, Any]) -> None:
        prev = self.prev
        if prev is None or prev.get("recno") is None or event.get("recno") is None:
            return
        missing = int(event["recno"]) - int(prev["recno"]) - 1
        if missing < self.params.min_missing:
            return  # consecutive, or a duplicate record number (dirty chunk)
        self.gap_count += 1
        self.missing += missing
        if len(self.gaps) < MAX_SAMPLES:
            self.gaps.append(
                {
                    "after_record": int(prev["recno"]),
                    "before_record": int(event["recno"]),
                    "missing": missing,
                    "from": prev["ts"].isoformat(),
                    "to": event["ts"].isoformat(),
                }
            )
            self.refs.extend([_ref(prev), _ref(event)])

    def finish(self) -> list[Finding]:
        if not self.gap_count:
            return []
        details = {"gaps": self.gaps, "gap_count": self.gap_count, "missing_records": self.missing}
        return [Finding(self.refs, details, self.host)]


class OutOfOrderState(SourceState):
    """Timestamps that step backwards in record order by more than ``tolerance``."""

    def __init__(self, params: OutOfOrderParams, source: SourceInfo) -> None:
        super().__init__(params, source)
        self.tolerance = parse_duration(params.tolerance, maximum=7 * 86400)
        self.samples: list[dict[str, Any]] = []
        self.refs: list[Ref] = []
        self.count = 0
        self.max_backstep = 0.0

    def _feed(self, event: Mapping[str, Any]) -> None:
        prev = self.prev
        if prev is None:
            return
        back = (prev["ts"] - event["ts"]).total_seconds()
        if back <= self.tolerance:
            return
        self.count += 1
        self.max_backstep = max(self.max_backstep, back)
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append(
                {
                    "record": event.get("recno"),
                    "previous_record": prev.get("recno"),
                    "backstep_seconds": back,
                    "from": prev["ts"].isoformat(),
                    "to": event["ts"].isoformat(),
                }
            )
            self.refs.extend([_ref(prev), _ref(event)])

    def finish(self) -> list[Finding]:
        if not self.count:
            return []
        details = {
            "backsteps": self.samples,
            "count": self.count,
            "max_backstep_seconds": self.max_backstep,
            "tolerance_seconds": self.tolerance,
        }
        return [Finding(self.refs, details, self.host)]


class TimeGapState(SourceState):
    """Silence in a source: a gap >= ``min_gap`` and >= ``factor`` x the median gap."""

    def __init__(self, params: TimeGapParams, source: SourceInfo) -> None:
        super().__init__(params, source)
        self.min_gap = parse_duration(params.min_gap, minimum=60, maximum=365 * 86400)
        self.deltas: array[float] = array("d")
        self.candidates: list[tuple[float, Mapping[str, Any], Mapping[str, Any]]] = []
        self.events = 0

    def _feed(self, event: Mapping[str, Any]) -> None:
        self.events += 1
        prev = self.prev
        if prev is None:
            return
        delta = (event["ts"] - prev["ts"]).total_seconds()
        if delta <= 0:
            return
        if len(self.deltas) < MAX_DELTAS:
            self.deltas.append(delta)
        if delta >= self.min_gap and len(self.candidates) < MAX_CANDIDATES:
            self.candidates.append((delta, _slim(prev), _slim(event)))

    def finish(self) -> list[Finding]:
        if self.events < self.params.min_events or not self.candidates:
            return []
        median = statistics.median(self.deltas) if self.deltas else 0.0
        limit = max(float(self.min_gap), self.params.factor * median)
        gaps = [c for c in self.candidates if c[0] >= limit][:MAX_SAMPLES]
        if not gaps:
            return []
        refs: list[Ref] = []
        samples = []
        for delta, before, after in gaps:
            refs.extend([_ref(before), _ref(after)])
            samples.append(
                {
                    "gap_seconds": delta,
                    "from": before["ts"].isoformat(),
                    "to": after["ts"].isoformat(),
                    "after_record": before.get("recno"),
                }
            )
        details = {
            "gaps": samples,
            "median_gap_seconds": median,
            "threshold_seconds": limit,
            "events": self.events,
        }
        return [Finding(refs, details, self.host)]


def _slim(event: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": event["id"], "ts": event["ts"], "recno": event.get("recno")}


class TruncationState(SourceState):
    """The log ends long before the evidence was acquired (tail cut off, or logging stopped)."""

    def __init__(self, params: TruncationParams, source: SourceInfo) -> None:
        super().__init__(params, source)
        self.min_gap = parse_duration(params.min_gap, minimum=60, maximum=365 * 86400)
        self.last: dict[str, Any] | None = None

    def _feed(self, event: Mapping[str, Any]) -> None:
        if self.last is None or event["ts"] >= self.last["ts"]:
            self.last = _slim(event)

    def finish(self) -> list[Finding]:
        acquired = self.source.acquired_at
        if acquired is None or self.last is None:
            return []
        silence = (acquired - self.last["ts"]).total_seconds()
        if silence < self.min_gap:
            return []
        details = {
            "last_event": self.last["ts"].isoformat(),
            "acquired_at": acquired.isoformat(),
            "silence_seconds": silence,
        }
        return [Finding([_ref(self.last)], details, self.host)]


@dataclass(frozen=True)
class DetectorSpec:
    name: str
    family: Literal["source", "event"]
    params_model: type[BaseModel]
    state: Callable[[Any, SourceInfo], SourceState] | None = None
    description: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


DETECTORS: dict[str, DetectorSpec] = {
    "record_gap": DetectorSpec(
        "record_gap", "source", RecordGapParams, RecordGapState, "missing record ids"
    ),
    "out_of_order": DetectorSpec(
        "out_of_order", "source", OutOfOrderParams, OutOfOrderState, "timestamps step backwards"
    ),
    "time_gap": DetectorSpec("time_gap", "source", TimeGapParams, TimeGapState, "logging gap"),
    "log_truncation": DetectorSpec(
        "log_truncation", "source", TruncationParams, TruncationState, "log ends early"
    ),
    "ioc_match": DetectorSpec("ioc_match", "event", IocParams, None, "IOC value seen"),
}
