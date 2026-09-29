"""Streaming detection engine (guide 11.3). Pure: no database, no network.

Input contract:

* :meth:`DetectionEngine.feed` receives the case's events ordered by ``(ts, id)``. Single and
  threshold rules, sequence rules and the ``ioc_match`` detector run here. Out-of-order input is
  counted (``unordered_input``) and never crashes the run.
* :meth:`DetectionEngine.feed_source` receives one source (file of an evidence item) in record
  order for the anti-forensics source detectors.

Output: :class:`AlertDraft` objects keyed by a deterministic ``dedup_key`` = rule id + SHA-256 of
(entity, time bucket). The entity is ``group_by``/``join_on`` values (default: ``host``) for event
rules, the IOC for IOC hits, and (evidence, file) for source detectors; the bucket is the event
time floored to the rule's ``dedup_window`` (default 1 day; source detectors use one bucket per
source). Running the engine twice over the same events yields the same drafts, which is what
makes detection idempotent.

Memory bounds (:class:`EngineLimits`): alert drafts, linked events per draft, groups per
threshold/sequence rule, partial runs per sequence key and events per distinct-threshold window
are all capped; hitting a cap is counted in ``warnings`` and makes the run ``partial``.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.detection.detectors import DETECTORS, Ref, SourceInfo
from app.detection.ioc import IocIndex
from app.detection.rules import CompiledRule, EventView

MAX_TRACKED_VALUES = 32
STEP_EXTRA = 200


@dataclass(frozen=True)
class EngineLimits:
    max_alerts: int = 20_000
    max_links_per_alert: int = 500
    max_groups_per_rule: int = 100_000
    max_runs_per_key: int = 8
    max_events_per_group: int = 10_000


def bucket_start(ts: datetime, window_s: int) -> str:
    epoch = int(ts.timestamp())
    start = epoch - (epoch % window_s)
    return datetime.fromtimestamp(start, UTC).isoformat().replace("+00:00", "Z")


def dedup_key(rule_id: str, entity: Mapping[str, Any], bucket: str) -> str:
    body = json.dumps({"entity": entity, "bucket": bucket}, sort_keys=True, default=str)
    return f"{rule_id}:{hashlib.sha256(body.encode('utf-8')).hexdigest()[:40]}"


@dataclass
class AlertDraft:
    rule: CompiledRule
    dedup_key: str
    entity: dict[str, Any]
    bucket: str
    title: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    refs: list[Ref] = field(default_factory=list)
    links_dropped: int = 0
    hosts: Counter[str] = field(default_factory=Counter)
    users: Counter[str] = field(default_factory=Counter)
    _ids: set[Any] = field(default_factory=set)

    def add(self, ref: Ref, host: str | None, user: str | None, max_links: int) -> None:
        event_id, ts = ref
        if event_id in self._ids:
            return
        self.count += 1
        self.first_seen = ts if self.first_seen is None or ts < self.first_seen else self.first_seen
        self.last_seen = ts if self.last_seen is None or ts > self.last_seen else self.last_seen
        if len(self.refs) < max_links:
            self.refs.append(ref)
            self._ids.add(event_id)
        else:
            self.links_dropped += 1
        for counter, value in ((self.hosts, host), (self.users, user)):
            if value and (value in counter or len(counter) < MAX_TRACKED_VALUES):
                counter[value] += 1

    @staticmethod
    def _single(counter: Counter[str]) -> str | None:
        return next(iter(counter)) if len(counter) == 1 else None

    @property
    def host(self) -> str | None:
        value = self.entity.get("host")
        return str(value) if value else self._single(self.hosts)

    @property
    def user(self) -> str | None:
        value = self.entity.get("user")
        return str(value) if value else self._single(self.users)

    def summary(self) -> dict[str, Any]:
        """``details`` stored on the alert (JSON-safe, bounded)."""
        out = dict(self.details)
        out["entity"] = self.entity
        out["bucket"] = self.bucket
        out["rule_kind"] = self.rule.kind
        if len(self.hosts) > 1:
            out["hosts"] = sorted(self.hosts)[:MAX_TRACKED_VALUES]
        if len(self.users) > 1:
            out["users"] = sorted(self.users)[:MAX_TRACKED_VALUES]
        if self.links_dropped:
            out["links_dropped"] = self.links_dropped
        return out


@dataclass
class _Entry:
    t: float
    ref: Ref
    host: str | None
    user: str | None
    value: str | None = None
    seq: int = 0


class _ThresholdGroup:
    __slots__ = ("counter", "emitted", "entries", "last_t", "next_seq")

    def __init__(self) -> None:
        self.entries: deque[_Entry] = deque()
        self.counter: Counter[str] = Counter()
        self.next_seq = 0
        self.emitted = -1
        self.last_t = 0.0

    def add(self, entry: _Entry, rule: CompiledRule, limits: EngineLimits) -> list[_Entry]:
        spec = rule.threshold
        if spec is None:
            raise RuntimeError("internal: spec missing")
        entry.seq = self.next_seq
        self.next_seq += 1
        self.last_t = entry.t
        self.entries.append(entry)
        if spec.distinct is None:
            while len(self.entries) > spec.count:
                self.entries.popleft()
            qualifies = (
                len(self.entries) == spec.count and entry.t - self.entries[0].t <= spec.window_s
            )
        else:
            if entry.value is not None:
                self.counter[entry.value] += 1
            while self.entries and (
                entry.t - self.entries[0].t > spec.window_s
                or len(self.entries) > limits.max_events_per_group
            ):
                self._drop()
            qualifies = len(self.counter) >= spec.count
        if not qualifies:
            return []
        out = [e for e in self.entries if e.seq > self.emitted]
        self.emitted = entry.seq
        return out

    def _drop(self) -> None:
        old = self.entries.popleft()
        if old.value is not None:
            self.counter[old.value] -= 1
            if self.counter[old.value] <= 0:
                del self.counter[old.value]


class _Run:
    __slots__ = ("events", "step")

    def __init__(self, steps: int) -> None:
        self.step = 0
        self.events: list[list[_Entry]] = [[] for _ in range(steps)]

    @property
    def start(self) -> float:
        for bucket in self.events:
            if bucket:
                return bucket[0].t
        return 0.0

    def add(self, index: int, entry: _Entry, cap: int) -> None:
        bucket = self.events[index]
        bucket.append(entry)
        if len(bucket) > cap:
            del bucket[0]

    def all(self) -> list[_Entry]:
        return sorted((e for bucket in self.events for e in bucket), key=lambda e: e.t)


class DetectionEngine:
    def __init__(
        self,
        rules: Sequence[CompiledRule],
        iocs: IocIndex | None = None,
        limits: EngineLimits | None = None,
    ) -> None:
        self.limits = limits or EngineLimits()
        self.rules = list(rules)
        self.event_rules = [r for r in rules if r.kind in ("single", "threshold")]
        self.sequence_rules = [r for r in rules if r.kind == "sequence"]
        self.ioc_rules = [
            r
            for r in rules
            if r.kind == "detector" and r.detector and DETECTORS[r.detector].family == "event"
        ]
        self.source_rules = [
            r
            for r in rules
            if r.kind == "detector" and r.detector and DETECTORS[r.detector].family == "source"
        ]
        self.iocs = iocs
        self.drafts: dict[str, AlertDraft] = {}
        self.matches: Counter[str] = Counter()
        self.warnings: Counter[str] = Counter()
        self.events_seen = 0
        self.source_events_seen = 0
        self._thresholds: dict[str, dict[tuple[Any, ...], _ThresholdGroup]] = {}
        self._sequences: dict[str, dict[tuple[Any, ...], list[_Run]]] = {}
        self._last: tuple[datetime, str] | None = None

    # ------------------------------------------------------------------ helpers

    @property
    def capped(self) -> bool:
        return any(
            k in self.warnings
            for k in ("alert_cap_reached", "group_cap_reached", "sequence_run_cap_reached")
        )

    def _draft(
        self,
        rule: CompiledRule,
        entity: dict[str, Any],
        bucket: str,
        *,
        title: str | None = None,
        confidence: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> AlertDraft | None:
        key = dedup_key(rule.id, entity, bucket)
        draft = self.drafts.get(key)
        if draft is None:
            if len(self.drafts) >= self.limits.max_alerts:
                self.warnings["alert_cap_reached"] += 1
                return None
            draft = AlertDraft(
                rule,
                key,
                entity,
                bucket,
                title or rule.title,
                rule.confidence if confidence is None else confidence,
                dict(details or {}),
            )
            self.drafts[key] = draft
        return draft

    def _add(self, draft: AlertDraft | None, entry: _Entry) -> None:
        if draft is not None:
            draft.add(entry.ref, entry.host, entry.user, self.limits.max_links_per_alert)

    @staticmethod
    def _entry(ev: EventView, value: str | None = None) -> _Entry:
        event = ev.event
        ts: datetime = event["ts"]
        return _Entry(ts.timestamp(), (event["id"], ts), ev.text("host"), ev.text("user"), value)

    def _key(
        self, rule: CompiledRule, ev: EventView, names: tuple[str, ...]
    ) -> tuple[Any, ...] | None:
        values = tuple(ev.text(n) for n in names)
        if any(v is None or v == "" for v in values):
            self.warnings[f"{rule.id}:join_field_missing"] += 1
            return None
        return values

    # ------------------------------------------------------------------ ts-ordered pass

    def feed(self, event: Mapping[str, Any]) -> None:
        self.events_seen += 1
        order = (event["ts"], str(event["id"]))
        if self._last is not None and order < self._last:
            self.warnings["unordered_input"] += 1
        self._last = order
        ev = EventView(event)
        for rule in self.event_rules:
            if rule.matches(ev):
                self.matches[rule.id] += 1
                if rule.kind == "single":
                    self._single(rule, ev)
                else:
                    self._threshold(rule, ev)
        for rule in self.sequence_rules:
            if rule.logsource.match(ev):
                self._sequence(rule, ev)
        if self.iocs is not None and len(self.iocs) and self.ioc_rules:
            hits = self.iocs.match(event)
            for rule in self.ioc_rules:
                if hits and rule.logsource.match(ev):
                    self._ioc(rule, ev, hits)

    def _single(self, rule: CompiledRule, ev: EventView) -> None:
        names = rule.group_by or ("host",)
        entity = {n: ev.text(n) for n in names}
        ts: datetime = ev.event["ts"]
        self._add(self._draft(rule, entity, bucket_start(ts, rule.dedup_window_s)), self._entry(ev))

    def _threshold(self, rule: CompiledRule, ev: EventView) -> None:
        spec = rule.threshold
        if spec is None:
            raise RuntimeError("internal: spec missing")
        found = self._key(rule, ev, rule.group_by) if rule.group_by else ()
        if found is None:
            return
        key: tuple[Any, ...] = found
        groups = self._thresholds.setdefault(rule.id, {})
        group = groups.get(key)
        entry = self._entry(ev, ev.text(spec.distinct) if spec.distinct else None)
        if group is None:
            if len(groups) >= self.limits.max_groups_per_rule:
                horizon = entry.t - spec.window_s
                for stale in [k for k, g in groups.items() if g.last_t < horizon]:
                    del groups[stale]
                if len(groups) >= self.limits.max_groups_per_rule:
                    self.warnings["group_cap_reached"] += 1
                    return
            group = groups[key] = _ThresholdGroup()
        fired = group.add(entry, rule, self.limits)
        if not fired:
            return
        entity = dict(zip(rule.group_by, key, strict=True))
        ts: datetime = ev.event["ts"]
        draft = self._draft(
            rule,
            entity,
            bucket_start(ts, rule.dedup_window_s),
            details={
                "threshold": {
                    "count": spec.count,
                    "window_seconds": spec.window_s,
                    "distinct": spec.distinct,
                }
            },
        )
        for item in fired:
            self._add(draft, item)

    def _sequence(self, rule: CompiledRule, ev: EventView) -> None:
        spec = rule.sequence
        if spec is None:
            raise RuntimeError("internal: spec missing")
        matched = [i for i, step in enumerate(spec.steps) if step.selection.match(ev)]
        if not matched:
            return
        key = self._key(rule, ev, spec.join_on)
        if key is None:
            return
        states = self._sequences.setdefault(rule.id, {})
        entry = self._entry(ev)
        runs = states.get(key)
        if runs is None:
            if len(states) >= self.limits.max_groups_per_rule:
                horizon = entry.t - spec.within_s
                for stale in [k for k, rs in states.items() if all(r.start < horizon for r in rs)]:
                    del states[stale]
                if len(states) >= self.limits.max_groups_per_rule:
                    self.warnings["group_cap_reached"] += 1
                    return
            runs = states[key] = []
        kept: list[_Run] = []
        for run in runs:
            if run.step == 0:
                first = run.events[0]
                while first and entry.t - first[0].t > spec.within_s:
                    del first[0]
                if first:
                    kept.append(run)
            elif entry.t - run.start <= spec.within_s:
                kept.append(run)
        runs[:] = kept
        last = len(spec.steps) - 1
        consumed = False
        for run in list(runs):
            step = run.step
            cap = spec.steps[step].min_count + STEP_EXTRA
            if step in matched:
                run.add(step, entry, cap)
                consumed = True
                if len(run.events[step]) >= spec.steps[step].min_count:
                    if step == last:
                        runs.remove(run)
                        self._complete(rule, key, run)
                    else:
                        run.step += 1
                break
            if step > 0 and (step - 1) in matched and not run.events[step]:
                run.add(step - 1, entry, spec.steps[step - 1].min_count + STEP_EXTRA)
                consumed = True
                break
        if not consumed and 0 in matched:
            run = _Run(len(spec.steps))
            run.add(0, entry, spec.steps[0].min_count + STEP_EXTRA)
            if spec.steps[0].min_count <= 1:
                run.step = 1
            runs.append(run)
            if len(runs) > self.limits.max_runs_per_key:
                del runs[0]
                self.warnings["sequence_run_cap_reached"] += 1
        if not runs:
            del states[key]

    def _complete(self, rule: CompiledRule, key: tuple[Any, ...], run: _Run) -> None:
        spec = rule.sequence
        if spec is None:
            raise RuntimeError("internal: spec missing")
        self.matches[rule.id] += 1
        entries = run.all()
        start = datetime.fromtimestamp(entries[0].t, UTC)
        entity = dict(zip(spec.join_on, key, strict=True))
        draft = self._draft(
            rule,
            entity,
            bucket_start(start, rule.dedup_window_s),
            details={
                "sequence": {step.name: len(run.events[i]) for i, step in enumerate(spec.steps)},
                "within_seconds": spec.within_s,
            },
        )
        for item in entries:
            self._add(draft, item)

    def _ioc(self, rule: CompiledRule, ev: EventView, hits: list[Any]) -> None:
        ts: datetime = ev.event["ts"]
        for hit in hits:
            ioc = hit.ioc
            entity = {"ioc_type": ioc.type, "ioc_value": ioc.value, "host": ev.text("host")}
            draft = self._draft(
                rule,
                entity,
                bucket_start(ts, rule.dedup_window_s),
                title=f"{rule.title}: {ioc.type} {ioc.value[:120]}",
                confidence=ioc.confidence,
                details={
                    "ioc": {
                        "id": ioc.id,
                        "type": ioc.type,
                        "value": ioc.value,
                        "tlp": ioc.tlp,
                        "source": ioc.source,
                    }
                },
            )
            if draft is not None:
                fields = draft.details.setdefault("matched_fields", [])
                if hit.field not in fields and len(fields) < 8:
                    fields.append(hit.field)
            self.matches[rule.id] += 1
            self._add(draft, self._entry(ev))

    # ------------------------------------------------------------------ record-ordered pass

    @property
    def needs_sources(self) -> bool:
        return bool(self.source_rules)

    def feed_source(self, source: SourceInfo, events: Iterable[Mapping[str, Any]]) -> None:
        states = []
        for rule in self.source_rules:
            spec = DETECTORS[rule.detector or ""]
            if spec.state is None:
                raise RuntimeError("internal: spec.state missing")
            states.append((rule, spec.state(rule.params, source)))
        for event in events:
            self.source_events_seen += 1
            ev = EventView(event)
            for rule, state in states:
                if rule.logsource.match(ev):
                    state.feed(event)
        for rule, state in states:
            for finding in state.finish():
                self.matches[rule.id] += 1
                entity = {"evidence_id": source.evidence_id, "source_file": source.source_file}
                draft = self._draft(rule, entity, "source", details=finding.details)
                if draft is None:
                    continue
                for ref in finding.refs:
                    draft.add(ref, finding.host, None, self.limits.max_links_per_alert)

    # ------------------------------------------------------------------ results

    def results(self) -> list[AlertDraft]:
        return [self.drafts[k] for k in sorted(self.drafts)]
