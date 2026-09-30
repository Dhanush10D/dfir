"""Evidence packs (guide 13.4): numbered, compact, sanitized records inside one data block.

The model sees short ids only (``E1`` events, ``A1`` alerts, ``S1`` script input, ``D1`` decoded
layers); :meth:`EvidencePack.ref_of` maps them back to database ids on the server. Every value is
passed through :func:`app.ai.sanitize.clean_text` and every record is scanned by
:func:`app.ai.sanitize.detect_injection` before rendering.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.ai.sanitize import clean_text, detect_injection

RecordKind = Literal["event", "alert", "script", "decoded"]
PREFIX: dict[RecordKind, str] = {"event": "E", "alert": "A", "script": "S", "decoded": "D"}
SHORT_ID_RE = re.compile(r"^[EASD][0-9]{1,4}$")
OPEN, CLOSE = "<evidence>", "</evidence>"

# (label in the line, key in the event mapping) in rendering order: an allowlist, never raw blobs.
EVENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("host", "host"),
    ("user", "user"),
    ("source", "source_type"),
    ("code", "event_code"),
    ("category", "event_category"),
    ("action", "action"),
    ("outcome", "outcome"),
    ("process", "process_name"),
    ("pid", "pid"),
    ("ppid", "ppid"),
    ("cmdline", "cmdline"),
    ("file", "file_path"),
    ("hash", "file_hash"),
    ("src_ip", "src_ip"),
    ("src_port", "src_port"),
    ("dst_ip", "dst_ip"),
    ("dst_port", "dst_port"),
    ("proto", "protocol"),
    ("reg", "registry_key"),
    ("attack", "attack_tags"),
    ("msg", "message"),
)


class PackFullError(Exception):
    """The pack reached ``max_records``."""


def iso(ts: object) -> str | None:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if ts is None:
        return None
    return str(ts)


# Redaction hook: (raw value, field label) -> value. Applied to the RAW value before
# sanitizing, quoting and truncation, so escaping cannot split a secret from its key and
# truncation cannot cut off the end of a secret block (docs/ai.md, Phase 7 review B1).
Redact = Callable[[str, str | None], str]

ALERT_FIELDS: tuple[tuple[str, str], ...] = (
    ("rule", "rule_id"),
    ("severity", "severity"),
    ("status", "status"),
    ("host", "host"),
    ("user", "user"),
    ("attack", "attack_tags"),
    ("first_seen", "first_seen"),
    ("last_seen", "last_seen"),
    ("events", "event_count"),
    ("title", "title"),
)


def _raw(value: object) -> str | None:
    value = getattr(value, "value", value)  # enums
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, list | tuple):
        return ",".join(str(v) for v in value)
    return str(value)


def _value(
    value: object, max_chars: int, redact: Redact | None = None, field: str | None = None
) -> str | None:
    raw = _raw(value)
    if raw is None:
        return None
    if redact is not None:
        raw = redact(raw, field)
    text = clean_text(raw, max_chars)
    if not text:
        return None
    if any(ch in text for ch in ' ="'):
        return '"' + text.replace('"', '\\"') + '"'
    return text


def _format(
    head: str, fields: tuple[tuple[str, str], ...], max_chars: int, redact: Redact | None
) -> str:
    parts = [head]
    for label, raw in fields:
        v = _value(raw, max_chars, redact, label)
        if v is not None:
            parts.append(f"{label}={v}")
    return " ".join(parts)


def _fields(
    mapping: Mapping[str, Any], spec: tuple[tuple[str, str], ...]
) -> tuple[tuple[str, str], ...]:
    out = []
    for label, key in spec:
        raw = _raw(mapping.get(key))
        if raw is not None:
            out.append((label, raw))
    return tuple(out)


def event_line(ev: Mapping[str, Any], max_chars: int, redact: Redact | None = None) -> str:
    """One event as ``<ts> key=value ...`` (no id prefix)."""
    return _format(iso(ev.get("ts")) or "-", _fields(ev, EVENT_FIELDS), max_chars, redact)


def alert_line(al: Mapping[str, Any], max_chars: int, redact: Redact | None = None) -> str:
    return _format("alert", _fields(al, ALERT_FIELDS), max_chars, redact)


@dataclass(frozen=True)
class PackRecord:
    short_id: str
    kind: RecordKind
    ref_id: str | None  # database id (events/alerts) or None
    ts: str | None
    line: str  # sanitized, unredacted, without the "[E1] " prefix
    flags: tuple[str, ...] = ()
    head: str = ""
    fields: tuple[tuple[str, str], ...] = ()  # raw (label, value) pairs
    max_chars: int = 512

    def render_line(self, redact: Redact | None = None) -> str:
        """The line as sent: raw values redacted first, then sanitized, quoted, truncated."""
        if redact is None:
            return self.line
        return _format(self.head, self.fields, self.max_chars, redact)

    def summary(self, limit: int = 240) -> str:
        return self.line if len(self.line) <= limit else self.line[: limit - 1] + "…"


@dataclass
class EvidencePack:
    max_records: int = 150
    max_field_chars: int = 512
    records: list[PackRecord] = field(default_factory=list)
    _by_ref: dict[tuple[str, str], str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------ building

    def _next_id(self, kind: RecordKind) -> str:
        if len(self.records) >= self.max_records:
            raise PackFullError(f"evidence pack is limited to {self.max_records} records")
        n = self._counters.get(kind, 0) + 1
        self._counters[kind] = n
        return f"{PREFIX[kind]}{n}"

    def _add(
        self,
        kind: RecordKind,
        ref: str | None,
        ts: str | None,
        head: str,
        fields: tuple[tuple[str, str], ...],
        max_chars: int,
    ) -> str:
        if ref is not None and (kind, ref) in self._by_ref:
            return self._by_ref[(kind, ref)]
        sid = self._next_id(kind)
        raw = "\n".join(v for _, v in fields)
        line = _format(head, fields, max_chars, None)
        self.records.append(
            PackRecord(
                sid, kind, ref, ts, line, tuple(detect_injection(raw)), head, fields, max_chars
            )
        )
        if ref is not None:
            self._by_ref[(kind, ref)] = sid
        return sid

    def add_event(self, ev: Mapping[str, Any]) -> str:
        ref = str(ev["id"]) if ev.get("id") is not None else None
        head = iso(ev.get("ts")) or "-"
        return self._add(
            "event", ref, iso(ev.get("ts")), head, _fields(ev, EVENT_FIELDS), self.max_field_chars
        )

    def add_alert(self, al: Mapping[str, Any]) -> str:
        ref = str(al["id"]) if al.get("id") is not None else None
        return self._add(
            "alert",
            ref,
            iso(al.get("first_seen")),
            "alert",
            _fields(al, ALERT_FIELDS),
            self.max_field_chars,
        )

    def add_text(
        self, kind: Literal["script", "decoded"], text: str, *, max_chars: int, label: str
    ) -> str:
        fields = (("text", text),) if text else (("text", "(empty)"),)
        return self._add(kind, None, None, label, fields, max_chars)

    # ------------------------------------------------------------------ reading

    @property
    def ids(self) -> set[str]:
        return {r.short_id for r in self.records}

    def ref_of(self, short_id: str) -> PackRecord | None:
        for r in self.records:
            if r.short_id == short_id:
                return r
        return None

    @property
    def warnings(self) -> list[dict[str, Any]]:
        return [
            {"type": "injection_suspected", "record": r.short_id, "flags": list(r.flags)}
            for r in self.records
            if r.flags
        ]

    def record_text(self, redact: Redact | None = None) -> dict[str, str]:
        """Short id -> the line the model sees (after redaction)."""
        return {r.short_id: r.render_line(redact) for r in self.records}

    def render(self, redact: Redact | None = None) -> str:
        """The ``<evidence>`` block, with ``redact`` applied to every raw value first."""
        lines = [OPEN]
        for r in self.records:
            lines.append(f"[{r.short_id}] {r.render_line(redact)}")
        lines.append(CLOSE)
        return "\n".join(lines)

    def input_sha256(self, extra: Mapping[str, Any] | None = None) -> str:
        """Hash of the canonical pack content (+ question/filters): same input -> same hash."""
        payload = {
            "records": [[r.short_id, r.kind, r.ref_id, r.line] for r in self.records],
            "extra": dict(extra or {}),
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def input_refs(self) -> dict[str, Any]:
        return {r.short_id: {"kind": r.kind, "id": r.ref_id, "ts": r.ts} for r in self.records}
