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


def _value(value: object, max_chars: int) -> str | None:
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, list | tuple):
        value = ",".join(str(v) for v in value)
    text = clean_text(value, max_chars)
    if not text:
        return None
    if any(ch in text for ch in ' ="'):
        return '"' + text.replace('"', '\\"') + '"'
    return text


def event_line(ev: Mapping[str, Any], max_chars: int) -> str:
    """One event as ``<ts> key=value ...`` (no id prefix)."""
    parts = [iso(ev.get("ts")) or "-"]
    for label, key in EVENT_FIELDS:
        v = _value(ev.get(key), max_chars)
        if v is not None:
            parts.append(f"{label}={v}")
    return " ".join(parts)


def alert_line(al: Mapping[str, Any], max_chars: int) -> str:
    parts = ["alert"]
    for label, key in (
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
    ):
        raw = al.get(key)
        if key in ("first_seen", "last_seen"):
            raw = iso(raw)
        v = _value(getattr(raw, "value", raw), max_chars)
        if v is not None:
            parts.append(f"{label}={v}")
    return " ".join(parts)


def _raw_text(mapping: Mapping[str, Any], keys: tuple[str, ...]) -> str:
    return "\n".join(str(mapping.get(k)) for k in keys if mapping.get(k) not in (None, "", []))


@dataclass(frozen=True)
class PackRecord:
    short_id: str
    kind: RecordKind
    ref_id: str | None  # database id (events/alerts) or None
    ts: str | None
    line: str  # sanitized, without the "[E1] " prefix
    flags: tuple[str, ...] = ()

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

    def _add(self, kind: RecordKind, ref: str | None, ts: str | None, line: str, raw: str) -> str:
        if ref is not None and (kind, ref) in self._by_ref:
            return self._by_ref[(kind, ref)]
        sid = self._next_id(kind)
        self.records.append(PackRecord(sid, kind, ref, ts, line, tuple(detect_injection(raw))))
        if ref is not None:
            self._by_ref[(kind, ref)] = sid
        return sid

    def add_event(self, ev: Mapping[str, Any]) -> str:
        raw = _raw_text(ev, tuple(k for _, k in EVENT_FIELDS))
        ref = str(ev["id"]) if ev.get("id") is not None else None
        return self._add("event", ref, iso(ev.get("ts")), event_line(ev, self.max_field_chars), raw)

    def add_alert(self, al: Mapping[str, Any]) -> str:
        raw = _raw_text(al, ("title", "host", "user", "rule_id"))
        ref = str(al["id"]) if al.get("id") is not None else None
        return self._add(
            "alert", ref, iso(al.get("first_seen")), alert_line(al, self.max_field_chars), raw
        )

    def add_text(
        self, kind: Literal["script", "decoded"], text: str, *, max_chars: int, label: str
    ) -> str:
        line = f"{label} text={_value(text, max_chars) or '(empty)'}"
        return self._add(kind, None, None, line, text)

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

    def render(self, transform: Callable[[str], str] | None = None) -> str:
        """The ``<evidence>`` block; ``transform`` (redaction) is applied per record line."""
        lines = [OPEN]
        for r in self.records:
            text = transform(r.line) if transform else r.line
            lines.append(f"[{r.short_id}] {text}")
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
