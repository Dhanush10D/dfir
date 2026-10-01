"""Mapping of SIEM/EDR webhook payloads to alerts (guide 19.3). Pure; every field is untrusted.

The body is a JSON object with a list under ``alerts`` / ``items`` / ``events`` / ``results``, a
bare list, or one object. Each item is read through a field map (dotted paths, from the saved
integration configuration, never from the payload) and cleaned with the same helpers the parser
pipeline uses (:mod:`app.parsers.normalize`): NUL and lone surrogates are replaced, every text is
length-capped, IPs must parse, the kept copy of the item is size-bounded. A timestamp must carry a
time zone (or be an epoch number); a missing one means "received now". An item that cannot be
mapped raises :class:`ItemError`: the caller counts it and carries on.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.parsers.normalize import clean_ip, clean_json, clean_text

LIST_KEYS = ("alerts", "items", "events", "results")
FIELDS = (
    "id",
    "title",
    "severity",
    "timestamp",
    "host",
    "user",
    "description",
    "attack",
    "src_ip",
    "dst_ip",
)
# Candidate paths per field for the generic format (first one present wins).
DEFAULT_PATHS: dict[str, tuple[str, ...]] = {
    "id": ("id", "alert_id", "event_id", "uuid"),
    "title": ("title", "name", "rule_name", "signature"),
    "severity": ("severity", "level", "priority"),
    "timestamp": ("timestamp", "time", "@timestamp", "created_at"),
    "host": ("host", "hostname", "device", "host.name"),
    "user": ("user", "username", "user.name"),
    "description": ("description", "message", "summary"),
    "attack": ("attack", "techniques", "mitre"),
    "src_ip": ("src_ip", "source_ip", "source.ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination.ip"),
}
SEVERITY_MAP = {
    "info": "info",
    "informational": "info",
    "notice": "info",
    "low": "low",
    "minor": "low",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "high": "high",
    "major": "high",
    "severe": "high",
    "critical": "critical",
    "fatal": "critical",
}
PATH_RE = re.compile(r"^[A-Za-z0-9_@-]{1,64}(\.[A-Za-z0-9_@-]{1,64}){0,7}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MAX_ID = 256
MAX_TITLE = 300
MAX_DESCRIPTION = 4096
MAX_RAW_BYTES = 32 * 1024
MAX_ATTACK = 20
MIN_YEAR, MAX_YEAR = 1990, 2200


class PayloadError(ValueError):
    """The whole delivery is unusable (not JSON, wrong shape, too many items)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ItemError(ValueError):
    """One item cannot be mapped; ``reason`` is a fixed code (never payload text)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ExternalAlert:
    external_id: str
    title: str
    severity: str
    ts: datetime
    ts_original: str | None
    ts_source: str  # payload | received
    host: str | None
    user: str | None
    description: str | None
    attack: tuple[str, ...]
    src_ip: str | None
    dst_ip: str | None
    raw: dict[str, Any]

    @property
    def id_sha256(self) -> str:
        return hashlib.sha256(self.external_id.encode("utf-8")).hexdigest()


def validate_field_map(field_map: Mapping[str, Any]) -> dict[str, str]:
    """A configured field map: known fields to dotted paths (raises ValueError)."""
    out: dict[str, str] = {}
    for name, path in field_map.items():
        if name not in FIELDS:
            raise ValueError(f"unknown field {str(name)[:40]!r} (use one of {', '.join(FIELDS)})")
        if not isinstance(path, str) or not PATH_RE.fullmatch(path):
            raise ValueError(f"invalid path for {name!r}")
        out[name] = path
    return out


def parse_items(body: bytes, max_items: int) -> list[Any]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise PayloadError("invalid_json", "The body is not valid UTF-8 JSON.") from exc
    items: Any
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next((data[k] for k in LIST_KEYS if isinstance(data.get(k), list)), [data])
    else:
        raise PayloadError("invalid_payload", "The body must be a JSON object or list.")
    if len(items) > max_items:
        raise PayloadError("too_many_items", f"At most {max_items} items per delivery.")
    return list(items)


def _lookup(item: Mapping[str, Any], path: str) -> Any:
    if path in item:  # keys such as "host.name" stored flat
        return item[path]
    value: Any = item
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _field(item: Mapping[str, Any], name: str, field_map: Mapping[str, str]) -> Any:
    paths: Sequence[str] = (field_map[name],) if name in field_map else DEFAULT_PATHS[name]
    for path in paths:
        value = _lookup(item, path)
        if value is not None and value != "":
            return value
    return None


def _scalar_text(value: Any, limit: int) -> str | None:
    if value is None or isinstance(value, bool | dict | list):
        return None
    text = clean_text(str(value), limit)
    if text is None:
        return None
    text = text.strip()
    return text or None


def _timestamp(value: Any, now: datetime) -> tuple[datetime, str | None, str]:
    if value is None:
        return now, None, "received"
    original = clean_text(str(value), 128)
    ts: datetime
    try:
        if isinstance(value, bool):
            raise ItemError("invalid_timestamp")
        if isinstance(value, int | float):
            seconds = float(value) / 1000.0 if abs(float(value)) > 1e11 else float(value)
            ts = datetime.fromtimestamp(seconds, UTC)
        elif isinstance(value, str) and len(value) <= 64:
            ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        else:
            raise ItemError("invalid_timestamp")
    except (ValueError, OverflowError, OSError) as exc:
        raise ItemError("invalid_timestamp") from exc
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ItemError("timestamp_without_timezone")
    try:
        ts = ts.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ItemError("invalid_timestamp") from exc
    if not MIN_YEAR <= ts.year <= MAX_YEAR:
        raise ItemError("timestamp_out_of_range")
    return ts, original, "payload"


def map_item(item: Any, field_map: Mapping[str, str], now: datetime) -> ExternalAlert:
    if not isinstance(item, dict):
        raise ItemError("not_an_object")
    external_id = _scalar_text(_field(item, "id", field_map), MAX_ID + 1)
    if external_id is None:
        raise ItemError("missing_id")
    if len(external_id) > MAX_ID:
        raise ItemError("id_too_long")
    title = _scalar_text(_field(item, "title", field_map), MAX_TITLE)
    if title is None:
        raise ItemError("missing_title")
    severity_raw = _scalar_text(_field(item, "severity", field_map), 32)
    severity = SEVERITY_MAP.get((severity_raw or "").lower(), "medium")
    ts, ts_original, ts_source = _timestamp(_field(item, "timestamp", field_map), now)
    attack_raw = _field(item, "attack", field_map)
    if isinstance(attack_raw, str):
        attack_raw = re.split(r"[,\s]+", attack_raw[:1024])
    attack: list[str] = []
    if isinstance(attack_raw, list):
        for entry in attack_raw[: MAX_ATTACK * 4]:
            tag = str(entry).strip().upper() if isinstance(entry, str) else ""
            if TECHNIQUE_RE.fullmatch(tag) and tag not in attack and len(attack) < MAX_ATTACK:
                attack.append(tag)
    raw = clean_json(item)
    encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RAW_BYTES:
        raw = {"_truncated": True, "_bytes": len(encoded), "summary": clean_text(encoded, 2048)}
    src = _field(item, "src_ip", field_map)
    dst = _field(item, "dst_ip", field_map)
    return ExternalAlert(
        external_id=external_id,
        title=title,
        severity=severity,
        ts=ts,
        ts_original=ts_original,
        ts_source=ts_source,
        host=_scalar_text(_field(item, "host", field_map), 255),
        user=_scalar_text(_field(item, "user", field_map), 512),
        description=_scalar_text(_field(item, "description", field_map), MAX_DESCRIPTION),
        attack=tuple(sorted(attack)),
        src_ip=clean_ip(src) if isinstance(src, str) else None,
        dst_ip=clean_ip(dst) if isinstance(dst, str) else None,
        raw=raw if isinstance(raw, dict) else {"value": raw},
    )
