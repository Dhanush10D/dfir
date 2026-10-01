"""Event -> ``events`` row (pure). Validates and sanitizes hostile parser output for PostgreSQL.

* ``ts`` must be timezone-aware; it is converted to UTC. Naive timestamps are a parser bug and are
  rejected (the runner counts the record as an error).
* Text: NUL characters (rejected by PostgreSQL ``text``/``jsonb``) and lone surrogates (not
  encodable as UTF-8) are replaced by U+FFFD; long values are truncated with a marker.
* ``inet`` and integer columns only receive values that fit; anything else becomes NULL (the
  original value stays in ``raw``).
* ``raw`` is made JSON-safe (strings/ints/bools/None/lists/dicts, floats kept only when finite) and
  its serialized size is bounded.
* The event id is deterministic: ``uuid5(namespace, evidence_id/parser/source_file/record_key)``,
  so a retry or reprocess of the same input can never create a second row for a record.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import uuid
from datetime import UTC
from typing import Any

from app.parsers.base import Event

EVENT_NAMESPACE = uuid.UUID("5b0f5d0e-6c3e-4f7a-9d1e-2f4a6c8b0d11")
MAX_TEXT = 32 * 1024
MAX_SHORT = 1024
MAX_RAW_BYTES = 512 * 1024
MAX_TAGS = 64
INT4_MAX = 2**31 - 1
REPLACEMENT = "�"
SURROGATES = re.compile(r"[\ud800-\udfff]")  # lone surrogates (not encodable as UTF-8)


class NormalizationError(ValueError):
    pass


def clean_text(value: str | None, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    if "\x00" in value:
        value = value.replace("\x00", REPLACEMENT)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = SURROGATES.sub(REPLACEMENT, value)
    if len(value) > limit:
        value = value[:limit] + "...[truncated]"
    return value


def clean_json(value: Any, depth: int = 0) -> Any:
    if depth > 32:
        return "[too deep]"
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value, 64 * 1024)
    if isinstance(value, dict):
        return {str(clean_text(str(k), 256)): clean_json(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [clean_json(v, depth + 1) for v in value]
    return clean_text(repr(value), 1024)


def clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def clean_int(value: int | None, low: int = 0, high: int = INT4_MAX) -> int | None:
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def event_id(
    evidence_id: str, parser_name: str, source_file: str | None, record_key: str
) -> uuid.UUID:
    return uuid.uuid5(
        EVENT_NAMESPACE, f"{evidence_id}/{parser_name}/{source_file or ''}/{record_key}"
    )


def clean_raw(value: Any) -> tuple[Any, str]:
    """JSON-safe ``raw`` and its compact encoding, replaced by a summary above MAX_RAW_BYTES."""
    raw = clean_json(value or {})
    encoded = json.dumps(raw, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_RAW_BYTES:
        raw = {"_truncated": True, "_bytes": len(encoded), "summary": clean_text(encoded, 4096)}
        encoded = json.dumps(raw)
    return raw, encoded


def clean_event(event: Event) -> Event:
    """``event`` with every column value cleaned exactly as ``to_row`` stores it.

    Idempotent (``clean_event(clean_event(e)) == clean_event(e)``: truncation keeps the marker,
    replacement characters stay), so the parser sandbox can send cleaned events and the worker
    normalises them again without changing a byte. ``ts``, ``record_key`` and ``source_file`` are
    left as they are: the deterministic event id is computed from the parser's own values.
    """
    raw, _ = clean_raw(event.raw)
    tags = event.tags[:MAX_TAGS] if isinstance(event.tags, list | tuple | str) else []
    return Event(
        ts=event.ts,
        source_type=clean_text(event.source_type, 64) or "unknown",
        message=clean_text(event.message) or "",
        record_key=event.record_key,
        host=clean_text(event.host, 255),
        user=clean_text(event.user, 512),
        event_code=clean_text(event.event_code, 128),
        event_category=clean_text(event.event_category, 64),
        action=clean_text(event.action, 64),
        outcome=clean_text(event.outcome, 32),
        process_name=clean_text(event.process_name, MAX_SHORT),
        pid=clean_int(event.pid),
        ppid=clean_int(event.ppid),
        cmdline=clean_text(event.cmdline),
        file_path=clean_text(event.file_path, 4096),
        file_hash=clean_text(event.file_hash, 256),
        src_ip=clean_ip(event.src_ip),
        dst_ip=clean_ip(event.dst_ip),
        src_port=clean_int(event.src_port, 0, 65535),
        dst_port=clean_int(event.dst_port, 0, 65535),
        protocol=clean_text(event.protocol, 32),
        registry_key=clean_text(event.registry_key, 4096),
        source_file=event.source_file,
        source_record_id=clean_text(event.source_record_id, 256),
        ts_original=clean_text(event.ts_original, MAX_SHORT),
        tags=[t for t in (clean_text(x, 128) for x in tags) if t],
        raw=raw,
    )


def to_row(
    event: Event,
    *,
    case_id: str,
    evidence_id: str,
    job_id: str,
    parser_name: str,
    parser_version: str,
) -> tuple[dict[str, Any], int]:
    """Row for ``events`` and its approximate size in bytes (for the output cap)."""
    ts = event.ts
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise NormalizationError("naive timestamp")
    if not event.record_key:
        raise NormalizationError("missing record_key")
    clean = clean_event(event)
    raw, encoded = clean_raw(clean.raw)
    row: dict[str, Any] = {
        "id": event_id(evidence_id, parser_name, event.source_file, event.record_key),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "job_id": job_id,
        "ts": ts.astimezone(UTC),
        "ts_original": clean.ts_original,
        "source_type": clean.source_type,
        "source_file": clean_text(event.source_file, MAX_SHORT),
        "source_record_id": clean.source_record_id,
        "host": clean.host,
        "user": clean.user,
        "event_code": clean.event_code,
        "event_category": clean.event_category,
        "action": clean.action,
        "outcome": clean.outcome,
        "process_name": clean.process_name,
        "pid": clean.pid,
        "ppid": clean.ppid,
        "cmdline": clean.cmdline,
        "file_path": clean.file_path,
        "file_hash": clean.file_hash,
        "src_ip": clean.src_ip,
        "dst_ip": clean.dst_ip,
        "src_port": clean.src_port,
        "dst_port": clean.dst_port,
        "protocol": clean.protocol,
        "registry_key": clean.registry_key,
        "message": clean.message,
        "tags": clean.tags,
        "raw": raw,
        "parser_name": parser_name,
        "parser_version": parser_version,
    }
    size = len(encoded) + len(row["message"]) + len(row["cmdline"] or "") + 256
    return row, size
