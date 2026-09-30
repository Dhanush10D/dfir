"""Machine-readable report artifacts: STIX 2.1 bundle, CSV (formula-safe) and JSON.

All exports are pure functions of the snapshot (and report metadata), with deterministic ids
(UUIDv5) and timestamps taken from the snapshot, so they re-render byte for byte.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from app.core.csvsafe import csv_cell

# UUIDv5 namespace for dfirbench STIX objects (fixed; changing it changes every generated id).
STIX_NAMESPACE = uuid.UUID("5d0f9d1e-6b8e-5c61-9d6c-2f7f3c1a8e40")
# TLP 1.0 marking definitions predefined by STIX 2.1 (section 7.2.1.4).
TLP_MARKINGS = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
# TLP 2.0 values mapped to TLP 1.0 markings; AMBER+STRICT maps to the more restrictive RED.
TLP_MAP = {
    "clear": "white",
    "white": "white",
    "green": "green",
    "amber": "amber",
    "amber+strict": "red",
    "red": "red",
}
TLP_ORDER = ("white", "green", "amber", "red")
HASH_KEYS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}

IOC_COLUMNS = ("type", "value", "tlp", "confidence", "source", "first_seen", "active", "scope")
TIMELINE_COLUMNS = (
    "ts",
    "ts_original",
    "host",
    "user",
    "source_type",
    "event_code",
    "summary",
    "process_name",
    "cmdline",
    "file_path",
    "src_ip",
    "dst_ip",
    "evidence_label",
    "reasons",
    "id",
)


def _sid(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, '|'.join((kind, *parts)))}"


def stix_ts(value: str | None) -> str:
    """STIX timestamp (UTC, millisecond precision, ``Z``) from an ISO string in the snapshot."""
    if not value:
        value = "1970-01-01T00:00:00Z"
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _quote(value: str) -> str:
    """A STIX pattern string literal (backslash and quote escaped)."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def stix_pattern(ioc_type: str, value: str) -> str | None:
    if ioc_type == "ip":
        kind = "ipv6-addr" if ":" in value else "ipv4-addr"
        return f"[{kind}:value = {_quote(value)}]"
    if ioc_type == "domain":
        return f"[domain-name:value = {_quote(value)}]"
    if ioc_type == "url":
        return f"[url:value = {_quote(value)}]"
    if ioc_type in HASH_KEYS:
        return f"[file:hashes.'{HASH_KEYS[ioc_type]}' = {_quote(value)}]"
    if ioc_type == "email":
        return f"[email-addr:value = {_quote(value)}]"
    if ioc_type == "filename":
        return f"[file:name = {_quote(value)}]"
    return None


def _tlp(value: str | None) -> str:
    return TLP_MAP.get((value or "amber").lower(), "amber")


def _confidence(value: Any) -> int | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, round(number * 100)))


def stix_bundle(context: Mapping[str, Any], meta: Mapping[str, Any]) -> dict[str, Any]:
    """A STIX 2.1 bundle: identity, one indicator per active IOC, attack-patterns, one report."""
    report_id = str(meta["report_id"])
    created = stix_ts(str(context.get("generated_at") or ""))
    org = str(context.get("org") or "dfirbench")
    case = context.get("case") or {}
    identity_id = _sid("identity", org)
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": org,
            "identity_class": "organization",
        }
    ]
    highest = 0
    for ioc in context.get("iocs") or []:
        if not ioc.get("active", True):
            continue
        pattern = stix_pattern(str(ioc.get("type")), str(ioc.get("value")))
        if pattern is None:
            continue
        tlp = _tlp(ioc.get("tlp"))
        highest = max(highest, TLP_ORDER.index(tlp))
        valid_from = stix_ts(ioc.get("first_seen") or context.get("generated_at"))
        obj: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _sid("indicator", report_id, str(ioc.get("id"))),
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "name": f"{ioc.get('type')}: {str(ioc.get('value'))[:200]}",
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": valid_from,
            "object_marking_refs": [TLP_MARKINGS[tlp]],
        }
        confidence = _confidence(ioc.get("confidence"))
        if confidence is not None:
            obj["confidence"] = confidence
        if (ioc.get("tlp") or "").lower() == "amber+strict":
            obj["description"] = "Shared as TLP:AMBER+STRICT (mapped to the TLP 1.0 RED marking)."
        objects.append(obj)
    for tech in context.get("attack") or []:
        tid = str(tech.get("technique"))
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": _sid("attack-pattern", report_id, tid),
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "name": tid,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
                    }
                ],
            }
        )
    refs = [o["id"] for o in objects]
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": _sid("report", report_id),
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "name": f"{case.get('case_number')}: {str(case.get('title') or '')[:200]}",
            "report_types": ["incident"],
            "published": stix_ts(str(meta.get("signed_at") or context.get("generated_at") or "")),
            "object_refs": refs,
            "object_marking_refs": [TLP_MARKINGS[TLP_ORDER[max(highest, 2)]]],
        }
    )
    return {"type": "bundle", "id": _sid("bundle", report_id), "objects": objects}


def stix_json(context: Mapping[str, Any], meta: Mapping[str, Any]) -> bytes:
    return (json.dumps(stix_bundle(context, meta), indent=2, ensure_ascii=False) + "\n").encode()


def _csv(columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([csv_cell(row.get(c)) for c in columns])
    return buffer.getvalue().encode("utf-8")


def iocs_csv(context: Mapping[str, Any]) -> bytes:
    rows = [
        {**ioc, "scope": "global" if ioc.get("global") else "case"}
        for ioc in context.get("iocs") or []
    ]
    return _csv(IOC_COLUMNS, rows)


def timeline_csv(context: Mapping[str, Any]) -> bytes:
    return _csv(TIMELINE_COLUMNS, list(context.get("key_events") or []))


def pretty_json(obj: Any) -> bytes:
    return (
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
    ).encode("utf-8")


def report_json(
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> bytes:
    return pretty_json(
        {
            "schema": "dfirbench.report/1",
            "meta": dict(meta),
            "sections": dict(sections),
            "findings": list(findings),
            "context": dict(context),
        }
    )


def custody_json(context: Mapping[str, Any]) -> bytes:
    return pretty_json(
        {
            "schema": "dfirbench.custody-report/1",
            "case": context.get("case"),
            "generated_at": context.get("generated_at"),
            "evidence": context.get("evidence"),
            "custody": context.get("custody"),
        }
    )
