"""Sigma -> dfirbench rule conversion for a documented subset (guide 11.3 item 7).

Supported (everything else is **rejected** with a list of the unsupported features, never
silently approximated):

* metadata: ``title id status description author references tags level falsepositives date
  modified license related fields`` (``tags: attack.tNNNN[.NNN]`` become ATT&CK ids; tactic tags
  are dropped);
* ``logsource``: ``product: windows`` with ``service: security|system|sysmon|powershell`` or
  ``category: process_creation|ps_script``; ``product: linux`` with ``service: auth|sshd``;
* ``detection``: named selections (mapping, or list of mappings = OR), ``condition`` with
  ``and/or/not``, parentheses, ``1 of``/``any of``/``all of`` ``<prefix>*``/``them``;
* values: strings (``*``/``?`` wildcards, ``\\`` escapes), numbers, ``null``, lists;
* modifiers: ``contains startswith endswith all re cidr gt gte lt lte exists``.

Rejected: keyword (full-text) selections, aggregations (``| count() ...``), ``near``,
``timeframe``, correlation rules, modifiers such as ``base64``/``base64offset``/``utf16*``/
``wide``/``windash``/``cased``/``expand``/``fieldref``, regexes RE2 cannot run (backreferences,
lookaround), fields without a mapping for non-Windows sources, and unknown logsources.

Field mapping (Windows): see ``WINDOWS_FIELDS``; any other Windows field name maps to
``raw.event_data.<Name>`` (the EVTX ``EventData``), which is exactly where the value lives.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any

import yaml

from app.detection.rules import RuleError, compile_rule
from app.detection.yamlsafe import YamlInputError, safe_yaml

META_KEYS = frozenset(
    {
        "title",
        "id",
        "status",
        "description",
        "author",
        "references",
        "tags",
        "level",
        "falsepositives",
        "date",
        "modified",
        "license",
        "related",
        "fields",
        "logsource",
        "detection",
        "name",
        "taxonomy",
    }
)
LEVELS = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
STATUS = {
    "stable": "stable",
    "test": "test",
    "experimental": "experimental",
    "deprecated": "deprecated",
}
SUPPORTED_MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "all", "re", "cidr", "gt", "gte", "lt", "lte", "exists"}
)
WINDOWS_FIELDS = {
    "EventID": "event_code",
    "Channel": "raw.system.channel",
    "Provider_Name": "raw.system.provider",
    "Computer": "host",
    "CommandLine": "cmdline",
    "Image": "file_path",
    "NewProcessName": "file_path",
    "ParentImage": "raw.normalized.parent_process",
    "ParentProcessName": "raw.normalized.parent_process",
    "User": "user",
    "ProcessId": "pid",
    "ParentProcessId": "ppid",
    "IpAddress": "src_ip",
    "SourceIp": "src_ip",
    "SourceAddress": "src_ip",
    "DestinationIp": "dst_ip",
    "DestAddress": "dst_ip",
    "SourcePort": "src_port",
    "IpPort": "src_port",
    "DestinationPort": "dst_port",
    "DestPort": "dst_port",
    "TargetFilename": "file_path",
    "ImagePath": "file_path",
    "ServiceFileName": "file_path",
    "ScriptBlockText": "cmdline",
    "TargetObject": "registry_key",
    "LogonType": "raw.normalized.logon_type",
}
LINUX_FIELDS = {
    "user": "user",
    "User": "user",
    "src_ip": "src_ip",
    "SourceIp": "src_ip",
    "host": "host",
    "Computer": "host",
    "message": "message",
    "program": "process_name",
    "pid": "pid",
}
EVENT_DATA_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
ATTACK_TAG = re.compile(r"^attack\.(t[0-9]{4}(?:\.[0-9]{3})?)$")
NAMESPACE = uuid.UUID("0b8f9e8a-6a55-4f39-9a6d-8f5c2f7b1c11")


class SigmaError(RuleError):
    """Conversion refused; ``errors`` lists every unsupported feature found."""


def _logsource(ls: Any, problems: list[str]) -> tuple[dict[str, Any], str]:
    if not isinstance(ls, Mapping):
        problems.append("logsource must be a mapping")
        return {}, "windows"
    extra = set(ls) - {"product", "service", "category", "definition"}
    if extra:
        problems.append(f"logsource keys not supported: {sorted(extra)}")
    product = str(ls.get("product") or "").lower()
    service = str(ls.get("service") or "").lower()
    category = str(ls.get("category") or "").lower()
    if product == "windows":
        if category and service:
            problems.append("logsource with both category and service is not supported")
        channels = {
            "security": "Security",
            "system": "System",
            "sysmon": "Microsoft-Windows-Sysmon/Operational",
            "powershell": "Microsoft-Windows-PowerShell/Operational",
        }
        if service in channels:
            return {"source_type": "evtx", "channel": channels[service]}, "windows"
        if category == "process_creation":
            return {"source_type": "evtx", "event_category": "process", "action": "create"}, (
                "windows"
            )
        if category == "ps_script":
            return {
                "source_type": "evtx",
                "event_category": "process",
                "action": "script_block",
            }, "windows"
        problems.append(f"unsupported Windows logsource service={service!r} category={category!r}")
        return {}, "windows"
    if product == "linux" and service in ("auth", "sshd") and not category:
        return {"source_type": ["auth_log", "syslog"]}, "linux"
    problems.append(
        f"unsupported logsource product={product!r} service={service!r} category={category!r}"
    )
    return {}, product or "unknown"


def _unescape_plain(value: str) -> tuple[str, bool]:
    """(literal text, has_wildcards) following Sigma's escaping (``\\*``, ``\\?``, ``\\\\``)."""
    out = []
    wild = False
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(value[i + 1])
            i += 2
            continue
        if ch in "*?":
            wild = True
        out.append(ch)
        i += 1
    return "".join(out), wild


def _glob_regex(value: str, anchor_start: bool, anchor_end: bool) -> str:
    parts = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            parts.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
        i += 1
    body = "".join(parts)
    return "(?is)" + ("^" if anchor_start else "") + body + ("$" if anchor_end else "")


def _convert_field(
    key: str, value: Any, product: str, problems: list[str]
) -> tuple[str, Any] | None:
    name, *mods = key.split("|")
    unsupported = [m for m in mods if m not in SUPPORTED_MODIFIERS]
    if unsupported:
        problems.append(f"field {key!r}: unsupported modifiers {unsupported}")
        return None
    if product == "windows":
        target = WINDOWS_FIELDS.get(name)
        if target is None:
            if not EVENT_DATA_NAME.fullmatch(name):
                problems.append(f"field {name!r} cannot be mapped")
                return None
            target = f"raw.event_data.{name}"
    else:
        target = LINUX_FIELDS.get(name)
        if target is None:
            problems.append(f"field {name!r} has no mapping for {product} sources")
            return None
    values = value if isinstance(value, list) else [value]
    for v in values:
        if isinstance(v, dict | list):
            problems.append(f"field {key!r}: nested values are not supported")
            return None
    operators = [m for m in mods if m not in ("all",)]
    quant = ["all"] if "all" in mods else []
    op = operators[0] if operators else "eq"
    if len(operators) > 1:
        problems.append(f"field {key!r}: more than one operator modifier")
        return None
    if op in ("re", "cidr", "gt", "gte", "lt", "lte", "exists"):
        return "|".join([target, op, *quant]), value
    converted: list[Any] = []
    need_regex = False
    for v in values:
        if isinstance(v, str):
            _, wild = _unescape_plain(v)
            need_regex = need_regex or wild
    if not need_regex:
        for v in values:
            if isinstance(v, str):
                converted.append(_unescape_plain(v)[0])
            elif isinstance(v, bool):
                problems.append(f"field {key!r}: boolean values are not supported")
                return None
            elif v is None:
                if op != "eq":
                    problems.append(f"field {key!r}: null only works with plain equality")
                    return None
                converted.append(None)
            else:
                converted.append(str(v) if target == "event_code" else v)
        spec = target if op == "eq" else f"{target}|{op}"
        out_value: Any = converted if isinstance(value, list) else converted[0]
        return "|".join([spec, *quant]), out_value
    for v in values:
        if not isinstance(v, str):
            v = str(v)
        converted.append(
            _glob_regex(
                v, anchor_start=op in ("eq", "startswith"), anchor_end=op in ("eq", "endswith")
            )
        )
    return "|".join([target, "re", *quant]), converted if isinstance(value, list) else converted[0]


def _selection(name: str, spec: Any, product: str, problems: list[str]) -> Any:
    if isinstance(spec, list):
        if all(isinstance(item, Mapping) for item in spec) and spec:
            groups = [
                _selection(f"{name}[{i}]", item, product, problems) for i, item in enumerate(spec)
            ]
            return [g for g in groups if g]
        problems.append(f"selection {name!r}: keyword (full-text) lists are not supported")
        return None
    if not isinstance(spec, Mapping) or not spec:
        problems.append(f"selection {name!r}: keyword or empty selections are not supported")
        return None
    out: dict[str, Any] = {}
    for key, value in spec.items():
        converted = _convert_field(str(key), value, product, problems)
        if converted is None:
            continue
        field_spec, field_value = converted
        if field_spec in out:
            problems.append(f"selection {name!r}: two conditions map to {field_spec!r}")
            continue
        out[field_spec] = field_value
    return out


def convert(text: str, rule_id: str | None = None) -> tuple[dict[str, Any], str, list[str]]:
    """Return ``(rule dict, native YAML, notes)``; raise :class:`SigmaError` when unsupported."""
    try:
        data = safe_yaml(text, max_bytes=128 * 1024)
    except YamlInputError as exc:
        raise SigmaError(str(exc)) from exc
    if not isinstance(data, Mapping):
        raise SigmaError("a Sigma rule must be a YAML mapping (one document)")
    problems: list[str] = []
    notes: list[str] = []
    unknown = sorted(set(data) - META_KEYS)
    if unknown:
        problems.append(f"unsupported top-level keys: {unknown}")
    if "correlation" in data or data.get("type") == "correlation":
        problems.append("correlation rules are not supported")
    title = data.get("title")
    if not isinstance(title, str) or not title.strip():
        problems.append("title is required")
    sigma_id = data.get("id")
    try:
        sid = uuid.UUID(str(sigma_id)) if sigma_id else None
    except ValueError:
        problems.append("id must be a UUID")
        sid = None
    level = LEVELS.get(str(data.get("level") or "medium").lower())
    if level is None:
        problems.append(f"unsupported level {data.get('level')!r}")
    status = STATUS.get(str(data.get("status") or "experimental").lower())
    if status is None:
        problems.append(f"unsupported status {data.get('status')!r}")
    attack: list[str] = []
    for tag in data.get("tags") or []:
        m = ATTACK_TAG.fullmatch(str(tag).lower())
        if m:
            attack.append(m.group(1).upper())
    logsource, product = _logsource(data.get("logsource"), problems)
    detection = data.get("detection")
    native_det: dict[str, Any] = {}
    if not isinstance(detection, Mapping):
        problems.append("detection must be a mapping")
    else:
        for key, value in detection.items():
            if key == "condition":
                continue
            if key == "timeframe":
                problems.append("timeframe/aggregations are not supported")
                continue
            if key in ("sequence", "group_by", "threshold", "join_on", "within", "detector"):
                problems.append(f"detection key {key!r} is not Sigma")
                continue
            converted = _selection(str(key), value, product, problems)
            if converted:
                native_det[str(key)] = converted
        condition = detection.get("condition")
        if isinstance(condition, list):
            if len(condition) != 1:
                problems.append("multiple conditions are not supported")
                condition = None
            else:
                condition = condition[0]
        if not isinstance(condition, str):
            problems.append("condition must be a string")
        else:
            if "|" in condition:
                problems.append("aggregations in the condition ('| count() ...') are not supported")
            if re.search(r"\bnear\b", condition):
                problems.append("'near' is not supported")
            native_det["condition"] = re.sub(r"\bany of\b", "1 of", condition)
    if problems:
        raise SigmaError("Sigma rule uses unsupported features", problems)
    if rule_id is None:
        base = sid or uuid.uuid5(NAMESPACE, text)
        rule_id = f"SIGMA-{base.hex[:12].upper()}"
    rule: dict[str, Any] = {
        "id": rule_id,
        "title": str(title).strip()[:200],
        "status": status,
        "level": level,
        "attack": sorted(set(attack)),
        "logsource": logsource,
        "detection": native_det,
    }
    if isinstance(data.get("description"), str):
        rule["description"] = data["description"][:4000]
    if isinstance(data.get("author"), str):
        rule["author"] = data["author"][:200]
    refs = [str(r)[:500] for r in data.get("references") or [] if isinstance(r, str)][:20]
    if refs:
        rule["references"] = refs
    fps = [str(r)[:500] for r in data.get("falsepositives") or [] if isinstance(r, str)][:20]
    if fps:
        rule["false_positives"] = fps
    if sid is not None:
        rule["origin_ref"] = f"sigma:{sid}"
    if product == "windows" and logsource.get("event_category") == "process":
        notes.append(
            "process_creation maps to 4688 and Sysmon 1 (event_category=process, action=create)"
        )
    native = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=100)
    try:
        compile_rule(rule, native)
    except RuleError as exc:
        raise SigmaError("converted rule is not valid", exc.errors) from exc
    return rule, native, notes
