"""Output validation (guide 13.5): schema first, then citations, then claim support.

* :func:`parse_output`: one JSON object (a single fenced block is tolerated), validated with the
  feature's Pydantic model (extra keys forbidden, caps enforced).
* :func:`check_citations`: every ``cites`` id must be a record of this pack (invented ids are
  rejected); statements in the feature's required lists must cite at least one record; IPs,
  hashes, URLs and domains named in a statement must occur in the records it cites (otherwise an
  ``unsupported_claim`` warning; top-level texts are checked against the whole pack).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

MAX_OUTPUT_CHARS = 512 * 1024
FENCE_RE = re.compile(r"^```(?:json|JSON)?\s*\n(.*)\n```\s*$", re.DOTALL)
CLAIM_TOKEN_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # IPv4
    r"|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b"  # sha256/sha1/md5
    r"|\bhttps?://[^\s\"'<>]{3,300}"  # URLs
)
TEXT_KEYS = ("statement", "description", "rationale", "action", "why")
TOP_LEVEL_TEXT = ("summary", "answer")


@dataclass
class CitationReport:
    cited: list[str] = field(default_factory=list)
    invalid_ids: list[str] = field(default_factory=list)
    uncited: list[str] = field(default_factory=list)  # paths of statements without citations
    unsupported: list[dict[str, Any]] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.invalid_ids and not self.uncited

    def problems(self) -> list[str]:
        out: list[str] = []
        if self.invalid_ids:
            out.append(
                "these cited ids are not in the evidence block: " + ", ".join(self.invalid_ids)
            )
        if self.uncited:
            out.append("these entries need at least one citation: " + ", ".join(self.uncited))
        return out


def parse_output[M: BaseModel](text: str, model: type[M]) -> tuple[M | None, list[str]]:
    """Parse and validate provider text. Returns ``(obj, [])`` or ``(None, problems)``."""
    if len(text) > MAX_OUTPUT_CHARS:
        return None, ["reply is too long"]
    body = text.strip()
    fenced = FENCE_RE.match(body)
    if fenced:
        body = fenced.group(1).strip()
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, RecursionError):
        return None, ["reply is not a single valid JSON object"]
    if not isinstance(data, dict):
        return None, ["reply must be a JSON object"]
    try:
        return model.model_validate(data), []
    except ValidationError as exc:
        problems = []
        for err in exc.errors()[:10]:
            loc = ".".join(str(p) for p in err["loc"]) or "(root)"
            problems.append(f"{loc}: {err['msg']}")
        return None, problems


def collect_cites(obj: Any, path: str = "") -> list[tuple[str, list[str]]]:
    """(path, cites) for every ``cites`` list in nested output."""
    found: list[tuple[str, list[str]]] = []
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else str(k)
            if k == "cites" and isinstance(v, list):
                found.append((path, [str(c) for c in v]))
            else:
                found.extend(collect_cites(v, sub))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(collect_cites(v, f"{path}[{i}]"))
    return found


def claim_tokens(text: str) -> set[str]:
    return {t.rstrip(".,;:)") for t in CLAIM_TOKEN_RE.findall(text or "")}


def _norm(text: str) -> str:
    return text.lower().replace("[.]", ".").replace("hxxp", "http")


def check_citations(
    data: Mapping[str, Any],
    record_text: Mapping[str, str],
    *,
    required: Iterable[str] = (),
    indicator_lists: Iterable[str] = (),
) -> CitationReport:
    """Validate citations of ``data`` against the pack.

    ``record_text`` maps each short id of the pack to the text the model saw for it.
    ``required``: top-level list fields whose every item must cite at least one record.
    ``indicator_lists``: list fields of ``{"value", "cites"}`` whose value must occur in the
    cited records.
    """
    report = CitationReport()
    allowed = set(record_text)
    cited: set[str] = set()
    for _path, cites in collect_cites(data):
        for c in cites:
            cited.add(c)
            if c not in allowed:
                report.invalid_ids.append(c)
    report.invalid_ids = sorted(set(report.invalid_ids))
    report.cited = sorted(cited & allowed)

    for name in required:
        for i, item in enumerate(data.get(name) or []):
            if isinstance(item, Mapping) and not item.get("cites"):
                report.uncited.append(f"{name}[{i}]")

    all_text = _norm("\n".join(record_text.values()))

    def cited_text(cites: Iterable[str]) -> str:
        return _norm("\n".join(record_text.get(c, "") for c in cites))

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, Mapping):
            cites = [str(c) for c in obj.get("cites") or []]
            scope = cited_text(cites) if cites else all_text
            for key in TEXT_KEYS:
                value = obj.get(key)
                if isinstance(value, str):
                    missing = sorted(t for t in claim_tokens(value) if _norm(t) not in scope)
                    if missing:
                        report.unsupported.append({"path": f"{path}.{key}", "tokens": missing})
            for k, v in obj.items():
                if isinstance(v, list | Mapping):
                    walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{path}[{i}]")

    walk(data, "")
    for key in TOP_LEVEL_TEXT:
        value = data.get(key)
        if isinstance(value, str):
            missing = sorted(t for t in claim_tokens(value) if _norm(t) not in all_text)
            if missing:
                report.unsupported.append({"path": key, "tokens": missing})
    for name in indicator_lists:
        for i, item in enumerate(data.get(name) or []):
            if not isinstance(item, Mapping):
                continue
            value = str(item.get("value") or "")
            scope = cited_text([str(c) for c in item.get("cites") or []])
            if value and _norm(value) not in scope:
                report.unsupported.append({"path": f"{name}[{i}].value", "tokens": [value]})
    return report
