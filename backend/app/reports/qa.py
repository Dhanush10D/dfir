"""Deterministic report QA gate (guide 18.3 step 4). Submission needs a run without errors.

Errors block submission; warnings are shown to the author and the approver. The check is pure:
the caller passes the references that no longer exist in the case (``missing_refs``).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.reports.model import SECTIONS

MARKER_RE = re.compile(r"\b(TODO|TBD|FIXME|XXX)\b")
HASH_KINDS = frozenset({"technical", "custody"})


@dataclass
class QaResult:
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def error(self, code: str, message: str, where: str = "") -> None:
        self.errors.append({"code": code, "message": message, "where": where})

    def warn(self, code: str, message: str, where: str = "") -> None:
        self.warnings.append({"code": code, "message": message, "where": where})

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": self.errors, "warnings": self.warnings}


def _markers(result: QaResult, text: str, where: str) -> None:
    found = sorted(set(MARKER_RE.findall(text or "")))
    if found:
        result.error(
            "unresolved_marker", f"Unresolved marker(s) {', '.join(found)} in the text.", where
        )


def run_qa(
    kind: str,
    context: Mapping[str, Any],
    title: str,
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    missing_refs: Collection[tuple[str, str]] = (),
) -> QaResult:
    result = QaResult()
    if not title.strip():
        result.error("title_empty", "The report has no title.", "title")
    _markers(result, title, "title")
    for sd in SECTIONS[kind]:
        stored = sections.get(sd.name) or {}
        text = str(stored.get("text") or "")
        if sd.required and not text.strip():
            result.error("section_empty", f"Required section '{sd.title}' is empty.", sd.name)
        _markers(result, text, sd.name)
        if stored.get("origin") in ("ai_approved", "ai_edited"):
            result.warn(
                "ai_content", f"Section '{sd.title}' contains approved AI-drafted text.", sd.name
            )
    missing = set(missing_refs)
    for i, f in enumerate(findings, start=1):
        where = f"finding {i}"
        _markers(result, str(f.get("title") or ""), where)
        _markers(result, str(f.get("body") or ""), where)
        refs = f.get("refs") or []
        if not refs:
            result.error(
                "finding_without_evidence",
                f"Finding {i} ('{str(f.get('title') or '')[:80]}') cites no evidence.",
                where,
            )
        for ref in refs:
            if (str(ref.get("type")), str(ref.get("id"))) in missing:
                result.error(
                    "reference_missing",
                    f"Finding {i} cites {ref.get('type')} {ref.get('id')}, which no longer "
                    "exists in the case.",
                    where,
                )
    if kind == "technical" and not findings:
        result.warn("no_findings", "The technical report has no findings.")
    if kind in HASH_KINDS:
        for ev in context.get("evidence") or []:
            if not ev.get("sha256"):
                result.error(
                    "evidence_hash_missing",
                    f"Evidence {ev.get('label')} has no SHA-256.",
                    f"evidence {ev.get('label')}",
                )
            elif ev.get("status") != "stored":
                result.warn(
                    "evidence_not_verified",
                    f"Evidence {ev.get('label')} is '{ev.get('status')}', not verified and stored.",
                    f"evidence {ev.get('label')}",
                )
        for chain in context.get("custody") or []:
            if not chain.get("ok"):
                result.error(
                    "custody_unverified",
                    f"The custody chain of {chain.get('label')} does not verify.",
                    f"custody {chain.get('label')}",
                )
    if kind == "ioc" and not [i for i in context.get("iocs") or [] if i.get("active", True)]:
        result.error("no_iocs", "The IOC package contains no active indicators.")
    new_alerts = [a for a in context.get("alerts") or [] if a.get("status") == "new"]
    if new_alerts and kind in ("technical", "executive"):
        result.warn("alerts_untriaged", f"{len(new_alerts)} alert(s) in the snapshot are 'new'.")
    truncated = sorted(k for k, v in (context.get("truncated") or {}).items() if v)
    if truncated:
        result.warn(
            "snapshot_truncated", "The snapshot was truncated: " + ", ".join(truncated) + "."
        )
    return result
