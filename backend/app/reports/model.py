"""Report kinds, their editable sections and layout, and the render view shared by all renderers.

A report renders from four stored inputs only: the render ``meta`` (who/when/status, frozen in the
manifest at signing), the snapshot ``context``, the edited ``sections`` and ``findings``. Nothing
here reads the clock, the database or the network, so the same inputs always give the same view
(and the renderers the same bytes).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.reports.seal import json_sha256

KIND_TITLES = {
    "technical": "Technical incident report",
    "executive": "Executive summary",
    "custody": "Evidence and custody report",
    "ioc": "Indicator of compromise package",
}

METHODOLOGY_DEFAULT = (
    "Evidence was received into a write-once vault and hashed (SHA-256 and MD5) while it was "
    "stored; every item was re-hashed and compared before it was processed. Parsers read copies "
    "only and count the records they read against the events they emit. All times in this report "
    "are UTC; the original timestamp strings are kept with each event. The tools, parser versions "
    "and processing runs are listed below, and the chain of custody of every item is verified "
    "(hash chain and Ed25519 signatures) when the report snapshot is taken."
)


@dataclass(frozen=True)
class SectionDef:
    name: str
    title: str
    required: bool = False
    default: str = ""
    ai_draft: bool = True  # the A4 AI draft may be requested for this section


SECTIONS: dict[str, tuple[SectionDef, ...]] = {
    "technical": (
        SectionDef("executive_summary", "Executive summary", required=True),
        SectionDef("scope", "Scope, objectives and authorization", required=True, ai_draft=False),
        SectionDef(
            "methodology", "Methodology", required=True, default=METHODOLOGY_DEFAULT, ai_draft=False
        ),
        SectionDef("affected_assets", "Affected assets and accounts"),
        SectionDef("root_cause", "Root cause and attack path"),
        SectionDef("impact", "Impact assessment"),
        SectionDef("actions", "Containment, eradication and recovery"),
        SectionDef("lessons_learned", "Lessons learned and improvements", ai_draft=False),
        SectionDef("limitations", "Limitations and uncertainties", required=True),
    ),
    "executive": (
        SectionDef("summary", "What happened", required=True),
        SectionDef("impact", "Impact", required=True),
        SectionDef("actions", "Actions taken", required=True),
        SectionDef("decisions", "Decisions needed", ai_draft=False),
    ),
    "custody": (
        SectionDef("scope", "Scope of this report", required=True, ai_draft=False),
        SectionDef(
            "methodology", "Handling and verification", default=METHODOLOGY_DEFAULT, ai_draft=False
        ),
        SectionDef("examiner", "Examiner statement", ai_draft=False),
        SectionDef("limitations", "Limitations", ai_draft=False),
    ),
    "ioc": (
        SectionDef("summary", "Summary", required=True),
        SectionDef("handling", "Handling and sharing guidance", ai_draft=False),
    ),
}

# Order of the rendered parts: ("section", name) = edited text, ("auto", name) = from the snapshot.
LAYOUT: dict[str, tuple[tuple[str, str], ...]] = {
    "technical": (
        ("section", "executive_summary"),
        ("section", "scope"),
        ("section", "methodology"),
        ("auto", "runs"),
        ("auto", "evidence"),
        ("auto", "key_events"),
        ("auto", "findings"),
        ("section", "affected_assets"),
        ("auto", "iocs"),
        ("auto", "attack"),
        ("section", "root_cause"),
        ("section", "impact"),
        ("section", "actions"),
        ("section", "lessons_learned"),
        ("section", "limitations"),
        ("auto", "custody"),
        ("auto", "alerts"),
        ("auto", "provenance"),
    ),
    "executive": (
        ("section", "summary"),
        ("auto", "overview"),
        ("section", "impact"),
        ("section", "actions"),
        ("section", "decisions"),
        ("auto", "provenance"),
    ),
    "custody": (
        ("section", "scope"),
        ("section", "methodology"),
        ("auto", "evidence"),
        ("auto", "custody_full"),
        ("auto", "runs"),
        ("section", "examiner"),
        ("section", "limitations"),
        ("auto", "provenance"),
    ),
    "ioc": (
        ("section", "summary"),
        ("auto", "iocs"),
        ("auto", "attack"),
        ("section", "handling"),
        ("auto", "provenance"),
    ),
}

AUTO_TITLES = {
    "runs": "Tools and processing runs",
    "evidence": "Evidence inventory",
    "key_events": "Timeline of key events",
    "findings": "Findings",
    "iocs": "Indicators of compromise",
    "attack": "MITRE ATT&CK techniques",
    "custody": "Appendix: chain of custody summary",
    "custody_full": "Chain of custody",
    "alerts": "Appendix: alerts",
    "overview": "Key figures",
    "provenance": "Report provenance",
}

CONFIDENCE = ("low", "medium", "high")


def section_def(kind: str, name: str) -> SectionDef | None:
    for sd in SECTIONS.get(kind, ()):
        if sd.name == name:
            return sd
    return None


def default_sections(kind: str) -> dict[str, dict[str, Any]]:
    return {
        sd.name: {"text": sd.default, "origin": "template" if sd.default else "analyst"}
        for sd in SECTIONS[kind]
    }


def content_sha256(
    title: str, sections: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]
) -> str:
    """Hash of everything a person edited (the snapshot has its own hash)."""
    return json_sha256({"title": title, "sections": dict(sections), "findings": list(findings)})


def ai_label(ai: Mapping[str, Any] | None, *, edited: bool = False) -> str | None:
    """The visible AI provenance label of a section or finding."""
    if not ai:
        return None
    text = (
        f"AI-drafted, approved by {ai.get('reviewed_by_label') or 'unknown'} "
        f"on {ai.get('reviewed_at') or '?'} (model {ai.get('model') or '?'}, "
        f"prompt {ai.get('prompt_version') or '?'}, interaction {ai.get('interaction_id') or '?'})"
    )
    if edited:
        text += "; edited by an analyst after approval"
    return text


def build_view(
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The render model: numbered parts in layout order plus the snapshot tables."""
    kind = str(meta["kind"])
    parts: list[dict[str, Any]] = []
    number = 0
    for part_type, name in LAYOUT[kind]:
        if part_type == "section":
            sd = section_def(kind, name)
            if sd is None:
                continue
            stored = sections.get(name) or {}
            text = str(stored.get("text") or "")
            ai = stored.get("ai") if stored.get("origin") in ("ai_approved", "ai_edited") else None
            number += 1
            parts.append(
                {
                    "type": "section",
                    "name": name,
                    "number": number,
                    "title": sd.title,
                    "text": text,
                    "ai_label": ai_label(ai, edited=stored.get("origin") == "ai_edited"),
                }
            )
        else:
            number += 1
            parts.append(
                {"type": "auto", "name": name, "number": number, "title": AUTO_TITLES[name]}
            )
    ai_used = []
    for name, stored in sorted(sections.items()):
        if isinstance(stored, Mapping) and stored.get("ai"):
            ai_used.append({"where": f"section {name}", **dict(stored["ai"])})
    for f in findings:
        if f.get("ai"):
            ai_used.append({"where": f"finding {f.get('title', '')}", **dict(f["ai"])})
    view_findings = []
    for i, f in enumerate(findings, start=1):
        view_findings.append(
            {
                **dict(f),
                "number": i,
                "ai_label": ai_label(f.get("ai"), edited=f.get("origin") == "ai_edited"),
                "source": {
                    "analyst": "Analyst",
                    "ai_approved": "AI-drafted, approved",
                    "ai_edited": "AI-drafted, approved, edited by analyst",
                }.get(str(f.get("origin") or "analyst"), "Analyst"),
            }
        )
    return {
        "meta": dict(meta),
        "kind_title": KIND_TITLES[kind],
        "org": context.get("org", ""),
        "case": context.get("case", {}),
        "generated_at": context.get("generated_at", ""),
        "generated_by": context.get("generated_by", ""),
        "parts": parts,
        "findings": view_findings,
        "evidence": context.get("evidence", []),
        "custody": context.get("custody", []),
        "alerts": context.get("alerts", []),
        "key_events": context.get("key_events", []),
        "iocs": context.get("iocs", []),
        "attack": context.get("attack", []),
        "runs": context.get("runs", []),
        "counts": context.get("counts", {}),
        "truncated": context.get("truncated", {}),
        "input_hashes": context.get("input_hashes", {}),
        "context_sha256": meta.get("context_sha256", ""),
        "content_sha256": meta.get("content_sha256", ""),
        "ai_used": ai_used,
        "ai_outputs": context.get("ai_outputs", []),
    }
