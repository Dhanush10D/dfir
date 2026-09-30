"""Report QA gate: each rule positive and negative."""

from __future__ import annotations

from typing import Any

from app.reports.qa import run_qa
from tests.unit.report_fixtures import EVENT1, sample_context, sample_findings, sample_sections


def codes(result: Any, kind: str = "errors") -> set[str]:
    return {e["code"] for e in getattr(result, kind)}


def test_clean_report_passes() -> None:
    result = run_qa("technical", sample_context(), "Title", sample_sections(), sample_findings())
    assert result.ok, result.errors
    assert "alerts_untriaged" in codes(result, "warnings")
    assert result.as_dict()["ok"] is True


def test_required_sections_and_title() -> None:
    sections = sample_sections()
    sections["executive_summary"] = {"text": "   ", "origin": "analyst"}
    result = run_qa("technical", sample_context(), " ", sections, sample_findings())
    assert {"section_empty", "title_empty"} <= codes(result)
    optional = sample_sections()
    optional["impact"] = {"text": "", "origin": "analyst"}
    assert run_qa("technical", sample_context(), "T", optional, sample_findings()).ok


def test_markers_block_everywhere() -> None:
    for where in ("title", "section", "finding_title", "finding_body"):
        sections, findings, title = sample_sections(), sample_findings(), "Title"
        if where == "title":
            title = "Title TODO"
        elif where == "section":
            sections["scope"] = {"text": "scope TBD later", "origin": "analyst"}
        elif where == "finding_title":
            findings[0]["title"] = "FIXME"
        else:
            findings[0]["body"] = "check XXX"
        result = run_qa("technical", sample_context(), title, sections, findings)
        assert "unresolved_marker" in codes(result), where
    ok = sample_sections()
    ok["scope"] = {"text": "todo list and xxx-large are fine", "origin": "analyst"}
    assert run_qa("technical", sample_context(), "T", ok, sample_findings()).ok


def test_findings_need_existing_evidence() -> None:
    findings = sample_findings()
    findings[0]["refs"] = []
    assert "finding_without_evidence" in codes(
        run_qa("technical", sample_context(), "T", sample_sections(), findings)
    )
    result = run_qa(
        "technical",
        sample_context(),
        "T",
        sample_sections(),
        sample_findings(),
        missing_refs={("event", EVENT1)},
    )
    assert "reference_missing" in codes(result)
    empty = run_qa("technical", sample_context(), "T", sample_sections(), [])
    assert empty.ok and "no_findings" in codes(empty, "warnings")


def test_hashes_and_custody() -> None:
    ctx = sample_context()
    ctx["evidence"][0]["sha256"] = None
    ctx["custody"][0]["ok"] = False
    for kind in ("technical", "custody"):
        result = run_qa(kind, ctx, "T", sample_sections(kind), sample_findings())
        assert {"evidence_hash_missing", "custody_unverified"} <= codes(result), kind
    assert run_qa("executive", ctx, "T", sample_sections("executive"), []).ok
    ctx = sample_context()
    ctx["evidence"][0]["status"] = "uploaded"
    result = run_qa("custody", ctx, "T", sample_sections("custody"), [])
    assert result.ok and "evidence_not_verified" in codes(result, "warnings")


def test_ioc_report_needs_iocs_and_truncation_warns() -> None:
    assert "no_iocs" in codes(
        run_qa("ioc", sample_context(iocs=[]), "T", sample_sections("ioc"), [])
    )
    assert run_qa("ioc", sample_context(), "T", sample_sections("ioc"), []).ok
    ctx = sample_context(truncated={"key_events": True, "alerts": False})
    result = run_qa("technical", ctx, "T", sample_sections(), sample_findings())
    assert "snapshot_truncated" in codes(result, "warnings")


def test_ai_sections_are_flagged() -> None:
    sections = sample_sections()
    sections["impact"] = {"text": "x", "origin": "ai_approved", "ai": {"interaction_id": "i"}}
    result = run_qa("technical", sample_context(), "T", sections, sample_findings())
    assert result.ok and "ai_content" in codes(result, "warnings")
