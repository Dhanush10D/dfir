"""Every built-in rule: compiles, has valid ATT&CK ids, fires on its positive fixture and stays
silent on its negative one; the coverage doc matches the pack; real parser output triggers the
expected rules (golden files of the Phase 2 fixtures)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from app.detection.attack import is_technique
from app.detection.coverage import (
    builtin_rules,
    builtin_texts,
    coverage_rows,
    info,
    render_markdown,
)
from app.detection.detectors import SourceInfo
from app.detection.engine import AlertDraft, DetectionEngine
from app.detection.ioc import IocEntry, IocIndex, normalize
from app.detection.rules import CompiledRule, load_rule
from tests.unit.detection_fixtures import FIXTURES

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
RULES = {r.id: r for r in builtin_rules()}


def run(rule: CompiledRule, spec: dict[str, Any], scenario: str) -> list[AlertDraft]:
    events = spec[scenario]
    iocs = None
    if "iocs" in spec:
        iocs = IocIndex(
            IocEntry(str(i), t, normalize(t, v), 0.9) for i, (t, v) in enumerate(spec["iocs"])
        )
    engine = DetectionEngine([rule], iocs)
    if "source" in spec:
        engine.feed_source(SourceInfo(**spec["source"]), sorted(events, key=lambda e: e["recno"]))
    else:
        for event in sorted(events, key=lambda e: (e["ts"], str(e["id"]))):
            engine.feed(event)
    assert not engine.warnings.get("unordered_input")
    return [d for d in engine.results() if d.rule.id == rule.id]


def test_every_builtin_rule_has_fixtures() -> None:
    assert set(FIXTURES) == set(RULES), set(FIXTURES) ^ set(RULES)
    assert len(RULES) >= 20


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_positive_fixture_fires(rule_id: str) -> None:
    drafts = run(RULES[rule_id], FIXTURES[rule_id], "positive")
    assert drafts, f"{rule_id} did not fire on its positive fixture"
    for draft in drafts:
        assert draft.count >= 1 and draft.refs
        assert draft.first_seen is not None and draft.first_seen <= draft.last_seen  # type: ignore[operator]


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_negative_fixture_is_silent(rule_id: str) -> None:
    assert run(RULES[rule_id], FIXTURES[rule_id], "negative") == []


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_metadata(rule_id: str) -> None:
    rule = RULES[rule_id]
    text = builtin_texts()[rule_id]
    assert rule.id == rule_id
    assert all(is_technique(t) for t in rule.attack)
    assert rule.model.description and rule.model.false_positives
    assert load_rule(text).sha256 == rule.sha256  # deterministic compile


def test_coverage_doc_is_current() -> None:
    expected = render_markdown([info(r) for r in RULES.values()])
    doc = (ROOT / "docs" / "detection-coverage.md").read_text(encoding="utf-8")
    assert doc == expected, "run: python -m app.detection.coverage ../docs/detection-coverage.md"


def test_coverage_rows_from_rules() -> None:
    rows = coverage_rows([info(r) for r in RULES.values()])
    by_tech = {row["technique"]: row for row in rows}
    assert by_tech["T1070.001"]["rules"] == [
        "DFIR-WIN-0001",
        "DFIR-WIN-0002",
        "DFIR-WIN-0027",
        "DFIR-WIN-0030",
    ]
    assert "credential-access" in by_tech["T1110"]["tactics"]  # type: ignore[operator]
    disabled = [info(RULES["DFIR-WIN-0012"], enabled=False)]
    assert coverage_rows(disabled) == []


def _golden_events(name: str) -> list[dict[str, Any]]:
    data = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    events = []
    for index, raw in enumerate(data["events"]):
        event = dict(raw)
        event["id"] = uuid.UUID(event["id"])
        event["ts"] = datetime.fromisoformat(event["ts"])
        rec = event.get("source_record_id")
        event["recno"] = int(rec) if rec and rec.isdigit() else index
        events.append(event)
    return events


@pytest.mark.parametrize(
    ("golden", "expected"),
    [
        ("evtx_new_user_security", {"DFIR-WIN-0008", "DFIR-WIN-0009", "DFIR-WIN-0027"}),
        ("evtx_security_short_selected", {"DFIR-WIN-0027"}),
        (
            "linux_auth_utc",
            {"DFIR-LNX-0004", "DFIR-LNX-0011", "DFIR-AF-0001", "DFIR-AF-0002"},
        ),
    ],
)
def test_real_parser_output_triggers_expected_rules(golden: str, expected: set[str]) -> None:
    events = _golden_events(golden)
    engine = DetectionEngine(list(RULES.values()))
    for event in sorted(events, key=lambda e: (e["ts"], str(e["id"]))):
        engine.feed(event)
    engine.feed_source(SourceInfo("golden", golden), sorted(events, key=lambda e: e["recno"]))
    fired = {d.rule.id for d in engine.results()}
    assert fired == expected
    # Idempotent: a second engine over the same events yields identical dedup keys and links.
    again = DetectionEngine(list(RULES.values()))
    for event in sorted(events, key=lambda e: (e["ts"], str(e["id"]))):
        again.feed(event)
    again.feed_source(SourceInfo("golden", golden), sorted(events, key=lambda e: e["recno"]))
    assert [(d.dedup_key, d.refs, d.count) for d in again.results()] == [
        (d.dedup_key, d.refs, d.count) for d in engine.results()
    ]
