"""Detection engine units: hostile rule input, matchers, conditions, bounds, Sigma subset, IOCs,
scoring, and the post-parse trigger (no Docker)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.detection import sigma
from app.detection.engine import DetectionEngine, EngineLimits, bucket_start, dedup_key
from app.detection.ioc import (
    IocEntry,
    IocError,
    IocIndex,
    normalize,
    parse_csv,
    parse_json,
    parse_stix,
)
from app.detection.rules import RuleError, load_rule, parse_condition
from app.detection.scoring import ScoredAlert, alert_risk, case_risk, host_risk, summarize
from app.detection.yamlsafe import YamlInputError, safe_yaml
from app.services.processing import RunResult
from app.workers.tasks import parse as parse_task

T0 = datetime(2026, 1, 1, tzinfo=UTC)

BASE = """id: TEST-RULE-0001
title: t
level: low
detection:
  selection: {selection}
  condition: selection
"""


def rule(selection: str, **extra: str) -> Any:
    text = BASE.format(selection=selection)
    for key, value in extra.items():
        text += f"{key}: {value}\n"
    return load_rule(text)


def ev(minutes: float = 0, **fields: Any) -> dict[str, Any]:
    return {"id": uuid.uuid4(), "ts": T0 + timedelta(minutes=minutes), "host": "h1", **fields}


def fire(r: Any, events: list[dict[str, Any]], limits: EngineLimits | None = None) -> Any:
    engine = DetectionEngine([r], limits=limits)
    for e in sorted(events, key=lambda e: (e["ts"], str(e["id"]))):
        engine.feed(e)
    return engine


# ---------------------------------------------------------------------------------- hostile YAML


@pytest.mark.parametrize(
    "text",
    [
        "a: &x [1, 2]\nb: *x\n",  # alias (billion laughs building block)
        "!!python/object/apply:os.system ['echo pwned']",
        "a: [" * 40 + "]" * 40,  # nesting
        "x: " + "y" * (300 * 1024),  # size
        "a: 1\n---\nb: 2\n",  # multiple documents
        "a: [unclosed",
    ],
    ids=["alias", "python-tag", "nesting", "size", "multi-doc", "syntax"],
)
def test_safe_yaml_rejects_hostile_input(text: str) -> None:
    with pytest.raises(YamlInputError):
        safe_yaml(text)


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (BASE.format(selection="{event_code: '1'}") + "surprise: 1\n", "surprise"),
        (BASE.format(selection="{nope_field: '1'}"), "unknown field"),
        (BASE.format(selection="{'cmdline|base64': 'x'}"), "unsupported modifier"),
        (BASE.format(selection="{'cmdline|re': '(a)\\1'}"), "RE2"),
        (BASE.format(selection="{'cmdline|re': '(?<=a)b'}"), "RE2"),
        (BASE.format(selection="{'cmdline|re': '" + "a" * 600 + "'}"), "longer than"),
        (BASE.format(selection="{'src_ip|cidr': 'not-a-net'}"), "network"),
        (BASE.format(selection="{'pid|gt': 'x'}"), "number"),
        (BASE.format(selection="[evil, keywords]"), "keyword"),
        (
            BASE.format(selection="{event_code: '1'}").replace("id: TEST-RULE-0001", "id: bad id"),
            "id",
        ),
        (BASE.format(selection="{event_code: '1'}") + "attack: [T12]\n", "ATT&CK"),
        (
            BASE.format(selection="{event_code: '1'}").replace(
                "condition: selection", "condition: selection | count() > 3"
            ),
            "aggregation",
        ),
        (
            BASE.format(selection="{event_code: '1'}").replace(
                "condition: selection", "condition: other"
            ),
            "unknown selection",
        ),
    ],
)
def test_rule_validation_rejects(text: str, needle: str) -> None:
    with pytest.raises(RuleError) as info:
        load_rule(text)
    assert needle.lower() in " ".join(info.value.errors).lower() + str(info.value).lower()


def test_threshold_and_sequence_bounds() -> None:
    bad_threshold = BASE.format(selection="{event_code: '1'}").replace(
        "condition: selection", "condition: selection\n  threshold: {count: 10, window: 30d}"
    )
    with pytest.raises(RuleError, match="window"):
        load_rule(bad_threshold)
    bad_count = bad_threshold.replace("count: 10, window: 30d", "count: 1000000, window: 5m")
    with pytest.raises(RuleError, match="count"):
        load_rule(bad_count)
    seq = """id: TEST-SEQ-0001
title: s
level: low
detection:
  sequence:
    - {match: {event_code: a}}
    - {match: {event_code: b}}
  join_on: [host]
  within: 8d
"""
    with pytest.raises(RuleError, match="within"):
        load_rule(seq)


def test_condition_grammar() -> None:
    names = ["sel_a", "sel_b", "filter"]
    assert parse_condition("1 of sel_* and not filter", names)
    assert parse_condition("all of them", names)
    with pytest.raises(RuleError):
        parse_condition("sel_a and (sel_b", names)
    with pytest.raises(RuleError):
        parse_condition("not " * 40 + "sel_a", names)
    with pytest.raises(RuleError):
        parse_condition("1 of nothing_*", names)


# ---------------------------------------------------------------------------------- matchers


def test_matchers_are_case_insensitive_and_typed() -> None:
    r = rule(
        "{'cmdline|contains|all': [VSSADMIN, delete], 'src_ip|cidr': 10.0.0.0/8, 'pid|gte': 100}"
    )
    good = ev(cmdline="vssadmin Delete shadows", src_ip="10.1.2.3", pid=4242)
    assert fire(r, [good]).drafts
    assert not fire(r, [ev(cmdline="vssadmin list", src_ip="10.1.2.3", pid=4242)]).drafts
    assert not fire(r, [ev(cmdline="vssadmin delete", src_ip="192.0.2.1", pid=4242)]).drafts
    assert not fire(r, [ev(cmdline="vssadmin delete", src_ip="10.0.0.1", pid=5)]).drafts
    nulls = rule("{user: null, 'host|exists': true}")
    assert fire(nulls, [ev()]).drafts and not fire(nulls, [ev(user="bob")]).drafts


def test_regex_is_linear_time() -> None:
    r = rule("{'cmdline|re': '(a+)+$'}")
    engine = fire(r, [ev(cmdline="a" * 30000 + "!")])  # catastrophic for backtracking engines
    assert not engine.drafts


def test_dedup_key_is_deterministic_and_bucketed() -> None:
    r = rule("{event_code: x}")
    engine = fire(r, [ev(0, event_code="x"), ev(60, event_code="x"), ev(60 * 25, event_code="x")])
    drafts = engine.results()
    assert [d.count for d in drafts] == [1, 2] or [d.count for d in drafts] == [2, 1]
    assert len(drafts) == 2  # day buckets
    key = dedup_key("R-X", {"host": "h1"}, bucket_start(T0, 86400))
    assert key == dedup_key("R-X", {"host": "h1"}, "2026-01-01T00:00:00Z")


def test_engine_limits_are_enforced() -> None:
    single = load_rule(
        BASE.format(selection="{event_code: x}").replace(
            "condition: selection", "condition: selection\n  group_by: [user]"
        )
    )
    events = [ev(i / 60, event_code="x", user=f"u{i}") for i in range(50)]
    engine = fire(single, events, EngineLimits(max_alerts=10, max_links_per_alert=1))
    assert len(engine.drafts) == 10 and engine.capped
    assert engine.warnings["alert_cap_reached"] == 40
    links = fire(
        rule("{event_code: x}"),
        [ev(i / 60, event_code="x") for i in range(20)],
        EngineLimits(max_links_per_alert=5),
    )
    [draft] = links.results()
    assert draft.count == 20 and len(draft.refs) == 5 and draft.links_dropped == 15


def test_unordered_input_is_counted_not_fatal() -> None:
    engine = DetectionEngine([rule("{event_code: x}")])
    engine.feed(ev(10, event_code="x"))
    engine.feed(ev(0, event_code="x"))
    assert engine.warnings["unordered_input"] == 1


# ---------------------------------------------------------------------------------- Sigma


SIGMA = """title: Suspicious certutil
id: 3f1c2b4a-0000-4000-8000-000000000001
status: experimental
level: high
tags: [attack.defense_evasion, attack.t1218, attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
  selection_img:
    Image|endswith: '\\\\certutil.exe'
  selection_cli:
    CommandLine|contains|all: ['-urlcache', 'http']
  weird:
    CommandLine: '*-f*http*'
  condition: selection_img and (selection_cli or weird)
falsepositives: [admins]
"""


def test_sigma_supported_subset_converts_and_matches() -> None:
    data, native, notes = sigma.convert(SIGMA)
    assert data["id"] == "SIGMA-3F1C2B4A0000" and data["attack"] == ["T1105", "T1218"]
    assert data["logsource"] == {
        "source_type": "evtx",
        "event_category": "process",
        "action": "create",
    }
    assert data["detection"]["weird"] == {"cmdline|re": "(?is)^.*\\-f.*http.*$"}
    assert notes
    compiled = load_rule(native)
    base = {"source_type": "evtx", "event_category": "process", "action": "create"}
    hit = ev(
        file_path="C:\\Windows\\System32\\certutil.exe",
        cmdline="certutil -urlcache -f http://x",
        **base,
    )
    miss = ev(
        file_path="C:\\tools\\certutil.exe.bak", cmdline="certutil -urlcache -f http://x", **base
    )
    assert fire(compiled, [hit]).drafts and not fire(compiled, [miss]).drafts


@pytest.mark.parametrize(
    ("patch", "needle"),
    [
        ("CommandLine|contains|all:", "CommandLine|windash|contains:"),
        (
            "logsource: {product: windows, category: process_creation}",
            "logsource: {product: macos}",
        ),
        (
            "  condition: selection_img and (selection_cli or weird)",
            "  condition: selection_img | count() > 2",
        ),
        ("  weird:\n", "  timeframe: 5m\n  weird:\n"),
        ("status: experimental", "status: experimental\ncustom_field: 1"),
        ("    CommandLine: '*-f*http*'", "    - just a keyword"),
    ],
)
def test_sigma_rejects_unsupported(patch: str, needle: str) -> None:
    text = SIGMA.replace(patch, needle)
    assert text != SIGMA
    with pytest.raises(sigma.SigmaError):
        sigma.convert(text)


def test_sigma_rejects_backreference_regex() -> None:
    text = SIGMA.replace("CommandLine: '*-f*http*'", "CommandLine|re: '(a)\\1'")
    with pytest.raises(sigma.SigmaError) as info:
        sigma.convert(text)
    assert "RE2" in " ".join(info.value.errors)


# ---------------------------------------------------------------------------------- IOCs


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("ip", "203.0.113[.]5", "203.0.113.5"),
        ("ip", "::ffff:198.51.100.1", "198.51.100.1"),
        ("domain", "Evil[.]Example.", "evil.example"),
        ("url", "hxxps://Evil.Example/Path?q=1", "https://evil.example/Path?q=1"),
        ("sha256", "A" * 64, "a" * 64),
        ("email", "Bad[@]Evil.Example", "bad@evil.example"),
        ("filename", "C:\\Temp\\Mimikatz.EXE", "mimikatz.exe"),
    ],
)
def test_ioc_normalization(ioc_type: str, value: str, expected: str) -> None:
    assert normalize(ioc_type, value) == expected


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [
        ("ip", "999.1.1.1"),
        ("md5", "abc"),
        ("domain", "no spaces.com"),
        ("url", "file:///etc"),
        ("x", "y"),
    ],
)
def test_ioc_normalization_rejects(ioc_type: str, value: str) -> None:
    with pytest.raises(IocError):
        normalize(ioc_type, value)


def test_ioc_imports_report_bad_rows() -> None:
    csv = parse_csv(
        "type,value,confidence\nip,1.2.3.4,0.9\nip,bad,\nmd5,d41d8cd98f00b204e9800998ecf8427e,2\n"
    )
    assert [i.value for i in csv.items] == ["1.2.3.4"] and len(csv.errors) == 2
    with pytest.raises(IocError):
        parse_csv("value\n1.2.3.4\n")
    js = parse_json(
        json.dumps([{"type": "domain", "value": "a.example"}, {"type": "ip", "extra": 1}])
    )
    assert len(js.items) == 1 and len(js.errors) == 1
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '10.0.0.1'] OR [url:value = 'http://a.example/x']",
                "confidence": 80,
            },
            {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + "b" * 64 + "']"},
            {"type": "indicator", "pattern": "[x-custom:value = 'q']"},
            {"type": "malware", "name": "ignored"},
        ],
    }
    stix = parse_stix(json.dumps(bundle))
    assert sorted(i.type for i in stix.items) == ["ip", "sha256", "url"]
    assert stix.items[0].confidence == 0.8 and len(stix.errors) == 1


def test_ioc_index_matches_fields() -> None:
    index = IocIndex(
        [
            IocEntry("1", "domain", "evil.example"),
            IocEntry("2", "email", "bad@evil.example"),
            IocEntry("3", "filename", "mimikatz.exe"),
        ]
    )
    hits = index.match({"cmdline": "ping a.b.evil.example", "user": "bad@evil.example",
                        "file_path": "C:\\t\\MimiKatz.exe"})  # fmt: skip
    assert {h.ioc.id for h in hits} == {"1", "2", "3"}
    assert index.match({"cmdline": "ping notevil.example"}) == []


# ---------------------------------------------------------------------------------- scoring


def test_scoring_is_deterministic() -> None:
    assert alert_risk("high", 0.8) == 56.0
    assert alert_risk("critical", 1.0, 0.5) == 45.0
    assert alert_risk("info", 2.0) == 5.0  # confidence clamped
    assert host_risk([50.0, 50.0]) == 75.0 and host_risk([]) == 0.0
    assert case_risk([40.0], ["T1110", "T1098", "T1490", "T1059"]) == 70.0  # tactic bonus capped
    summary = summarize(
        [
            ScoredAlert("a", "h1", 50.0, ("T1110",), "x"),
            ScoredAlert("b", "h1", 50.0, (), "y"),
            ScoredAlert("c", None, 10.0, (), "z"),
        ]
    )
    assert summary.hosts[0]["host"] == "h1" and summary.hosts[0]["risk"] == 75.0
    assert summary.case_risk == 85.0 and summary.tactics == ["credential-access"]


# ---------------------------------------------------------------------------------- trigger


@pytest.mark.parametrize(
    ("outcome", "called"),
    [("succeeded", True), ("partial", True), ("failed", False), ("cancelled", False)],
)
def test_parse_task_triggers_detection(
    monkeypatch: pytest.MonkeyPatch, outcome: str, called: bool
) -> None:
    seen: list[uuid.UUID] = []
    monkeypatch.setattr(parse_task, "after_parse", seen.append)
    job_id = uuid.uuid4()
    parse_task._trigger_detection(RunResult(job_id, outcome))
    assert seen == ([job_id] if called else [])


def test_parse_task_trigger_failure_is_not_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_: uuid.UUID) -> None:
        raise RuntimeError("queue down")

    monkeypatch.setattr(parse_task, "after_parse", boom)
    parse_task._trigger_detection(RunResult(uuid.uuid4(), "succeeded"))  # logged, not raised


# ---------------------------------------------------------------------------------- sequence expiry

SEQ = """id: TEST-SEQ-0002
title: s
level: low
detection:
  sequence:
    - {{name: a, match: {{event_code: a}}, min_count: {n}}}
    - {{name: b, match: {{event_code: b}}}}
  join_on: [host]
  within: 10m
"""


def test_sequence_keeps_newer_step_events_when_the_oldest_expire() -> None:
    r = load_rule(SEQ.format(n=1))
    # A@0 starts the run; A@8 is absorbed into it; B@12 is within 10m of A@8 only.
    assert fire(r, [ev(0, event_code="a"), ev(8, event_code="a"), ev(12, event_code="b")]).drafts
    assert not fire(r, [ev(0, event_code="a"), ev(12, event_code="b")]).drafts


def test_sequence_earlier_failures_do_not_hide_a_later_burst() -> None:
    # LNX-0002 shape: 5 fails then a success within the window. Old fails at 0-4 must not
    # swallow the fresh burst at 26-30 (success at 31).
    r = load_rule(SEQ.format(n=5).replace("within: 10m", "within: 30m"))
    old = [ev(m, event_code="a") for m in range(5)]
    burst = [ev(26 + m, event_code="a") for m in range(5)]
    assert fire(r, [*old, *burst, ev(31, event_code="b")]).drafts
    # At 36 the old fails (0-4) are outside 30m and only 3 fresh ones remain: no alert.
    assert not fire(r, [*old, *burst[2:], ev(36, event_code="b")]).drafts


def test_linux_rules_fire_on_journal_events() -> None:
    # journal_json emits the linux_auth event codes with source_type "journal" (systemd-only hosts).
    from app.detection.coverage import builtin_rules

    lnx = [r for r in builtin_rules() if r.id.startswith("DFIR-LNX-")]
    engine = DetectionEngine(lnx)
    engine.feed(ev(source_type="journal", event_code="ssh_accepted", user="root", src_ip="1.2.3.4"))
    assert "DFIR-LNX-0003" in {d.rule.id for d in engine.drafts.values()}


def test_anti_forensics_detectors_skip_shell_history() -> None:
    # bash appends each session's history at exit, so overlapping sessions step backwards in time.
    from app.detection.coverage import builtin_rules
    from app.detection.detectors import SourceInfo

    af = [r for r in builtin_rules() if r.id == "DFIR-AF-0001"]

    def run(source_type: str) -> set[str]:
        engine = DetectionEngine(af)
        rows = [ev(m, source_type=source_type, recno=i) for i, m in enumerate([0, 60, 30, 90])]
        engine.feed_source(SourceInfo("e1", "f"), rows)
        return {d.rule.id for d in engine.drafts.values()}

    assert run("shell_history") == set()
    assert run("auth_log") == {"DFIR-AF-0001"}
