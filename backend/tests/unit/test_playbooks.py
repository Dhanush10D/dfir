"""Playbook format, loader limits and the closed action registry (pure)."""

from __future__ import annotations

import pytest

from app.response import registry
from app.response.registry import (
    ACTIONS,
    ActionContext,
    ActionParamError,
    clean_params,
    plan,
)
from app.response.schema import (
    MAX_PLAYBOOK_BYTES,
    PlaybookError,
    builtin_playbooks,
    builtin_texts,
    parse_playbook,
)

GOOD = """
id: PB-TEST-01
title: Test playbook
trigger: { attack: [T1486], rules: [DFIR-WIN-0010] }
phases:
  - name: Containment
    steps:
      - { id: c1, text: "Isolate the host", action: agent.isolate_host }
      - { id: c2, text: "Tell the team", action: notify.team, requires_approval: true }
      - { id: c3, text: "Write it down", manual: true }
notify: { channels: [in_app, slack], roles: [lead] }
"""


def _errors(text: str) -> str:
    with pytest.raises(PlaybookError) as err:
        parse_playbook(text)
    return " | ".join(err.value.errors)


def test_good_playbook_and_forced_approval() -> None:
    loaded = parse_playbook(GOOD)
    assert loaded.id == "PB-TEST-01" and len(loaded.sha256) == 64
    steps = {s.id: s for _, _, s in loaded.model.flat_steps()}
    assert steps["c1"].needs_approval  # impactful: the registry decides, not the file
    assert steps["c2"].needs_approval  # the file may add approval to a harmless action
    assert not steps["c3"].needs_approval and steps["c3"].kind == "manual"
    definition = loaded.definition()
    flags = {s["id"]: s["requires_approval"] for p in definition["phases"] for s in p["steps"]}
    assert flags == {"c1": True, "c2": True, "c3": False}
    assert [pos for pos, _, _ in loaded.model.flat_steps()] == [0, 1, 2]


def test_file_cannot_switch_off_approval_of_an_impactful_action() -> None:
    text = GOOD.replace(
        "action: agent.isolate_host }", "action: agent.isolate_host, requires_approval: false }"
    )
    step = parse_playbook(text).definition()["phases"][0]["steps"][0]
    assert step["requires_approval"] is True


def test_the_eight_starter_playbooks_load() -> None:
    books = builtin_playbooks()
    assert [b.id for b in books] == sorted(b.id for b in books)  # loaded in name order
    assert {b.id for b in books} == {
        "PB-RANSOMWARE-01",
        "PB-PHISHING-01",
        "PB-CREDENTIAL-01",
        "PB-MALWARE-01",
        "PB-LOGTAMPER-01",
        "PB-EXFIL-01",
        "PB-CLOUD-01",
        "PB-WEBSHELL-01",
    }
    for stem, text in builtin_texts().items():
        assert parse_playbook(text).id == stem  # the file name is the id
    ransomware = next(b for b in books if b.id == "PB-RANSOMWARE-01")
    assert ransomware.model.trigger.attack == ["T1486", "T1490"]
    for book in books:
        for _, _, step in book.model.flat_steps():
            if step.action in ("agent.isolate_host", "agent.kill_process", "agent.disable_account"):
                assert step.needs_approval, (book.id, step.id)


@pytest.mark.parametrize(
    ("change", "needle"),
    [
        (("action: notify.team", "action: os.system"), "unknown action"),
        (("action: notify.team", "action: __import__"), "unknown action"),
        (("id: c2", "id: c1"), "duplicate step ids"),
        (("id: PB-TEST-01", "id: pb test"), "id"),
        (("id: c3", "id: 3"), "id"),
        (("manual: true", "manual: true, action: notify.team"), "either"),
        (("manual: true", "manual: false"), "either"),
        (("manual: true", "manual: true, requires_approval: true"), "manual step"),
        (("manual: true", "manual: yes please"), "manual"),
        (("title: Test playbook", "title: Test playbook\nowner: someone"), "owner"),
        (("attack: [T1486]", "attack: [T9]"), "attack"),
        (("channels: [in_app, slack]", "channels: [sms]"), "channels"),
        (("roles: [lead]", "roles: [root]"), "roles"),
        (('text: "Write it down"', 'text: ""'), "text"),
        (
            ("action: agent.isolate_host", "action: agent.isolate_host, params: {cmd: ls}"),
            "no parameter",
        ),
        (
            ("action: agent.isolate_host", "action: agent.isolate_host, params: {host: 5}"),
            "must be",
        ),
    ],
)
def test_strict_schema_rejects(change: tuple[str, str], needle: str) -> None:
    text = GOOD.replace(*change)
    assert text != GOOD
    assert needle in _errors(text)


def test_hostile_yaml_is_refused() -> None:
    assert "larger than" in _errors("id: PB-BIG-01\ntitle: " + "x" * (MAX_PLAYBOOK_BYTES + 1))
    assert "aliases" in _errors("a: &a [1]\nb: *a\n") or "anchors" in _errors("a: &a [1]\nb: *a\n")
    assert "nesting deeper" in _errors("a: " + "[" * 12 + "]" * 12)
    assert "invalid YAML" in _errors("id: [unclosed")
    assert "mapping" in _errors("- just\n- a list\n")
    assert "duplicate key" in _errors(GOOD + "title: Second title\n")
    # No Python object construction: the tag is an error, nothing is executed.
    assert "invalid YAML" in _errors('!!python/object/apply:os.system ["echo pwned"]')
    assert "more than" in _errors("id: PB-N-01\ntitle: t\nphases:\n" + "  - x\n" * 6000)
    dup_phase = GOOD.replace(
        "notify:",
        "  - name: Containment\n    steps:\n      - { id: z1, text: t, manual: true }\nnotify:",
    )
    assert "phase names must be unique" in _errors(dup_phase)


def test_registry_is_a_closed_dict_of_known_actions() -> None:
    assert set(ACTIONS) == {
        "agent.isolate_host",
        "agent.kill_process",
        "agent.disable_account",
        "agent.memory_dump",
        "agent.collect_triage",
        "notify.team",
    }
    assert {n for n, s in ACTIONS.items() if s.impact} == {
        "agent.isolate_host",
        "agent.kill_process",
        "agent.disable_account",
    }
    assert all(s.executor == "none" for n, s in ACTIONS.items() if n.startswith("agent."))
    source = registry.__file__
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    for forbidden in ("getattr(", "importlib", "__import__", "eval(", "exec(", "globals()"):
        assert forbidden not in text, forbidden


def _ctx(emitted: list[tuple[str, dict[str, object], str]], **params: object) -> ActionContext:
    return ActionContext(
        case_id="c",
        run_id="r",
        playbook_id="PB-TEST-01",
        step_key="c1",
        alert_id=None,
        params=params,
        emit=lambda event, payload, dedup: emitted.append((event, payload, dedup)),
    )


def test_agent_actions_never_claim_to_have_run() -> None:
    emitted: list[tuple[str, dict[str, object], str]] = []
    for name, spec in ACTIONS.items():
        if spec.executor != "none":
            continue
        result = spec.handler(_ctx(emitted, host="WS-042"))
        assert result.outcome == "not_executed", name
        assert result.detail["reason"] == "no_remote_agent" and result.detail["simulated"] is True
        text = (result.detail["message"] + spec.effect).lower()
        assert "not executed" in text or "nothing is changed" in text
        for claim in ("host isolated", "was isolated", "process killed", "account disabled"):
            assert claim not in text
    assert emitted == []


def test_notify_team_queues_exactly_one_event() -> None:
    emitted: list[tuple[str, dict[str, object], str]] = []
    result = ACTIONS["notify.team"].handler(_ctx(emitted))
    assert result.outcome == "completed"
    assert emitted == [
        (
            "playbook.notice",
            {"run_id": "r", "playbook_id": "PB-TEST-01", "step_key": "c1"},
            "playbook.notice:r:c1",
        )
    ]


def test_params_are_validated_against_the_spec() -> None:
    assert clean_params("agent.kill_process", {"host": " WS-1 ", "pid": 4242}, require=True) == {
        "host": "WS-1",
        "pid": 4242,
    }
    for params in (
        {"host": "a\nb"},
        {"host": ""},
        {"host": "x" * 256},
        {"host": 5},
        {"host": "h", "pid": True},
        {"host": "h", "pid": -1},
        {"host": "h", "pid": "12"},
        {"host": "h", "shell": "rm -rf /"},
    ):
        with pytest.raises(ActionParamError):
            clean_params("agent.kill_process", params, require=True)
    with pytest.raises(ActionParamError, match="needs: host"):
        clean_params("agent.isolate_host", {}, require=True)
    assert clean_params("agent.isolate_host", {}, require=False) == {}


def test_plan_describes_without_doing() -> None:
    dry = plan("agent.isolate_host", {}, requires_approval=False)
    assert dry["requires_approval"] is True and dry["would_execute"] is False
    assert dry["missing_params"] == ["host"] and "no remote agent" in dry["effect"].lower()
    real = plan("notify.team", {}, requires_approval=False)
    assert real["would_execute"] is True and real["requires_approval"] is False
