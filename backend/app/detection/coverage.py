"""ATT&CK coverage table generated from rules (built-in pack or the ``rules`` table).

``python -m app.detection.coverage ../docs/detection-coverage.md`` regenerates the committed doc;
``tests/unit/test_detection_rules.py`` fails when the doc and the built-in pack disagree.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources

from app.detection.attack import tactics_of
from app.detection.rules import CompiledRule, load_rule


@dataclass(frozen=True)
class RuleInfo:
    id: str
    title: str
    level: str
    kind: str
    attack: tuple[str, ...]
    enabled: bool = True


def builtin_texts() -> dict[str, str]:
    """``{file stem: YAML text}`` of the built-in pack shipped in ``app.detection.builtin``."""
    root = resources.files("app.detection.builtin")
    out: dict[str, str] = {}
    for item in sorted(root.iterdir(), key=lambda p: p.name):
        if item.name.endswith(".yml"):
            out[item.name[: -len(".yml")]] = item.read_text(encoding="utf-8")
    return out


def builtin_rules() -> list[CompiledRule]:
    return [load_rule(text) for text in builtin_texts().values()]


def info(rule: CompiledRule, enabled: bool = True) -> RuleInfo:
    return RuleInfo(rule.id, rule.title, str(rule.level), rule.kind, rule.attack, enabled)


def coverage_rows(rules: Iterable[RuleInfo]) -> list[dict[str, object]]:
    """One row per technique: tactics and the (enabled) rules that cover it."""
    by_technique: dict[str, list[RuleInfo]] = {}
    for rule in rules:
        if not rule.enabled:
            continue
        for technique in rule.attack:
            by_technique.setdefault(technique, []).append(rule)
    return [
        {
            "technique": technique,
            "tactics": list(tactics_of(technique)),
            "rules": [r.id for r in sorted(by_technique[technique], key=lambda r: r.id)],
        }
        for technique in sorted(by_technique)
    ]


def render_markdown(rules: list[RuleInfo]) -> str:
    rows = coverage_rows(rules)
    lines = [
        "# Detection coverage (built-in rule pack)",
        "",
        "Generated from `backend/app/detection/builtin/*.yml` by "
        "`python -m app.detection.coverage`; do not edit by hand. The live table for the rules "
        "enabled in a deployment is `GET /api/v1/rules/coverage`.",
        "",
        "## By ATT&CK technique",
        "",
        "| Technique | Tactics | Rules |",
        "|---|---|---|",
    ]
    for row in rows:
        tactics = ", ".join(row["tactics"]) or "-"  # type: ignore[arg-type]
        rule_ids = ", ".join(row["rules"])  # type: ignore[arg-type]
        lines.append(f"| {row['technique']} | {tactics} | {rule_ids} |")
    lines += [
        "",
        "## Rules",
        "",
        "| Rule | Title | Level | Kind | ATT&CK |",
        "|---|---|---|---|---|",
    ]
    for rule in sorted(rules, key=lambda r: r.id):
        attack = ", ".join(rule.attack) or "-"
        lines.append(f"| {rule.id} | {rule.title} | {rule.level} | {rule.kind} | {attack} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    import sys
    from pathlib import Path

    text = render_markdown([info(r) for r in builtin_rules()])
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_bytes(text.encode("utf-8"))  # LF on every platform
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
