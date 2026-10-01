#!/usr/bin/env python3
"""Tool validation records (Phase 10, guide 22.7; docs/validation/TOOL_VALIDATION.md).

    backend/.venv/Scripts/python scripts/tool-validation.py           # regenerate
    backend/.venv/Scripts/python scripts/tool-validation.py --check   # fail if the docs are stale

In the spirit of NIST CFTT: for every parser, run it on its known inputs (the golden fixtures,
with the same fixed ids as the golden tests) and record the fixture SHA-256, the parser version,
records read / emitted / skipped / errors, the SHA-256 of the normalised output and whether it
equals the reviewed golden file; for every built-in detection rule, run its positive and negative
fixtures; list each integrity test of guide 22.3 with the test that proves it. The output is
deterministic (no timestamps, host names or Python patch versions), so ``--check`` can run in CI.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from app.parsers.base import ToolConfig  # noqa: E402
from app.parsers.registry import all_parsers  # noqa: E402
from tests.unit import deep_helpers  # noqa: E402
from tests.unit import test_detection_rules as rules_tests  # noqa: E402
from tests.unit import test_parsers_deep_golden as deep  # noqa: E402
from tests.unit import test_parsers_golden as phase2  # noqa: E402

DOC = ROOT / "docs" / "validation" / "TOOL_VALIDATION.md"
JSON_OUT = ROOT / "docs" / "validation" / "tool-validation.json"
BEGIN, END = "<!-- BEGIN GENERATED (scripts/tool-validation.py) -->", "<!-- END GENERATED -->"
PACKAGES = (
    "python-evtx", "pefile", "yara-python", "dpkt", "LnkParse3", "defusedxml", "google-re2",
    "PyYAML", "tzdata",
)
FAKE_ENGINES = {"tsk_fs": "fls/mmls", "volatility": "vol", "zeek": "zeek"}

# Guide 22.3 integrity tests -> what proves them (test node ids, smoke checks).
INTEGRITY = [
    (
        "Upload a file; the stored hash equals an independent SHA-256",
        [
            "backend/tests/integration/test_evidence_api.py::test_full_lifecycle",
            "backend/tests/integration/test_vault_minio.py::"
            "test_streaming_multipart_upload_hash_matches_independent_digest",
            "scripts/phase1-smoke.py",
        ],
    ),
    (
        "Flip one byte in the vault copy; verify fails and logs hash_failed",
        [
            "backend/tests/integration/test_tamper.py::"
            "test_flipped_byte_in_stored_version_is_detected",
            "backend/tests/integration/test_integrity.py::"
            "test_flipped_byte_and_edited_custody_row_are_found",
        ],
    ),
    (
        "Modify a custody row as a privileged user; chain verification fails",
        [
            "backend/tests/integration/test_tamper.py::"
            "test_edited_custody_detail_is_detected_at_its_seq",
            "backend/tests/integration/test_tamper.py::"
            "test_owner_publishing_attacker_key_and_resigning_whole_chain_fails",
            "scripts/phase1-smoke.py",
        ],
    ),
    (
        "UPDATE/DELETE on custody_log as the app role is denied",
        [
            "backend/tests/integration/test_tamper.py::"
            "test_app_role_cannot_mutate_custody_or_audit",
            "scripts/verify-phase10.sh",
        ],
    ),
    (
        "Process evidence twice; no duplicate events, original hash unchanged",
        [
            "backend/tests/integration/test_processing.py::"
            "test_idempotent_submit_and_reprocess",
        ],
    ),
    (
        "Writing to the evidence mount from the parser container fails",
        ["scripts/phase10-smoke.py"],
    ),
    (
        "A restored backup is re-verified (hashes, custody chains, chain heads) before use",
        [
            "backend/tests/integration/test_integrity.py::"
            "test_manifest_round_trip_and_tail_truncation",
            "scripts/verify-phase10.sh",
        ],
    ),
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def parser_cases(tools_dir: Path) -> list[dict[str, Any]]:
    tools = tools_dir / "tools"
    for name in ("fls", "mmls", "vol", "zeek"):
        deep_helpers.make_tool(tools, name)
    fake_cfg = ToolConfig(search_path=str(tools), timeout_s=60)
    parsers = all_parsers()
    out: list[dict[str, Any]] = []
    for name, fixture, golden, params in phase2.CASES:
        path = phase2.FIXTURES / fixture
        result = phase2.run_parser(name, path, params)
        out.append(_record(name, f"tests/fixtures/{fixture}", path, golden, params, result))
    for name, fixture, golden, params in deep.DEEP_CASES:
        path = deep_helpers.BIN / fixture
        ctx = deep_helpers.context(path, params=params, source_file=f"evidence/{fixture}")
        result = deep_helpers.run(name, ctx)
        out.append(
            _record(name, f"tests/fixtures/deep/bin/{fixture}", path, f"deep_{golden}", params, result)
        )
    for name, fixture, golden, params in deep.TOOL_CASES:
        path = deep_helpers.BIN / fixture
        work = tools_dir / f"work-{golden}"
        work.mkdir()
        ctx = deep_helpers.context(path, params=params, tools=fake_cfg, work_dir=work)
        result = deep_helpers.run(name, ctx)
        rec = _record(name, f"tests/fixtures/deep/bin/{fixture}", path, f"deep_{golden}", params,
                      result)
        rec["engine"] = f"recorded {FAKE_ENGINES[name]} output (fake binary); wrapper validated"
        out.append(rec)
    assert {r["parser"] for r in out} == set(parsers), "every parser needs a validation case"
    return out


def _record(
    name: str, fixture_rel: str, path: Path, golden: str, params: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    golden_path = deep_helpers.GOLDEN / f"{golden}.json"
    expected = json.loads(golden_path.read_text(encoding="utf-8"))
    normalised = json.loads(json.dumps(result))
    return {
        "parser": name,
        "parser_version": result["parser_version"],
        "fixture": fixture_rel,
        "fixture_sha256": sha256_file(path),
        "params": params,
        "counts": result["counts"],
        "warnings": sum(result["warnings"].values()),
        "output_sha256": sha256_json(normalised["events"]),
        "golden": f"tests/fixtures/golden/{golden}.json",
        "matches_golden": normalised == expected,
        "engine": "in-process (pinned Python packages)",
    }


def rule_cases() -> list[dict[str, Any]]:
    out = []
    for rule_id in sorted(rules_tests.RULES):
        rule = rules_tests.RULES[rule_id]
        spec = rules_tests.FIXTURES[rule_id]
        positive = rules_tests.run(rule, spec, "positive")
        negative = rules_tests.run(rule, spec, "negative")
        out.append(
            {
                "rule": rule_id,
                "rule_sha256": rule.sha256,
                "attack": sorted(rule.attack),
                "positive_alerts": len(positive),
                "negative_alerts": len(negative),
                "passed": bool(positive) and not negative,
            }
        )
    return out


def _functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def integrity_cases() -> list[dict[str, Any]]:
    out = []
    for requirement, proofs in INTEGRITY:
        for proof in proofs:
            file_part, _, func = proof.partition("::")
            path = ROOT / file_part
            if not path.is_file() or (func and func not in _functions(path)):
                raise SystemExit(f"integrity proof not found: {proof}")
        out.append({"requirement": requirement, "proved_by": proofs})
    return out


def versions() -> dict[str, str]:
    found = {name: importlib.metadata.version(name) for name in PACKAGES}
    dockerfile = (ROOT / "infra" / "docker" / "worker.Dockerfile").read_text(encoding="utf-8")
    match = re.search(r"ARG SLEUTHKIT_VERSION=(\S+)", dockerfile)
    found["sleuthkit (worker image)"] = match.group(1) if match else "?"
    reqs = (ROOT / "infra" / "docker" / "volatility-requirements.txt").read_text(encoding="utf-8")
    match = re.search(r"^volatility3==(\S+)", reqs, re.MULTILINE)
    found["volatility3 (worker image)"] = match.group(1) if match else "?"
    return dict(sorted(found.items()))


def build() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="dfir-validation-") as tmp:
        parsers = parser_cases(Path(tmp))
    return {
        "format": "dfirbench-tool-validation",
        "version": 1,
        "versions": versions(),
        "parsers": parsers,
        "rules": rule_cases(),
        "integrity": integrity_cases(),
    }


def markdown(data: dict[str, Any]) -> str:
    lines = ["### Parsers (known inputs -> recorded outputs)", ""]
    lines.append("| Parser | Version | Fixture | Read | Emitted | Skipped | Errors | Output SHA-256 "
                 "| Golden | Engine |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for p in data["parsers"]:
        c = p["counts"]
        params = ", ".join(f"{k}={v}" for k, v in sorted(p["params"].items()))
        fixture = f"`{p['fixture']}`" + (f" ({params})" if params else "")
        lines.append(
            f"| {p['parser']} | {p['parser_version']} | {fixture} | {c['records_read']} | "
            f"{c['events_emitted']} | {c['skipped']} | {c['errors']} | `{p['output_sha256'][:16]}` "
            f"| {'match' if p['matches_golden'] else 'DIFFERS'} | {p['engine']} |"
        )
    passed = sum(1 for r in data["rules"] if r["passed"])
    lines += [
        "",
        f"### Detection rules ({passed}/{len(data['rules'])} pass: the positive fixture alerts, "
        "the near-miss negative fixture does not)",
        "",
        "| Rule | ATT&CK | Positive alerts | Negative alerts | Result |",
        "|---|---|---|---|---|",
    ]
    for r in data["rules"]:
        lines.append(
            f"| {r['rule']} | {', '.join(r['attack']) or '-'} | {r['positive_alerts']} | "
            f"{r['negative_alerts']} | {'pass' if r['passed'] else 'FAIL'} |"
        )
    lines += ["", "### Integrity tests (guide 22.3)", "", "| Requirement | Proved by |", "|---|---|"]
    for item in data["integrity"]:
        proofs = "<br>".join(f"`{p}`" for p in item["proved_by"])
        lines.append(f"| {item['requirement']} | {proofs} |")
    lines += ["", "### Versions under test", "", "| Component | Version |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in data["versions"].items()]
    return "\n".join(lines)


def render_doc(current: str, table: str) -> str:
    start, end = current.index(BEGIN), current.index(END)
    return current[: start + len(BEGIN)] + "\n" + table + "\n" + current[end:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = build()
    json_text = json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    doc_text = render_doc(DOC.read_text(encoding="utf-8"), markdown(data))
    failures = [p["parser"] for p in data["parsers"] if not p["matches_golden"]]
    failures += [r["rule"] for r in data["rules"] if not r["passed"]]
    if args.check:
        stale = []
        if JSON_OUT.read_text(encoding="utf-8") != json_text:
            stale.append(str(JSON_OUT.relative_to(ROOT)))
        if DOC.read_text(encoding="utf-8") != doc_text:
            stale.append(str(DOC.relative_to(ROOT)))
        if stale or failures:
            print(f"tool validation stale: {stale}; failing: {failures}", file=sys.stderr)
            return 1
        print(f"tool validation current: {len(data['parsers'])} parser cases, "
              f"{len(data['rules'])} rules, {len(data['integrity'])} integrity requirements")
        return 0
    JSON_OUT.write_bytes(json_text.encode("utf-8"))
    DOC.write_bytes(doc_text.encode("utf-8"))
    print(f"wrote {JSON_OUT.relative_to(ROOT)} and {DOC.relative_to(ROOT)}; failing: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
