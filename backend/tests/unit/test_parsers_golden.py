"""Golden-output tests for the Phase 2 parsers (guide 10.2 rule 6, 22.2).

Each fixture is parsed and normalized exactly as the worker does (``to_row``) with fixed
provenance ids; the result (counts, warnings, assumptions and every row, ids included) must equal
``tests/fixtures/golden/<name>.json``. Regenerate after a deliberate change with
``DFIR_UPDATE_GOLDEN=1 pytest tests/unit/test_parsers_golden.py`` and review the diff.

Fixtures: ``evtx/*.evtx`` are byte-identical copies of ``samples/new-user-security.evtx`` and
``samples/Security_short_selected.evtx`` from github.com/omerbenamram/evtx (MIT/Apache-2.0);
``linux/auth.log`` is synthetic (documentation IP ranges).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.parsers.base import ParseContext
from app.parsers.normalize import to_row
from app.parsers.registry import get_parser

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
GOLDEN = FIXTURES / "golden"
CASE_ID = "00000000-0000-4000-8000-00000000c0de"
EVIDENCE_ID = "00000000-0000-4000-8000-0000000e0001"
JOB_ID = "00000000-0000-4000-8000-000000000b01"
REFERENCE = datetime(2026, 1, 3, tzinfo=UTC)

CASES = [
    ("evtx", "evtx/new_user_security.evtx", "evtx_new_user_security", {}),
    ("evtx", "evtx/security_short_selected.evtx", "evtx_security_short_selected", {}),
    ("linux_auth", "linux/auth.log", "linux_auth_utc", {"timezone": "UTC"}),
    ("linux_auth", "linux/auth.log", "linux_auth_kolkata", {"timezone": "Asia/Kolkata"}),
]


def run_parser(parser_name: str, path: Path, params: dict[str, Any]) -> dict[str, Any]:
    parser = get_parser(parser_name)
    ctx = ParseContext(
        path=path,
        evidence_id=EVIDENCE_ID,
        case_id=CASE_ID,
        source_file=path.name,
        timezone=params.get("timezone", "UTC"),
        year=params.get("year"),
        reference_time=REFERENCE,
        reference_source="test",
        params=params,
    )
    rows = []
    for event in parser.parse(ctx):
        row, _ = to_row(
            event,
            case_id=CASE_ID,
            evidence_id=EVIDENCE_ID,
            job_id=JOB_ID,
            parser_name=parser.name,
            parser_version=parser.version,
        )
        ctx.stats.events_emitted += 1
        row = {k: v for k, v in row.items() if k not in {"case_id", "evidence_id", "job_id"}}
        row["id"] = str(row["id"])
        row["ts"] = row["ts"].isoformat()
        rows.append(row)
    assert ctx.stats.balanced, ctx.stats.counts()
    return {
        "parser": parser.name,
        "parser_version": parser.version,
        "counts": ctx.stats.counts(),
        "warnings": dict(sorted(ctx.stats.warnings.items())),
        "error_samples": ctx.stats.error_samples,
        "assumptions": ctx.stats.assumptions,
        "events": rows,
    }


@pytest.mark.parametrize(("parser_name", "fixture", "golden", "params"), CASES)
def test_golden_output(parser_name: str, fixture: str, golden: str, params: dict[str, Any]) -> None:
    actual = json.loads(json.dumps(run_parser(parser_name, FIXTURES / fixture, params)))
    target = GOLDEN / f"{golden}.json"
    if os.environ.get("DFIR_UPDATE_GOLDEN") == "1":
        target.write_text(
            json.dumps(actual, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    expected = json.loads(target.read_text(encoding="utf-8"))
    assert actual == expected


def test_golden_files_cover_every_registered_parser() -> None:
    from app.parsers.registry import all_parsers

    assert {c[0] for c in CASES} == set(all_parsers())


def test_ids_are_stable_across_runs_and_independent_of_params() -> None:
    utc = run_parser("linux_auth", FIXTURES / "linux/auth.log", {"timezone": "UTC"})
    again = run_parser("linux_auth", FIXTURES / "linux/auth.log", {"timezone": "UTC"})
    kolkata = run_parser("linux_auth", FIXTURES / "linux/auth.log", {"timezone": "Asia/Kolkata"})
    ids = [e["id"] for e in utc["events"]]
    assert ids == [e["id"] for e in again["events"]]
    assert ids == [e["id"] for e in kolkata["events"]]  # a reprocess replaces the same records
    assert len(set(ids)) == len(ids)
