"""Shared helpers for the Phase 6 parser tests (no Docker, no network)."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.parsers.base import ParseContext, ParseLimits, ToolConfig
from app.parsers.normalize import to_row
from app.parsers.registry import get_parser

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
DEEP = FIXTURES / "deep"
BIN = DEEP / "bin"
GOLDEN = FIXTURES / "golden"
FAKE = DEEP / "fake_tools" / "fake_engines.py"
CASE_ID = "00000000-0000-4000-8000-00000000c0de"
EVIDENCE_ID = "00000000-0000-4000-8000-0000000e0006"
JOB_ID = "00000000-0000-4000-8000-000000000b06"
REFERENCE = datetime(2026, 1, 3, tzinfo=UTC)


def make_tool(directory: Path, name: str, fake: str | None = None) -> Path:
    """A launcher ``name`` in ``directory`` that runs ``fake_engines.py <fake or name>``."""
    directory.mkdir(parents=True, exist_ok=True)
    target = fake or name
    if sys.platform == "win32":
        path = directory / f"{name}.bat"
        path.write_text(f'@"{sys.executable}" "{FAKE}" {target} %*\r\n', encoding="ascii")
    else:
        path = directory / name
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" {target} "$@"\n')
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def context(
    path: Path,
    *,
    params: dict[str, Any] | None = None,
    tools: ToolConfig | None = None,
    work_dir: Path | None = None,
    limits: ParseLimits | None = None,
    source_file: str | None = None,
) -> ParseContext:
    params = params or {}
    return ParseContext(
        path=path,
        evidence_id=EVIDENCE_ID,
        case_id=CASE_ID,
        source_file=source_file or path.name,
        timezone=params.get("timezone", "UTC"),
        reference_time=REFERENCE,
        reference_source="test",
        params=params,
        tools=tools or ToolConfig(),
        work_dir=work_dir,
        limits=limits or ParseLimits(),
    )


def run(parser_name: str, ctx: ParseContext) -> dict[str, Any]:
    parser = get_parser(parser_name)
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
    return json.loads(
        json.dumps(
            {
                "parser": parser.name,
                "parser_version": parser.version,
                "counts": ctx.stats.counts(),
                "warnings": dict(sorted(ctx.stats.warnings.items())),
                "error_samples": ctx.stats.error_samples,
                "assumptions": ctx.stats.assumptions,
                "events": rows,
            }
        )
    )


def check_golden(actual: dict[str, Any], golden: str) -> None:
    target = GOLDEN / f"{golden}.json"
    if os.environ.get("DFIR_UPDATE_GOLDEN") == "1":
        target.write_text(
            json.dumps(actual, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    expected = json.loads(target.read_text(encoding="utf-8"))
    assert actual == expected
