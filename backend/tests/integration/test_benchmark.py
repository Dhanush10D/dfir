"""Phase 10: the benchmark code runs end to end (tiny size; the real run is in verify-phase10)."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine

from app.ops.bench import QUERIES, run, write_auth_log
from app.parsers.base import ParseContext
from app.parsers.registry import get_parser

pytestmark = pytest.mark.integration


def test_synthetic_log_parses_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    write_auth_log(path, 700)
    ctx = ParseContext(
        path=path,
        evidence_id="e",
        case_id="c",
        source_file="auth.log",
        year=2026,
        params={"year": 2026},
    )
    events = list(get_parser("linux_auth").parse(ctx))
    assert ctx.stats.records_read == 700 and len(events) == 700 and ctx.stats.errors == 0
    hosts = {e.host for e in events}
    assert hosts == {"bench01"}
    assert all(
        e.src_ip is None or e.src_ip.startswith(("198.51.100.", "203.0.113.", "192.0.2."))
        for e in events
    )


def test_benchmark_runs_on_the_test_database(db_engine: Engine, tmp_path: Path) -> None:
    result = run(db_engine, tmp_path, events=500, search_runs=2)
    assert result["parse"]["lines"] == 500
    assert result["ingest"]["events"] == 500
    assert set(result["search"]) == {*QUERIES, "_count"}
    assert result["search"]["_count"]["rows"] == 500
    assert result["search"]["field"]["rows"] > 0
    assert result["detection"]["events"] == 500 and result["detection"]["rules"] > 10
