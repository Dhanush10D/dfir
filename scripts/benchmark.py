#!/usr/bin/env python3
"""Performance benchmark on a throwaway database (Phase 10; docs/validation/BENCHMARK.md).

    backend/.venv/Scripts/python scripts/benchmark.py --events 200000 \\
        --min-parse-lps 20000 --min-ingest-eps 2000 --max-search-p95-ms 2000 --max-detect-s 300

Creates ``dfirbench_bench_<hex>`` on the compose Postgres (DATABASE_URL, owner login), migrates
it, runs ``app.ops.bench`` (parse, ingest, search, detection), prints JSON and drops the database.
The floors are deliberately loose (they catch gross regressions on the 7.8 GB dev host, not small
drifts); exit 1 when one is missed. Never run it next to a test suite (memory).
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

from app.config import Settings  # noqa: E402
from app.ops.bench import run  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--events", type=int, default=200_000)
    parser.add_argument("--search-runs", type=int, default=20)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--min-parse-lps", type=float, default=0)
    parser.add_argument("--min-ingest-eps", type=float, default=0)
    parser.add_argument("--max-search-p95-ms", type=float, default=0)
    parser.add_argument("--max-detect-s", type=float, default=0)
    args = parser.parse_args()

    server = make_url(Settings(_env_file=None).database_url)  # type: ignore[call-arg]
    admin = create_engine(server.set(database="postgres"), isolation_level="AUTOCOMMIT")
    name = f"dfirbench_bench_{uuid.uuid4().hex[:10]}"
    url = server.set(database=name).render_as_string(hide_password=False)
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        cfg = Config(str(ROOT / "backend" / "alembic.ini"))
        cfg.attributes["db_url"] = url
        cfg.attributes["configure_logger"] = False
        command.upgrade(cfg, "head")
        engine = create_engine(url, connect_args={"options": "-c timezone=UTC"})
        try:
            with tempfile.TemporaryDirectory(prefix="dfir-bench-") as tmp:
                result = run(engine, Path(tmp), events=args.events, search_runs=args.search_runs)
        finally:
            engine.dispose()
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()

    result["host"] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor() or platform.machine(),
    }
    worst_p95 = max(v["p95_ms"] for k, v in result["search"].items() if not k.startswith("_"))
    checks = {
        "parse_lines_per_s": (result["parse"]["lines_per_s"], ">=", args.min_parse_lps),
        "ingest_events_per_s": (result["ingest"]["events_per_s"], ">=", args.min_ingest_eps),
        "search_worst_p95_ms": (worst_p95, "<=", args.max_search_p95_ms),
        "detection_seconds": (result["detection"]["seconds"], "<=", args.max_detect_s),
    }
    failed = [
        f"{name} {value} (needs {op} {limit})"
        for name, (value, op, limit) in checks.items()
        if limit and not (value >= limit if op == ">=" else value <= limit)
    ]
    result["floors"] = {"failed": failed}
    text_out = json.dumps(result, indent=2)
    print(text_out)
    if args.json_out:
        args.json_out.write_text(text_out + "\n", encoding="utf-8")
    if failed:
        print("BENCHMARK FLOORS MISSED: " + "; ".join(failed), file=sys.stderr)
        return 1
    print("benchmark floors met", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
