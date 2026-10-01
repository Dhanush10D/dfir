"""Performance benchmark (Phase 10, guide 22.1 "Performance"): parse, ingest, search, detection.

Runs against a database the caller provides (``scripts/benchmark.py`` creates and drops a
throwaway one on the compose Postgres; a small integration test uses the test database):

1. **parse**: the ``linux_auth`` parser over a synthetic auth.log (documentation IP ranges, no
   real data), lines per second;
2. **ingest**: parse + ``to_row`` + the worker's batch insert (``insert_event_rows``: COPY into
   a staging table, ``INSERT ... SELECT ... ON CONFLICT DO NOTHING``; ``INGEST_BATCH_SIZE`` rows
   per transaction, monthly partitions ensured first), events/s;
3. **search**: six queries of the search language compiled to SQL as the API does (keyset order,
   limit 100), p50/p95 latency over repeated runs;
4. **detection**: the built-in rules over the case's events streamed in time order (the scan the
   detection worker performs; alert drafts are counted, not stored).

Nothing is kept in memory beyond one batch, so 200 000 events fit on the 7.8 GB dev host.
"""

from __future__ import annotations

import random
import statistics
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from app.db.models import Event
from app.detection import fields as F  # noqa: N812 - same alias as services/detection.py
from app.detection.coverage import builtin_rules
from app.detection.engine import DetectionEngine
from app.parsers.base import ParseContext
from app.parsers.normalize import to_row
from app.parsers.registry import get_parser
from app.search.compile import to_sql
from app.search.language import parse
from app.services.processing import insert_event_rows

START = datetime(2026, 1, 1, tzinfo=UTC)
USERS = ("root", "deploy", "alice", "bob", "svc_backup", "admin", "oracle", "postgres")
NETS = ("198.51.100.", "203.0.113.", "192.0.2.")
QUERIES = {
    "field": "user:root",
    "and": "process_name:sshd outcome:failure",
    "or": "event_code:ssh_failed OR event_code:ssh_invalid_user",
    "ip": "src_ip:203.0.113.7",
    "wildcard": "user:svc*",
    "not": "action:logon NOT user:deploy",
}


def _line(i: int, rnd: random.Random) -> str:
    ts = START + timedelta(seconds=i)
    stamp = f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"
    user = rnd.choice(USERS)
    ip = rnd.choice(NETS) + str(rnd.randint(1, 254))
    pid = 1000 + i % 30000
    kind = i % 7
    if kind == 0:
        body = f"sshd[{pid}]: Accepted password for {user} from {ip} port {40000 + i % 20000} ssh2"
    elif kind == 1:
        body = f"sshd[{pid}]: Failed password for {user} from {ip} port {40000 + i % 20000} ssh2"
    elif kind == 2:
        body = f"sshd[{pid}]: Invalid user {user}x from {ip} port {40000 + i % 20000}"
    elif kind == 3:
        body = (
            f"sudo:   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
            f"COMMAND=/usr/bin/systemctl restart svc{i % 50}"
        )
    elif kind == 4:
        body = (
            f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1001) "
            "by (uid=0)"
        )
    elif kind == 5:
        body = f"CRON[{pid}]: pam_unix(cron:session): session closed for user {user}"
    else:
        body = f"systemd-logind[612]: New session {i % 9000} of user {user}."
    return f"{stamp} bench01 {body}\n"


def write_auth_log(path: Path, lines: int, seed: int = 10) -> int:
    rnd = random.Random(seed)  # noqa: S311 - synthetic test data, not security
    with path.open("w", encoding="ascii", newline="\n") as fh:
        for i in range(lines):
            fh.write(_line(i, rnd))
    return path.stat().st_size


def _context(path: Path, case_id: str, evidence_id: str) -> ParseContext:
    return ParseContext(
        path=path,
        evidence_id=evidence_id,
        case_id=case_id,
        source_file="auth.log",
        timezone="UTC",
        year=2026,
        reference_time=START,
        reference_source="benchmark",
        params={"timezone": "UTC", "year": 2026},
    )


def _rate(count: int, seconds: float) -> float:
    return round(count / seconds, 1) if seconds > 0 else 0.0


def setup_case(session: Session) -> dict[str, str]:
    """Case, evidence and parse job rows the events point to (throwaway data)."""
    case_id, evidence_id, job_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    session.execute(
        text("INSERT INTO cases (id, case_number, title) VALUES (:id, :n, 'Benchmark')"),
        {"id": case_id, "n": f"BENCH-{case_id.hex[:12]}"},
    )
    session.execute(
        text(
            "INSERT INTO evidence (id, case_id, label, kind, original_name, storage_uri, status) "
            "VALUES (:id, :c, 'EV-BENCH', 'log', 'auth.log', :uri, 'stored')"
        ),
        {"id": evidence_id, "c": case_id, "uri": f"s3://bench/{evidence_id}"},
    )
    session.execute(
        text(
            "INSERT INTO jobs (id, case_id, evidence_id, kind, parser, status) "
            "VALUES (:id, :c, :e, 'parse', 'linux_auth', 'succeeded')"
        ),
        {"id": job_id, "c": case_id, "e": evidence_id},
    )
    session.commit()
    return {"case_id": str(case_id), "evidence_id": str(evidence_id), "job_id": str(job_id)}


def bench_parse(path: Path, ids: dict[str, str]) -> dict[str, Any]:
    parser = get_parser("linux_auth")
    ctx = _context(path, ids["case_id"], ids["evidence_id"])
    started = time.perf_counter()
    count = sum(1 for _ in parser.parse(ctx))
    seconds = time.perf_counter() - started
    return {
        "lines": ctx.stats.records_read,
        "events": count,
        "seconds": round(seconds, 3),
        "lines_per_s": _rate(ctx.stats.records_read, seconds),
    }


def _rows(path: Path, ids: dict[str, str]) -> Iterator[dict[str, Any]]:
    parser = get_parser("linux_auth")
    for event in parser.parse(_context(path, ids["case_id"], ids["evidence_id"])):
        row, _ = to_row(
            event,
            case_id=ids["case_id"],
            evidence_id=ids["evidence_id"],
            job_id=ids["job_id"],
            parser_name=parser.name,
            parser_version=parser.version,
        )
        yield row


def bench_ingest(session: Session, path: Path, ids: dict[str, str], batch: int) -> dict[str, Any]:
    months: set[tuple[int, int]] = set()
    pending: list[dict[str, Any]] = []
    inserted = 0
    started = time.perf_counter()

    def flush() -> int:
        for row in pending:
            month = (row["ts"].year, row["ts"].month)
            if month not in months:
                months.add(month)
                session.execute(text("SELECT dfir_ensure_events_partition(:ts)"), {"ts": row["ts"]})
                session.commit()
        done = insert_event_rows(session, pending)  # the worker's insert path
        session.commit()
        return done

    for row in _rows(path, ids):
        pending.append(row)
        if len(pending) >= batch:
            inserted += flush()
            pending = []
    if pending:
        inserted += flush()
    seconds = time.perf_counter() - started
    session.execute(text("ANALYZE events"))
    session.commit()
    return {
        "events": inserted,
        "seconds": round(seconds, 3),
        "events_per_s": _rate(inserted, seconds),
        "batch": batch,
    }


def bench_search(session: Session, case_id: str, runs: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, query in QUERIES.items():
        node = parse(query)
        if node is None:
            continue
        stmt = (
            select(Event.id, Event.ts, Event.message)
            .where(Event.case_id == uuid.UUID(case_id), to_sql(node))
            .order_by(Event.ts.asc(), Event.id.asc())
            .limit(100)
        )
        timings: list[float] = []
        rows = 0
        for _ in range(runs):
            started = time.perf_counter()
            rows = len(session.execute(stmt).all())
            timings.append((time.perf_counter() - started) * 1000)
            session.commit()
        timings.sort()
        p95 = timings[min(len(timings) - 1, max(0, round(0.95 * len(timings)) - 1))]
        out[name] = {
            "query": query,
            "rows": rows,
            "p50_ms": round(statistics.median(timings), 2),
            "p95_ms": round(p95, 2),
        }
    count_started = time.perf_counter()
    total = session.execute(
        select(func.count()).select_from(Event).where(Event.case_id == uuid.UUID(case_id))
    ).scalar_one()
    session.commit()
    out["_count"] = {
        "rows": int(total),
        "ms": round((time.perf_counter() - count_started) * 1000, 2),
    }
    return out


def bench_detection(session: Session, case_id: str, batch: int) -> dict[str, Any]:
    rules = builtin_rules()
    engine = DetectionEngine(rules)
    raw_paths = {f for r in rules for f in r.fields if f.startswith("raw.")}
    raw_cols = [
        func.jsonb_extract_path_text(Event.raw, *(F.raw_path(name) or ())).label(name)
        for name in sorted(raw_paths)
    ]
    base = [
        Event.id,
        Event.ts,
        Event.evidence_id,
        *(getattr(Event, name) for name in sorted(F.TEXT_FIELDS | F.INT_FIELDS | F.IP_FIELDS)),
    ]
    stmt = (
        select(*base, *raw_cols)
        .where(Event.case_id == uuid.UUID(case_id))
        .order_by(Event.ts, Event.id)
    )
    started = time.perf_counter()
    seen = 0
    for row in session.execute(stmt, execution_options={"yield_per": batch}):
        engine.feed(dict(row._mapping))
        seen += 1
    session.commit()
    seconds = time.perf_counter() - started
    return {
        "rules": len(rules),
        "events": seen,
        "seconds": round(seconds, 3),
        "events_per_s": _rate(seen, seconds),
        "alert_drafts": len(engine.drafts),
    }


def run(
    engine: Engine, workdir: Path, *, events: int, search_runs: int, batch: int = 1000
) -> dict[str, Any]:
    path = workdir / "bench-auth.log"
    size = write_auth_log(path, events)
    with Session(engine) as session:
        ids = setup_case(session)
        result: dict[str, Any] = {
            "input": {"lines": events, "bytes": size},
            "parse": bench_parse(path, ids),
            "ingest": bench_ingest(session, path, ids, batch),
            "search": bench_search(session, ids["case_id"], search_runs),
            "detection": bench_detection(session, ids["case_id"], 2000),
        }
    path.unlink(missing_ok=True)
    result["case_id"] = ids["case_id"]
    return result
