# Performance benchmark

Phase 10 (spec `docs/specs/PHASE-10.md`, decision 8; acceptance criterion 7). `scripts/benchmark.py`
creates a throwaway database on the compose Postgres, migrates it, and measures the real code paths:
synthetic `auth.log` parse throughput, event ingest (the worker's COPY-based insert path, batches
of 1000), search latency for six queries of the search language, and one detection run with the
built-in rules. Then it drops the database. CI runs only the 500-event integration test of the same
code (`tests/integration/test_benchmark.py`).

```bash
backend/.venv/Scripts/python scripts/benchmark.py --events 200000 --search-runs 20 \
  --min-parse-lps 20000 --min-ingest-eps 2000 --max-search-p95-ms 2000 --max-detect-s 300 \
  --json-out var/benchmark.json
```

`scripts/verify-phase10.sh` runs exactly this command, so the verify run enforces the spec floors.

## Latest result (2026-10-02, `verify-phase10.sh`)

Host:
- Development laptop: Intel Core i3-N305 (8 cores), 7.8 GB RAM, Windows 11.
- Docker Desktop 29.3.1 (WSL 2 VM: 8 CPUs, 3.9 GB).
- Python 3.12.10 on the host; Postgres 16 with pgvector in compose.
- The api, worker, web and sandbox containers were stopped while it ran.

| Measure | Result | Floor (spec) |
|---|---|---|
| Parse (`linux_auth`, 200,000 lines, 19.7 MB) | **20,565 lines/s** (9.7 s) | ≥ 20,000 lines/s |
| Ingest (200,000 events, batches of 1000) | **2,773 events/s** (72.1 s) | ≥ 2,000 events/s |
| Search p95, `event_code:` field | 4.8 ms (p50 3.6 ms) | ≤ 2,000 ms |
| Search p95, `AND` | 82.1 ms (p50 37.3 ms) | ≤ 2,000 ms |
| Search p95, `OR` | 6.5 ms (p50 5.5 ms) | ≤ 2,000 ms |
| Search p95, `ip:` | 150.5 ms (p50 95.3 ms) | ≤ 2,000 ms |
| Search p95, wildcard | 9.3 ms (p50 7.2 ms) | ≤ 2,000 ms |
| Search p95, `NOT` | 9.4 ms (p50 6.0 ms) | ≤ 2,000 ms |
| Count of all 200,000 events | 39.6 ms | — |
| Detection (25 rules over 200,000 events) | 25.9 s, 7,713 events/s, 4 alert drafts | ≤ 300 s |

Notes:
- The parse margin is thin on this host: 2.8 % above the floor. A run next to other load can miss
  it. That is a real signal on this machine, so re-run `verify-phase10.sh` on an idle host before
  you change the floor.
- An earlier build of the verify script used lower floors (5,000 lines/s, 1,500 events/s) without
  recording a decision. The independent review flagged this, and the spec floors are back.
- These are single-host numbers for a development laptop, not a capacity statement. A server with
  more memory for Postgres will ingest faster. Parsing is one job at a time per sandbox replica
  (`docs/hardening.md`).
