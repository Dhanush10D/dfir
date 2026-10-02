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

## Latest result (2026-10-02)

Host:
- Development laptop: Intel Core i3-N305 (8 efficiency cores), 7.8 GB RAM, Windows 11, on AC
  power with the Balanced plan.
- Docker Desktop 29.3.1 (WSL 2 VM: 8 CPUs, 3.9 GB).
- Python 3.12.10 on the host; Postgres 16 with pgvector in compose.
- Only postgres, redis and minio were running.

| Measure | Result | Floor (spec) |
|---|---|---|
| Parse (`linux_auth`, 200,000 lines, 19.7 MB) | **24,288 lines/s** (8.2 s) | ≥ 20,000 lines/s |
| Ingest (200,000 events, batches of 1000) | **3,240 events/s** (61.7 s) | ≥ 2,000 events/s |
| Search p95, `event_code:` field | 6.5 ms (p50 4.5 ms) | ≤ 2,000 ms |
| Search p95, `AND` | 86.8 ms (p50 44.9 ms) | ≤ 2,000 ms |
| Search p95, `OR` | 8.7 ms (p50 6.0 ms) | ≤ 2,000 ms |
| Search p95, `ip:` | 107.9 ms (p50 73.5 ms) | ≤ 2,000 ms |
| Search p95, wildcard | 6.7 ms (p50 4.7 ms) | ≤ 2,000 ms |
| Search p95, `NOT` | 4.7 ms (p50 4.0 ms) | ≤ 2,000 ms |
| Count of all 200,000 events | 38.6 ms | — |
| Detection (25 rules over 200,000 events) | 27.5 s, 7,264 events/s, 4 alert drafts | ≤ 300 s |

Notes:
- **Load matters.** Parsing is single-threaded CPU work on efficiency cores. With a video call or
  a browser busy on the same laptop, runs of the earlier code measured 13,000–18,500 lines/s.
  Run the benchmark on an idle host.
- **Parser speed-up (2026-10-02).** Before, `linux_auth` converted every BSD timestamp to UTC
  with a full round trip, about seven timezone operations per line, only to detect DST gaps and
  overlaps. It now compares the fold=0 and fold=1 offsets first; they differ only in a gap or an
  overlap (PEP 495). Only then does it run the round trip that tells the two apart. Output and
  warnings are identical: checked against the old code on 736,512 local times in 7 zones
  (including Lord Howe's 30-minute DST, Samoa's skipped day in 2011, Newfoundland, India and
  UTC), plus the golden and hostile-input tests. The parse rate on the same idle host went from
  about 19,000–20,700 to 21,300–24,300 lines/s.
- An earlier build of the verify script used lower floors (5,000 lines/s, 1,500 events/s) without
  recording a decision. The independent review flagged this, and the spec floors are back.
- These are single-host numbers for a development laptop, not a capacity statement. A server with
  more memory for Postgres will ingest faster. Parsing is one job at a time per sandbox replica
  (`docs/hardening.md`).
