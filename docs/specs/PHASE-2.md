# PHASE 2: Processing pipeline

## Goal
Turn stored evidence into a normalized, queryable timeline without ever touching the original.
An analyst submits parse jobs for a finalized evidence item; a Celery worker claims the job, checks
the custody chain and re-hashes the vault object against the signed ingest SHA-256, parses a
read-only scratch copy with a pure, streaming parser (EVTX, Linux auth.log/secure/syslog), normalizes
every record to the Appendix A field dictionary (UTC `ts` + original `ts_original`), and bulk-inserts
events with deterministic ids into monthly partitions. Every run leaves a run manifest (tools,
parameters, timezone/year assumptions, records read vs. emitted vs. skipped vs. errored, samples)
pinned by a signed `processed` custody entry. Jobs have progress, cancel, retry (manual and automatic
with backoff) and idempotent reprocess; the timeline API serves filtered, keyset-paginated events
with case-scoped RBAC.

## In scope
- Parser framework (guide 10.2): `Parser` protocol, `Event`, `ParseContext`, `ParseStats`
  (`records_read == events_emitted + skipped + errors` is enforced), `ParseLimits`, registry with
  content sniffing (`detect`), shared bounded line reader for plain/gzip text.
- Parsers: `evtx` 1.0.0 (python-evtx 0.8.1, XML via defusedxml; Security/System/Sysmon/PowerShell/
  Eventlog mappings incl. 4624/4625/4688/4697/4698/4720/4728/4732/4776/5152/5156/1102/104/7045/
  Sysmon 1/3/11), `linux_auth` 1.0.0 (BSD syslog, RFC 3339, RFC 5424; sshd, sudo, su, PAM,
  useradd/usermod/userdel/passwd, systemd-logind; non-auth lines become `syslog` events).
- Normalization (`parsers/normalize.py`): UTC conversion, NUL/surrogate scrubbing, bounded text and
  `raw`, inet/int validation, deterministic `uuid5` event ids.
- Jobs (10.6, 14.5): `JobService` (submit with idempotency key, cancel, retry, reprocess, list,
  detail), `ProcessingService` (claim with fencing token and lease, integrity check, scratch copy,
  batches, manifest, custody), Celery task `dfirbench.parse_evidence` on queue `parse`.
- Timeline API: list with filters + keyset cursor, single event with `raw`.
- Migration 0004 and least-privilege grants; compose worker scratch volume; live smoke script.

## Out of scope (later phases, see `docs/BACKLOG.md`)
Search language, histogram/facets/context/export endpoints (Phase 4); progress over WebSocket/SSE
(Phase 4); evidence status `processing/processed` state machine; Hayabusa enrichment and detection
jobs (Phase 3); deep parsers, journal export, wtmp, bash_history (Phase 5/6); per-job sandbox
containers (Phase 10); scheduled reaper for lost queue messages, nightly re-verify, partition
retention (scheduler, Phase 3).

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/parsers/base.py` | `Event`, `ParseStats`, `ParseLimits`, `ParseContext`, `Parser` protocol, `ParserInputError` |
| `backend/app/parsers/registry.py` | `register`, `get_parser(name)`, `all_parsers()`, `detect(head, filename)` |
| `backend/app/parsers/textio.py` | `iter_lines(path, limits, stats, progress)` (line cap, gzip bomb guards), `head_text` |
| `backend/app/parsers/evtx.py`, `linux_auth.py` | the two parsers (pure, streaming) |
| `backend/app/parsers/normalize.py` | `to_row(event, ...) -> (row, size)`, `event_id(...)` |
| `backend/app/services/jobs.py` | `JobService.submit/cancel/retry/reprocess/get/list_for_case`, `validate_params`, `idempotency_key` |
| `backend/app/services/processing.py` | `ProcessingService.run(job_id, allow_retry, stop_exceptions) -> RunResult`, `EventSink`, `lock_running` |
| `backend/app/services/events.py` | `EventService.timeline/get`, `EventFilter`, cursor encode/decode |
| `backend/app/workers/tasks/parse.py` | `parse_evidence(job_id)` task, `backoff_seconds`, `service_factory` |
| `backend/app/workers/dispatch.py` | `dispatch_parse(job_id)` (API side, injected via `get_job_dispatcher`) |
| `backend/app/api/v1/jobs.py`, `events.py`; `schemas/jobs.py`, `events.py` | HTTP layer only |
| `backend/app/services/cases.py` | `close()` refuses while jobs are queued/running |
| `scripts/phase2-smoke.py`, `scripts/verify-phase2.sh` | live smoke + full verification |

## Data model changes (`0004_processing.py`)
- `jobs`: `heartbeat_at`, `superseded_by` (FK jobs), `ck_jobs_progress_range`, indexes
  `(case_id, queued_at)`, `(evidence_id)`, partial unique `uq_jobs_active_parse (evidence_id, parser)
  WHERE kind='parse' AND status IN ('queued','running')`.
- `events`: index `(evidence_id, parser_name)`.
- `dfir_ensure_events_partition(ts)`: `SECURITY DEFINER`, `search_path = pg_catalog, pg_temp`,
  builds the month's partition detached, moves stray rows out of `events_default`, attaches it, and
  revokes all app-role privileges on the new partition. EXECUTE revoked from PUBLIC, granted to the
  app role.
- Grants for `dfirbench_app`: `events` SELECT/INSERT/DELETE (no UPDATE/TRUNCATE; DELETE is needed by
  reprocess), `jobs` SELECT/INSERT/UPDATE (no DELETE: run manifests are provenance), nothing on
  partitions (rows are reached through the parent only).

## Job lifecycle and concurrency rules
- `queued -> running -> succeeded | partial | failed | cancelled`; `failed|partial|cancelled ->
  queued` by retry (not when superseded); reprocess creates a new job that supersedes the pair's
  previous jobs.
- Idempotency key = SHA-256 of canonical `(evidence_id, parser, parser_version, params)`; the same
  submission returns the existing job. Creation runs under an advisory lock per (evidence, parser)
  plus `FOR NO KEY UPDATE` on the pair's current rows; `uq_jobs_active_parse` is the backstop.
- Submit/retry/reprocess take `FOR SHARE` on the case row and re-check it is open; case close takes
  `FOR UPDATE` and refuses while jobs are queued/running, so no job ever writes to a closed case.
- Claim: one `UPDATE ... WHERE status='queued' OR (running AND heartbeat older than JOB_LEASE_S)
  RETURNING attempts`; `attempts` is the fencing token. Every batch and the finish lock the job row
  (`FOR NO KEY UPDATE`) and re-check `(status='running', attempts=token)`; a cancel committed before
  a batch means that batch is not written, and a cancelled job is never flipped to succeeded.
- Replace: under the job lock the pair's previous events are deleted, then batches insert with
  deterministic ids and `ON CONFLICT DO NOTHING` (retries/reprocess never duplicate).
- Integrity: custody chain must verify against trusted keys (signer + trust file); SHA-256 and size
  of the streamed vault version must equal the signed `ingested` entry. Byte mismatch or missing
  object: job `failed`, custody `hash_failed`, evidence `failed`, admins notified. Chain problems:
  custody `verification_failed`.
- Task: transient errors (DB/vault I/O) re-queue under the row lock and retry with exponential
  backoff (10 s doubling, cap 10 min, 25 % jitter, `JOB_MAX_AUTO_RETRIES`); `busy` (live lease) and
  unexpected errors retry after the lease; soft time limit -> `partial` with the events written.

## API changes (all under `/api/v1`)
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/parsers` | authenticated | name, version, description, accepted params |
| POST | `/evidence/{id}/process` | `evidence:add` on the case | body `{parsers: "auto" \| [names], params: {timezone?, year?}}` -> 202 `{jobs, created}`; 409 closed case / not stored / active job; 422 unknown parser / params; 503 queue down (job recorded as failed, retryable) |
| GET | `/cases/{id}/jobs` | `case:read` | filters `status`, `evidence_id`, `limit` |
| GET | `/jobs/{id}` | `case:read` | detail incl. `run_manifest`, `counts` |
| POST | `/jobs/{id}/cancel` | `evidence:add` | queued/running only |
| POST | `/jobs/{id}/retry` | `evidence:add` | failed/partial/cancelled, not superseded, open case |
| POST | `/jobs/{id}/reprocess` | `evidence:add` | optional `{params}`; new job replaces the events |
| GET | `/cases/{id}/events` | `case:read` | `from`, `to` (tz required), `evidence_id`, `job_id`, `host`, `user`, `event_code`, `event_category`, `action`, `outcome`, `source_type`, `ip`, `q` (FTS), `order`, `limit` (1-500), `cursor` |
| GET | `/cases/{id}/events/{event_id}` | `case:read` | includes `raw` |

A case the caller cannot read answers 404 for every case-scoped id (job, event, evidence).

## Run manifest
`job_id, evidence_id, case_id, parser, parser_version, params, attempt, worker, tools{python,
dfirbench, tzdata, python-evtx, defusedxml}, source_file, evidence_sha256, evidence_size,
evidence_version_id, limits, replaced_previous_events, started_at, finished_at, duration_ms, outcome,
error, counts{records_read, events_emitted, skipped, errors, inserted, outside_partition_window},
warnings{code: n}, warning_samples, error_samples, assumptions{timezone, year_source, reference_time,
first_line_year, year_rollovers, compression, chunks_*, incomplete}, partitions,
container_image_digest`. Its canonical SHA-256 is signed into the `processed` custody entry.

## Test plan
- Unit (no Docker): golden files for all fixtures (`tests/fixtures/golden/*.json`, ids included);
  hostile input (over-long lines, gzip bombs by ratio and size, truncated gzip, DST gap/overlap,
  year rollover, bad timestamps, invalid UTF-8/NUL, corrupt EVTX record body/header, truncated
  EVTX, DTD rejection, hypothesis fuzzing of both parsers keeping the record balance); normalization;
  params and idempotency keys; cursors and filters; Celery task retry decisions (task called
  directly, no broker); settings defaults.
- Integration (compose Postgres, fake vault): end-to-end auth.log and EVTX jobs, manifest and custody,
  partitions; timeline filters, pagination, detail; idempotent submit and reprocess (same ids, no
  duplicates, params change); 8 concurrent submits -> 1 job; 6 concurrent workers -> 1 run; cancel
  mid-run (no later batch, stays cancelled), retry, stale-token fencing, lease reclaim; dispatch
  failure; integrity mismatch; closed-case rules; validation; RBAC and cross-case scoping; app-role
  privilege denials; migration grants and SECURITY DEFINER partition function.
- Live (compose): `scripts/phase2-smoke.py` through the real API, Redis and Celery worker.

## Acceptance criteria (executable)
1. Parser framework + registry: `pytest tests/unit/test_parsers_golden.py tests/unit/test_parsers_hostile.py`.
2. Celery jobs with retry/cancel/progress: `pytest tests/unit/test_processing_units.py -k task` and
   `pytest tests/integration/test_processing.py -k "cancel or dispatch or concurrent"`.
3. EVTX + Linux auth/syslog parsers with normalization: golden tests + `-k "evtx_job or auth_log"`.
4. Run manifests: `test_auth_log_job_end_to_end` (counts, tools, assumptions, signed digest).
5. Idempotent reprocess: `test_idempotent_submit_and_reprocess`.
6. Timeline API with RBAC: `test_timeline_filters_pagination_and_detail`, `test_rbac_and_case_scoping`.
7. Live stack: `scripts/phase2-smoke.py` prints `PHASE 2 SMOKE PASSED` (also in CI).

## Verification command
```bash
bash scripts/verify-phase2.sh
```
(compose up --build, probes, app-role denials, alembic upgrade + check + 0004 round trip, Phase 1 and
Phase 2 live smoke, ruff, mypy, bandit, full pytest with coverage >= 80 %).

## Implementation notes / deliberate deviations
- Events are stored in PostgreSQL only (Standard profile); progress is persisted on the job row
  (polled) instead of Redis pub/sub + WebSocket, which arrives with the UI in Phase 4.
- Timeline listing is `GET /cases/{id}/events` with query parameters; the guide's
  `POST /events/search` with the search language is Phase 4.
- A reprocess deletes then re-inserts in separate short transactions, so a reader can briefly see a
  partial timeline for that evidence; ids are deterministic, so the final state never duplicates.
- Evidence `status` stays `stored` during processing (job state carries progress); the
  `processing/processed` evidence states are deferred.
- EVTX fixtures are byte-identical copies of `samples/new-user-security.evtx` and
  `samples/Security_short_selected.evtx` from github.com/omerbenamram/evtx (MIT/Apache-2.0).
