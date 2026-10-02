# PHASE 10: Hardening + validation

## Goal
Harden the Standard-profile stack against hostile evidence and a compromised application process,
and produce the validation evidence a DFIR tool needs (guide 20, 21.4, 22). Parsers stop running
inside the networked worker: every parse job runs in a separate **parser sandbox container** with
no network, a read-only root file system, a read-only evidence mount, no capabilities, a non-root
user and resource limits. The API and workers log in to PostgreSQL as the least-privilege role
itself, so a compromised process can no longer `RESET ROLE` back to the owner. The phase adds
per-IP rate limits on authentication, security regression tests, dependency/image/secret scans,
Prometheus metrics, an encrypted and signed backup with a tested restore that re-verifies every
evidence hash and custody chain, a performance benchmark, and the tool validation appendix
(guide 22.7).

## In scope / Out of scope
In scope:
* `app/sandbox/` (protocol, child runner, sandbox server, worker client) and the `parser-sandbox`
  compose service; `ProcessingService` runs parse jobs through it when `SANDBOX_MODE=spool`.
* Database login as `dfirbench_app` (no owner login for the API/worker), provisioned by the
  migrate job from `DATABASE_MIGRATE_URL`; prod refuses an owner login.
* Row-locking fix in `IAMService.update_user` (BACKLOG Phase 1 deadlock + last-admin race).
* Per-IP rate limits on `/auth/login`, `/auth/mfa/verify`, `/auth/refresh`.
* Security tests: every route requires authentication unless allowlisted; every case-scoped route
  refuses a non-member; security headers from one nginx include file (BACKLOG Phase 4).
* `GET /metrics` (Prometheus text format, bearer token, not proxied by nginx).
* `app/services/integrity.py` + `python -m app.cli integrity-check` (read-only) and
  `backup-manifest` (signed state summary); `app/ops/backupcrypt.py` (streaming AES-256-GCM);
  `scripts/backup.py` and `scripts/restore.py`; a restore drill into a separate compose project.
* `scripts/benchmark.py` (parse, ingest, search, detection) and `docs/validation/BENCHMARK.md`.
* `scripts/tool-validation.py`, `docs/validation/tool-validation.json` and
  `docs/validation/TOOL_VALIDATION.md` (guide 22.7), kept current by a unit test.
* Scans: `scripts/scan.sh` (pip-audit, npm audit, gitleaks, Trivy image scan + CycloneDX SBOMs)
  and a CI `security` job; Volatility 3 dependencies pinned with hashes (BACKLOG Phase 6).
* CI compose-smoke also runs the Phase 7, 9 and 10 smokes (BACKLOG Phase 7/9).
* `docs/hardening.md`, `docs/backup-restore.md`, smoke + verify scripts, tests.

Out of scope (decisions per BACKLOG item are in the table at the end): Celery beat and everything
that needs a scheduler (job reaper, nightly re-verify, custody anchors, reapers, outbound sweeps);
TLS termination in compose; OpenTelemetry traces; cosign image signing; new forensic engines;
new parsers, detection content and UI features; JWT/TOTP key rotation; KMS/HSM key storage.

## Standard-profile decisions (made without the owner; recorded here)
1. **One long-lived sandbox container, one job at a time, a process per job.** The guide (10.7)
   asks for a container per parser job. Starting containers from the worker needs the Docker
   socket, which is root on the host, so the worker never gets it. Instead compose runs a
   `parser-sandbox` service from the worker image with `network_mode: none`, `read_only: true`,
   `cap_drop: [ALL]`, `no-new-privileges`, the default seccomp profile, `init: true`,
   `pids_limit`, `mem_limit` and `cpus`. **uid split** (added after the independent review: with
   one shared uid a parser could stop the server and outlive its job): the container starts as
   root with only `cap_add: [SETUID, SETGID, KILL, DAC_OVERRIDE]`; the server keeps euid 0,
   touches files as `10001` (fsuid) and starts every child as uid `10002`, group `10001`, no
   supplementary groups and no capabilities, so the child cannot signal the server. It shares two volumes with the worker:
   `spoolin` (read-write in the worker, **read-only** in the sandbox: the evidence copy and the
   request) and `spoolout` (the sandbox writes the output stream there). A third volume,
   `sandboxwork`, is mounted only in the sandbox (per-job scratch for external engines).
   * The worker serialises access with an exclusive file lock (`fcntl.flock`, `msvcrt.locking`
     on Windows) on `<SCRATCH_DIR>/sandbox-slot.lock` in its private scratch volume, so the
     sandbox only ever sees **one job's evidence**: the slot holder wipes stale spool entries,
     fetches the evidence (hash-verified as before) directly into `spoolin/<job dir>/`, writes
     `request.json` and then the `ready` marker, waits, consumes the output and deletes both
     spool directories before it releases the lock. A crashed holder's lock is released by the
     kernel; the next holder wipes what it left.
   * The sandbox server is a subreaper (`PR_SET_CHILD_SUBREAPER`): it runs the parser as a child
     process (`python -m app.sandbox.child`) with its own session, a clean environment (no
     database, object-store or key material exists in the container at all), `RLIMIT_AS`,
     `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_CORE=0` set by the child before it
     reads evidence, a wall-clock timeout, an output cap and a line-length cap. After the child
     exits (or is killed on timeout, cancel, output overflow or protocol violation) the server
     kills and reaps **every remaining descendant** (orphans are re-parented to it) and deletes
     the job's work directory; only then does it write `exit.json`. Leftover processes therefore
     cannot touch a later job, and the next job only starts after the worker removed the
     previous one's spool directories.
   * Trade-off, documented in `docs/hardening.md`: jobs share one container (isolation between
     jobs is by process, lock and sweep, not by a fresh container per job), and throughput is
     one parse at a time per sandbox replica. Bundle unpacking (`BundleIngestService`: stdlib
     `zipfile` + JSON with the Phase 5 bounds, then uploads to the vault) stays in the worker
     because it needs the vault; parser auto-detection in the API reads only the first bytes and
     compares magic values. Both are listed as residual risks.
2. **The output is untrusted.** The child writes one line per item to stdout: `E{json}` events,
   `P<fraction>` progress, `R{json}` the final result (stats). The server copies `E`/`R` lines to
   `spoolout/<dir>/events.jsonl`, records progress in `progress`, and writes `exit.json` with the
   reason (`ok`, `timeout`, `cancelled`, `output_limit`, `protocol`, `crashed`, `failed_start`),
   the byte count and the SHA-256 of `events.jsonl`. The worker first checks size and SHA-256
   against `exit.json`, then rebuilds every `Event` with strict type checks (bad lines are counted
   errors), runs the unchanged `to_row` normalisation and inserts under the job lock as before.
   `case_id`, `evidence_id`, `job_id` and the deterministic event id are always set by the
   worker, so sandbox output can only describe its own evidence. Events are serialised without
   loss (`jsonable` keeps strings unshortened), so the stored rows are identical to in-process
   parsing; a unit test proves it for every golden fixture of all 16 parsers.
3. **Modes.** `SANDBOX_MODE=none` (default; tests, CI unit/integration jobs, Windows dev host)
   parses in-process as before; `SANDBOX_MODE=spool` uses the sandbox (compose default).
   `APP_ENV=prod` refuses `none`. The old placeholder values `docker`/`k8s` (never implemented)
   are removed. The run manifest records `sandbox` (mode and the `exit.json` summary).
4. **Database login.** Migration 0002 created `dfirbench_app` as NOLOGIN and the app connected as
   the owner with `SET ROLE`, so any SQL injection or code execution in the API could `RESET
   ROLE` to a superuser. Now `python -m app.cli provision-app-login` (run by the migrate job after
   `alembic upgrade head`, connected through `DATABASE_MIGRATE_URL` as the owner) gives
   `dfirbench_app` LOGIN with the password from `DATABASE_URL`, sent as a client-computed
   SCRAM-SHA-256 verifier (the plaintext never reaches the server or its logs). It refuses if the
   role is a superuser, has CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS or is a member of any other
   role. API and worker connect with `DATABASE_URL=postgresql+psycopg://dfirbench_app:...`.
   Alembic uses `DATABASE_MIGRATE_URL` when set, else `DATABASE_URL` (tests, CI, host scripts).
   Prod refuses a `DATABASE_URL` whose user differs from `DATABASE_APP_ROLE` and the dev
   placeholder password. No schema migration is needed (roles are not tracked by Alembic).
5. **Rate limits on authentication** (guide 14.3): per client IP (the proxy-trusted address),
   fixed one-minute windows in Redis: `AUTH_RATE_LIMIT_PER_MINUTE` (default 30) shared by
   `/auth/login` and `/auth/mfa/verify`, `AUTH_REFRESH_RATE_LIMIT_PER_MINUTE` (default 120) for
   `/auth/refresh`. Over the limit: 429 `rate_limited` with `Retry-After`, audited as
   `auth.rate_limited`. Redis down: 503 (fail closed, as the AI limiter). The account lockout
   stays as the per-account control.
6. **Metrics** (guide 21.4) without a new dependency: `app/core/metrics.py` renders the
   Prometheus text format. HTTP request counter and latency histogram by method, route template
   and status class (no ids in labels); scrape-time gauges from the database and Redis, cached
   for `METRICS_CACHE_S`: jobs by kind and status, job duration (average and maximum over 24 h
   by parser), events inserted in the last hour, Celery queue depth, custody verification
   failures, outbound deliveries by status, AI calls/tokens/cost today. `GET /metrics` is outside
   `/api/v1` (nginx does not proxy it, and the audit middleware does not log scrapes), returns 404
   unless `METRICS_TOKEN` is set and then needs `Authorization: Bearer <token>` (constant-time
   compare). Prod requires 32+ characters. Traces (OpenTelemetry) stay out of scope.
7. **Backup and restore** (guide 7.6, 20.2, 21.6). `scripts/backup.py` (host, backend venv)
   stops `web`, `api` and `worker` for a short maintenance window so the state is consistent,
   then writes into a new directory:
   * `manifest.json`: produced inside a one-off api container (`python -m app.cli
     backup-manifest`) and **signed with the custody key**: Alembic revision, row counts of the
     forensic tables, every evidence item's SHA-256, size, vault version and custody chain head
     (`seq`, `entry_hash`), every signed report's hashes;
   * `db.dump.enc` (`pg_dump -Fc` in the postgres container), `objects.tar.enc` (the MinIO volume,
     read-only mount, MinIO stopped meanwhile so object versions, Object Lock retention and
     metadata are copied exactly), `keys.tar.enc` (custody key volume);
   * `index.json`: file names, sizes and SHA-256 of the encrypted files.
   Encryption: `app/ops/backupcrypt.py`, a STREAM construction (AES-256-GCM over 1 MiB chunks,
   nonce = random prefix + chunk counter + last-chunk flag, header as AAD, scrypt key from
   `BACKUP_PASSPHRASE`, at least 20 characters): truncation, reordering, a wrong passphrase or
   any bit flip fails. The passphrase is read from the environment only and never printed.
   `scripts/restore.py --project NAME` restores into **empty** volumes of another compose project
   (refuses non-empty volumes; the live project needs `--force`), starts its postgres and MinIO
   on other ports, `pg_restore`s, and runs `python -m app.cli integrity-check --manifest`
   against it with trusted keys supplied by the operator (never taken from the backup).
   `integrity-check` is read-only (`SET TRANSACTION READ ONLY`, no custody appends): it verifies
   the manifest signature, Alembic revision and counts; every custody chain against the trusted
   keys; that chain heads equal the manifest (no truncation, no extension); every original's
   bytes at the recorded version against the signed ingest SHA-256 and size; Object Lock
   retention is present; published signing keys equal the trusted ones. Exit 1 on any problem.
   Without `--manifest` it is the on-demand "re-verify everything" check (cron-able).
8. **Benchmark**: `scripts/benchmark.py` runs against a throwaway database on the compose
   Postgres (like the integration tests): synthetic auth.log parse throughput, batched event
   ingest (the worker's insert path), search latency p50/p95 for six queries of the search
   language, and a detection run with the built-in rules. It prints JSON, can enforce floors
   (`--min-*`), and the verify script runs it with 200,000 events. The latest numbers and host
   description are recorded in `docs/validation/BENCHMARK.md`. CI runs only a 500-event
   integration test of the same code.
9. **Tool validation** (guide 22.7): `scripts/tool-validation.py` runs every parser on its golden
   fixtures (the same cases as the golden tests), the detection rules on their positive and
   negative fixtures, and lists the integrity tests of guide 22.3 with the test that proves each;
   it writes `docs/validation/tool-validation.json` (fixture SHA-256, parser version, records
   read/emitted/skipped/errors, SHA-256 of the normalised output, pinned engine versions) and the
   generated table in `TOOL_VALIDATION.md`. `--check` fails when either is stale; a unit test runs
   it. Engines replaced by fake binaries in tests (tsk_fs, volatility, zeek) are marked as such.
10. **Scans**: `scripts/scan.sh` (run by the verify script; needs network) and a CI `security`
    job. Gating: gitleaks (whole history, `.gitleaks.toml` allowlists test fixtures that contain
    fake secrets on purpose), pip-audit on the backend environment and `npm audit
    --audit-level=high` fail the run; Trivy fails on CRITICAL findings with a fix available in
    Python packages, and reports OS-package findings without failing (base-image updates are a
    rebuild, recorded in `docs/hardening.md`). Ignored advisories need an entry with a reason in
    `.trivyignore` / `scripts/scan-ignore.txt`. SBOMs (CycloneDX: Python environment, npm, both
    images) are written to `var/scan/` locally and uploaded as CI artifacts.

## Files and interfaces
* `backend/app/sandbox/protocol.py`: `SandboxRequest` (Pydantic), `encode_event(Event) -> bytes`,
  `decode_event(bytes) -> Event` (raises `ProtocolError`), `ChildResult`, `decode_result`,
  `jsonable(value)`, `ExitInfo`, file-name constants and caps.
* `backend/app/sandbox/child.py`: `main(argv)`: `set_limits(...)`, read the request, run the
  parser, write lines to stdout.
* `backend/app/sandbox/server.py`: `SandboxServer(in_dir, out_dir, work_dir, policy).run_once() ->
  str | None`, `serve_forever()`, `sweep_descendants(...)`, `main()` (refuses root),
  `--health`.
* `backend/app/sandbox/client.py`: `SandboxSlot` (context manager: lock, wipe, job dir),
  `SandboxClient.run(slot, request, *, tick) -> SandboxOutput`, `SandboxOutput.events()`,
  `.result`, `.exit`.
* `backend/app/services/processing.py`: parse through the sandbox in spool mode (same claim,
  fencing, custody, replace and batch logic).
* `backend/app/config.py`: `SANDBOX_MODE` (`none`|`spool`), `SANDBOX_IN_DIR`, `SANDBOX_OUT_DIR`,
  `SANDBOX_START_TIMEOUT_S`, `DATABASE_MIGRATE_URL`, `AUTH_RATE_LIMIT_PER_MINUTE`,
  `AUTH_REFRESH_RATE_LIMIT_PER_MINUTE`, `METRICS_TOKEN`, `METRICS_CACHE_S`; prod checks.
* `backend/app/db/provision.py`: `scram_sha256_verifier(password, salt, iterations)`,
  `provision_app_login(owner_engine, role, password)`; CLI `provision-app-login`.
* `backend/app/services/iam.py`: `update_user` locks actor, target and all active admins in id
  order before reading them.
* `backend/app/api/v1/auth.py`, `app/deps.py` (`get_auth_limiter`).
* `backend/app/core/metrics.py`, `backend/app/services/metrics.py`, `backend/app/api/metrics.py`.
* `backend/app/services/integrity.py`: `IntegrityChecker.check(manifest=None) -> IntegrityReport`,
  `build_manifest(session, signer) -> dict`, `verify_manifest_signature(...)`.
* `backend/app/ops/backupcrypt.py`: `encrypt_stream(src, dst, passphrase)`,
  `decrypt_stream(src, dst, passphrase)`, `check_passphrase(value)`.
* `backend/app/cli.py`: `provision-app-login`, `integrity-check`, `backup-manifest`.
* `scripts/backup.py`, `scripts/restore.py`, `scripts/benchmark.py`, `scripts/tool-validation.py`,
  `scripts/scan.sh`, `scripts/phase10-smoke.py`, `scripts/verify-phase10.sh`.
* `infra/compose.yaml` (`parser-sandbox`, volumes, login URL, migrate command, metrics token),
  `infra/docker/worker.Dockerfile` (spool directories; Volatility constraints with hashes,
  `infra/docker/volatility-requirements.txt`), `infra/docker/security-headers.conf` +
  `nginx.conf`, `.github/workflows/ci.yml`, `.gitleaks.toml`, `.trivyignore`, `.env.example`.
* Docs: `docs/hardening.md`, `docs/backup-restore.md`, `docs/validation/BENCHMARK.md`,
  `docs/validation/TOOL_VALIDATION.md`, `docs/validation/tool-validation.json`.

## Data model changes
None. No migration: the login change is role provisioning (not schema) and is re-run by the
migrate job; `alembic check` stays clean. The verify script still round-trips the latest
migrations on the live data the smokes leave, and checks that the provisioned login survives it.

## API changes
* `GET /metrics` (root, not `/api/v1`): Prometheus text; 404 when `METRICS_TOKEN` is unset, 401
  without the right bearer token.
* `/auth/login`, `/auth/mfa/verify`, `/auth/refresh`: 429 `rate_limited` per client IP.

## Settings (new)
`SANDBOX_MODE` (now `none`|`spool`), `SANDBOX_IN_DIR`, `SANDBOX_OUT_DIR`,
`SANDBOX_START_TIMEOUT_S` (120), `DATABASE_MIGRATE_URL`, `AUTH_RATE_LIMIT_PER_MINUTE` (30),
`AUTH_REFRESH_RATE_LIMIT_PER_MINUTE` (120), `METRICS_TOKEN`, `METRICS_CACHE_S` (15). Sandbox
server (its own environment, not `Settings`): `SANDBOX_CHILD_MEMORY_MB` (2048),
`SANDBOX_CHILD_CPU_S` (3600), `SANDBOX_MAX_RUN_S` (3600), `SANDBOX_MAX_OUTPUT_MB` (4096),
`SANDBOX_MAX_LINE_KB` (4096). Backup: `BACKUP_PASSPHRASE` (environment of the backup/restore
scripts only).

## Test plan
* Unit: protocol round trip, strict decoding of hostile lines, result validation, `jsonable`
  equivalence with in-process normalisation for every golden fixture (`test_sandbox_protocol.py`);
  sandbox server with a real child process: success, input error, crash, timeout, cancel, output
  cap, line cap, abandoned job, stale-dir wipe, descendant sweep on a fake `/proc`
  (`test_sandbox_server.py`); slot lock exclusivity (`test_sandbox_client.py`); SCRAM verifier
  against the RFC 7677 test vector; backup crypto round trip and tamper cases
  (`test_backupcrypt.py`); metrics rendering/escaping and the endpoint token
  (`test_metrics.py`); settings (prod refuses sandbox none, owner login, short metrics token);
  tool-validation `--check` (`test_tool_validation.py`).
* Integration (PostgreSQL): parse jobs end to end in spool mode with a sandbox server thread
  (rows identical to in-process mode, cancel, sandbox down -> retry, crash -> failed, integrity
  still checked before the sandbox); `provision-app-login` on a throwaway role (password works,
  `RESET ROLE` stays unprivileged, `SET ROLE` owner denied); `update_user` concurrency (no
  deadlock, last admin kept); auth rate limit; route auth matrix and case-isolation matrix
  (`test_security.py`); integrity check (clean, flipped byte, truncated chain, manifest
  mismatch, read-only); `/metrics` with data; benchmark at 500 events.
* Live (`scripts/phase10-smoke.py`): sandbox container properties (`docker inspect`: no network,
  read-only root, CapDrop ALL, no-new-privileges, non-root user, pids/memory limits; inside:
  only `lo`, no DNS, writing the root or the evidence mount fails, `CapEff` 0, no credentials in
  the environment), a parse job runs through the sandbox (`run_manifest.sandbox.mode=spool`), the
  worker cannot write the spool from the sandbox side; app login (`RESET ROLE` keeps
  `dfirbench_app`, `SET ROLE dfir` denied, not superuser); auth rate limit 429; `/metrics` 404
  through nginx, 401 without token, 200 with; security headers on every location.

## Acceptance criteria (executable)
1. The parser container has no network, a read-only root and evidence mount, and limits; parser
   children run as their own non-root uid with no capabilities and cannot signal the server; and
   parse jobs run in it: `phase10-smoke.py` sandbox section.
2. Hostile/broken parser output and runaway parsers are contained: `test_sandbox_server.py`,
   `test_sandbox_protocol.py`, spool integration tests.
3. The app cannot regain owner privileges: smoke + `test_provision.py`; verify denial checks.
4. Security regression tests pass: `test_security.py`, rate-limit tests.
5. Scans pass: `bash scripts/scan.sh` (pip-audit, npm audit, gitleaks, Trivy gate) and SBOMs exist.
6. Backup -> restore into a fresh project -> `integrity-check --manifest` passes; a tampered
   backup file is refused: verify script restore drill.
7. Benchmark meets the floors: `scripts/benchmark.py --events 200000 --min-ingest-eps 2000
   --min-parse-lps 20000 --max-search-p95-ms 2000`.
8. Tool validation appendix is current: `scripts/tool-validation.py --check`.
9. Everything from earlier phases still passes: Phase 1-10 smokes, app-role denials, migration
   round trip, ruff/mypy/bandit, pytest with coverage >= 80, AI eval, frontend checks.

## BACKLOG decisions for items targeted at Phase 10
Done in Phase 10: per-job sandbox (both entries; as decision 1), separate LOGIN role, per-IP auth
rate limit, `/metrics`, scans + SBOM (pip-audit, npm audit, gitleaks, Trivy), security headers
include file, `update_user` deadlock, Volatility 3 dependency pins, Phase 7/9 smokes in CI.
Partly done: on-demand full re-verification (`integrity-check`; scheduling it needs Celery beat),
custody anchors (signed chain heads in every backup manifest; periodic anchors need a scheduler).

Re-targeted (one-line reasons; the full list moves to the "Post-v1" section of BACKLOG):
* Celery beat and everything that needs it (job reaper, nightly re-verify, custody anchors,
  uploaded/orphan/artifact reapers, outbound retry sweeps, approval expiry, signing-key
  mismatch notifications): post-v1, a scheduler is a new always-on service on the 7.8 GB host
  and each sweep needs its own locking review; `integrity-check` can be scheduled by cron.
* Events partition retention, `audit_log` partitioning: post-v1, needs a legal retention policy.
* TLS reverse proxy (Caddy): post-v1; the dev stack binds 127.0.0.1, deployment TLS is described
  in the Phase 11 admin guide.
* OpenTelemetry traces: post-v1 (new dependencies and a collector service).
* cosign signing, `container_image_digest` in manifests: post-v1 (needs a registry and a release
  pipeline).
* MinIO image: pinned by digest in Phase 10 together with the other service images (decision
  recorded in `docs/hardening.md`); replacing the community image stays post-v1.
* Plaso, Hayabusa, tshark, Suricata, Zeek, capa/FLOSS, ssdeep/TLSH, Volatility symbol packs,
  split worker images: post-v1 (image size and RAM on the dev host).
* Generated TS client/shadcn, Monaco, virtualised table, entity merge UI, file browser, MFA
  enrolment/admin screens, bundle verdict UI, citation deep links, integration config editing,
  failed-webhook redelivery: post-v1 (UI features, no hardening value).
* Breached-password API, JWT multi-`kid` and TOTP key rotation, KMS/HSM custody keys: post-v1
  (need egress or a secret manager; rotation procedures go into the Phase 11 admin guide).
* Non-superuser owner test for 0003: post-v1 (`CREATE EXTENSION vector` needs a superuser or a
  pre-created extension; documented in the Phase 11 admin guide).
* Resumable uploads, multi-segment evidence, acquisition JSON import, raw NTFS/VSS, signed
  collector releases, other bundle formats, Windows collector reparse points, bundle crash
  members: post-v1 (collection features; bounded and read-only today).
* Evidence status derived from jobs, reprocess staging swap, backpressure, progress over
  WebSocket, SQL push-down and incremental detection, detection on partial reprocess,
  SECURITY DEFINER event deletes: post-v1 (correct today; performance or defence in depth with a
  schema change; the benchmark now measures the paths).
* Parsers and analytics (MFT, Jump Lists, ShellBags, SRUM, WAL replay, volatile listings,
  ShimCache variants, scikit-learn analytics, YARA from users, new detection rules, MISP pull,
  global IOC API, asset inventory, tag provenance, suppressions, incident grouping, AI A11/A14,
  background AI jobs, neural embeddings, encrypted redaction mapping, exact AI budget): post-v1
  (features, not hardening).
* Reporting items (charts, PDF/A fonts, RFC 3161, background renders, more STIX objects, Object
  Lock for report artifacts, write-once artifact keys, artifact reaper), export package
  `original/` members, export as background job: post-v1.
* HTTP response-header total deadline, follow-up outbox dedup: post-v1 (bounded today).

## Verification command
`bash scripts/verify-phase10.sh`
