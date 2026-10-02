# Hardening (Phase 10)

How dfirbench limits the damage of hostile evidence, a compromised API or worker, and a
compromised dependency (guide 10.7, 20, 21.4). Spec: `docs/specs/PHASE-10.md`.

## Parser sandbox

Every parse job runs in the `parser-sandbox` container, never in a process that can reach the
database, the object store, Redis, the network or key material.

| Property | Setting | Checked by |
|---|---|---|
| No network | `network_mode: none` (only `lo`) | `phase10-smoke.py` (no DNS, no route) |
| Read-only root | `read_only: true`, no tmpfs | smoke (write fails with EROFS) |
| Evidence read-only | `spoolin` mounted `:ro` | smoke (mount flag `ST_RDONLY`) |
| No privileges for parsers | `cap_drop: [ALL]`, `no-new-privileges`, default seccomp profile, `ipc: private`; every parser child runs as uid `10002` (group `10001`) with no capabilities | smoke, probe as `10002:10001` (`CapEff` 0, `NoNewPrivs` 1, `Seccomp` 2) |
| uid split | the server starts as root with only `SETUID`, `SETGID`, `KILL`, `DAC_OVERRIDE` (`cap_add`), keeps euid 0 to start and kill children, and reads/writes files as `10001` (fsuid); it never parses evidence | smoke (server `Uid` `0 0 0 10001`, `CapPrm` exactly those four; the child cannot signal the server, list the output spool or write the work root) |
| Resource limits | `pids_limit` 128, `mem_limit`/`memswap_limit` 2g, `cpus` 1.0 (`SANDBOX_*`) | smoke (`docker inspect`) |
| Per job | child process with `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, no core dumps, wall-clock timeout, output and line caps, clean environment | `test_sandbox_server.py` |
| No secrets | the container gets only `SANDBOX_*` variables and no key volume | smoke |

**How a job flows.** The worker takes the sandbox slot (an exclusive lock on a file in its own
scratch volume), wipes stale spool entries, writes the hash-verified evidence copy straight into
`spoolin/job-<id>/` (0400), then the request and a `ready` marker. The sandbox server
(`python -m app.sandbox.server`, a child subreaper, refuses to run as root) starts
`python -m app.sandbox.child` for that job; the child lowers its own limits before reading
anything, runs the parser and streams cleaned events to stdout. The server copies `E`/`R` lines
into `spoolout/job-<id>/events.jsonl` (strict line kinds, caps), kills the child on timeout,
cancel, overflow or protocol violation, **kills and reaps every remaining descendant**, deletes
the job's work directory and only then writes `exit.json` with the size and SHA-256 of the output.
The worker checks the output against `exit.json`, decodes every line strictly (malformed lines
are counted errors), normalises with the same `to_row` as before and inserts under its job lock;
`case_id`, `evidence_id`, `job_id` and event ids are always the worker's. Finally it deletes both
spool directories and releases the slot. The run manifest records `sandbox` (mode, exit reason,
output hash).

**Outcomes.** Input errors fail the job with the parser's message; a timeout or output overflow
keeps a partial result; a crash, a kill (memory/CPU limit) or a protocol violation fails the job
(`parser sandbox: ...`); a sandbox that does not pick the job up within
`SANDBOX_START_TIMEOUT_S` is a transient error (the job is retried).

**Why one container and not one per job.** Starting containers from the worker needs the Docker
socket, which is root on the host; no service gets it. Isolation between jobs is therefore by
process, lock and sweep: only one job's evidence is ever in the spool, no process of a finished
job survives, and the next job starts only after the previous one's spool is gone. The sweep can
only be trusted because the parser runs as a different uid from the server: with one shared uid
a compromised parser could `SIGSTOP` the server, survive its job, read the next job's evidence
and answer that job itself (independent review, 2026-10-02). Now the child (uid `10002`) cannot
signal the server (euid 0), cannot list or write the output spool (`0700`, owner `10001`) and
can only traverse the work root (`0710`) to its own job's directory. Files the child may read
(the job's input in `spoolin`) are group-readable by `10001`; nothing is readable by others. Throughput is
one parse at a time per sandbox replica (a second parse job waits for the slot while keeping its
lease alive).

**Residual risks** (accepted for the Standard profile):

* Bundle unpacking (`BundleIngestService`) still runs in the worker: stdlib `zipfile` and JSON
  with the Phase 5 bounds (member count, sizes, ratio, name checks), and it must upload derived
  files to the vault. A sandboxed unpacker is post-v1.
* Parser auto-detection in the API reads the first 4 KiB of the original and compares magic
  values (`can_parse`); no decoding library touches it.
* The sandbox shares the host kernel; a kernel exploit from a parser escapes it. gVisor/Kata
  runtimes are a deployment option outside this repository.
* `SANDBOX_MODE=none` (in-process parsing) remains for tests and hosts without Docker; prod
  refuses it.

## Database roles

* Migrations and role provisioning use the owner login (`DATABASE_MIGRATE_URL`, only in the
  `migrate` job). `python -m app.cli provision-app-login` gives `dfirbench_app` LOGIN with the
  password from `DATABASE_URL`, sent as a client-computed SCRAM-SHA-256 verifier; it refuses a
  role that is superuser, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS or a member of any role.
* The API and workers log in as `dfirbench_app` itself. `RESET ROLE` keeps it, `SET ROLE dfir`
  and `SET SESSION AUTHORIZATION` are denied (verify script, smoke, `test_provision.py`), so the
  grants and triggers of the earlier phases cannot be bypassed by the app.
* Prod refuses a `DATABASE_URL` that logs in as anything but `DATABASE_APP_ROLE`, and the dev
  placeholder password (`DATABASE_APP_PASSWORD` in `.env`).
* Event inserts use a per-session temporary staging table (COPY, then `INSERT ... SELECT ... ON
  CONFLICT DO NOTHING`), so the app role needs the database's default `TEMPORARY` privilege. A
  deployment that revokes `TEMPORARY` from `PUBLIC` must grant it to `dfirbench_app`.

## Authentication limits

Per client IP (the address uvicorn trusts from the web proxy), one-minute windows in Redis:
`AUTH_RATE_LIMIT_PER_MINUTE` (30) for `/auth/login` and `/auth/mfa/verify` together,
`AUTH_REFRESH_RATE_LIMIT_PER_MINUTE` (120) for `/auth/refresh`. Over the limit: 429
`rate_limited` with `Retry-After`, audited as `auth.rate_limited`; Redis down: 503 (fail closed).
The per-account lockout stays. Behind another proxy (for example a TLS terminator in front of
`web`), that proxy must pass the real client address and nginx must trust it
(`set_real_ip_from`); otherwise every client shares the proxy's address and one bucket, and a
single client can lock everyone out of login for a minute. `update_user` locks the acting admin, the target and every active
admin in id order before reading them, so concurrent admin changes cannot deadlock or remove the
last active admin; `mfa_enroll` locks the user row.

## Metrics

`GET /metrics` on the API (port 8000, not proxied by the web container, not audited): 404 unless
`METRICS_TOKEN` is set, then `Authorization: Bearer <token>`. Families: `dfir_http_requests_total`
and `dfir_http_request_duration_seconds` (labels: method, route template, status class; no ids),
`dfir_jobs{kind,status}`, `dfir_job_duration_seconds_{avg,max}_24h{parser}`,
`dfir_jobs_finished_24h`, `dfir_events_ingested_1h`, `dfir_evidence{status}`,
`dfir_custody_verification_failures{action}`, `dfir_outbound_deliveries{status}`,
`dfir_ai_{calls,tokens,cost_usd}_today`, `dfir_queue_depth{queue}` and
`dfir_metrics_section_up{section}`. Scrape-time sections are cached for `METRICS_CACHE_S`.
Suggested alerts: `dfir_custody_verification_failures` increasing, `dfir_queue_depth{queue="parse"}`
above zero for 30 minutes, `dfir_metrics_section_up == 0`, 5xx rate.

## Web security headers

One include file (`infra/docker/security-headers.conf`) is used at server level and in every
location that adds its own headers: CSP (`script-src 'self'`, no inline, `frame-ancestors
'none'`), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, COOP, CORP and
`Permissions-Policy`. `phase10-smoke.py` checks `/`, an SPA route, an asset, the API and
`/healthz`. TLS (and HSTS) belong on the reverse proxy in front of the web container; the dev
stack binds to 127.0.0.1 only.

## Supply chain

* Every service and base image is pinned by tag **and** multi-arch index digest (compose,
  Dockerfiles, CI service containers). Update: pull the new tag, `docker buildx imagetools
  inspect <tag>`, replace the digest, rebuild, run `verify-phase10.sh`.
* Python dependencies are pinned in `pyproject.toml`; Volatility 3 and its dependencies are
  installed with `--require-hashes` from `infra/docker/volatility-requirements.txt`; npm uses the
  lockfile.
* `scripts/scan.sh` (verify script and the CI `security` job): gitleaks over the whole history
  (reviewed non-secrets baselined by fingerprint in `.gitleaksignore`), pip-audit on the frozen
  backend dependency set, `npm audit --audit-level=high`, Trivy on the api and worker images
  (gate: CRITICAL with a fix in language packages; all HIGH/CRITICAL OS findings in
  `var/scan/trivy-*.txt`), CycloneDX SBOMs for the Python environment, npm and both images.
  OS-package findings are fixed by rebuilding on a newer pinned base image; an advisory may only
  be ignored with a reason in `.trivyignore` / `scripts/scan-ignore.txt`.
* Not done (post-v1): image signing (cosign) and provenance, `container_image_digest` in run
  manifests (needs a registry and a release pipeline).

## Backup, restore and re-verification

See `docs/backup-restore.md`.
