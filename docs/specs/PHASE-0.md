# PHASE 0: Foundation

## Goal
Stand up the dfirbench monorepo (Standard profile) so that later phases only add features: a FastAPI
backend skeleton with config, structured logging, a consistent error format, health/readiness probes,
SQLAlchemy 2.0 models plus one Alembic baseline migration for every table in guide section 7.2/7.3,
a Celery worker skeleton, a React + TypeScript + Vite + Tailwind shell, a Docker Compose stack
(PostgreSQL 16 + pgvector, Redis, MinIO, api, worker, web) and a CI workflow.

## In scope
- `backend/`: `pyproject.toml` (Python 3.12, pinned deps, `[dev]` extras), app factory, config, logging,
  errors, request-id middleware, `deps.py`, DB session, models, Alembic baseline, Celery app + `ping` task,
  `/api/v1/health` and `/api/v1/ready`.
- All tables from guide 7.2 and 7.3, the 5 enums, extensions (`pgcrypto`, `citext`, `pg_trgm`, `vector`),
  append-only triggers on `custody_log` (and `audit_log`), `events` partitioned by month.
- `frontend/`: Vite + React + TS + Tailwind v4 shell that shows API health; Vitest smoke test; ESLint.
- `infra/compose.yaml`, `infra/docker/{api,worker,web}.Dockerfile`, MinIO bucket init (Object Lock on the
  vault bucket), one-shot `migrate` service, healthchecks. `.env.example` at the repo root.
- `.github/workflows/ci.yml`: ruff (lint + format), mypy, bandit, pytest with a pgvector service, frontend
  lint/typecheck/test/build.
- `scripts/` dev helpers; README quickstart; `docs/BACKLOG.md`.

## Out of scope (later phases)
Auth/RBAC/JWT/TOTP, case and evidence endpoints, custody hashing/signing service (Phase 1); parsers, job
orchestration, partition management at ingest time (Phase 2); forensic binaries in the worker image
(Phase 6); reverse proxy/TLS, `/metrics`, pip-audit/Trivy/SBOM, separate DB app role with REVOKEs
(Phase 10). OpenSearch is Full-profile only and is not included.

## Files and interfaces
- `backend/app/main.py`: `create_app(settings: Settings | None = None) -> FastAPI`; module-level `app`.
- `backend/app/config.py`: `class Settings(BaseSettings)` (env vars from guide Appendix C);
  `get_settings() -> Settings` (cached). `APP_ENV=prod` fails fast on missing/placeholder secrets and `*` CORS.
- `backend/app/core/logging.py`: `setup_logging(level: str, json: bool = True) -> None` (structlog JSON, stdlib bridged).
- `backend/app/core/errors.py`: `class AppError(Exception)(code, message, status_code=400, details=None)`,
  `register_handlers(app)`, `error_body(code, message, details, request_id) -> dict`.
- `backend/app/core/middleware.py`: `RequestIdMiddleware` (pure ASGI; honours a safe inbound `X-Request-ID`,
  otherwise generates one; echoes it; binds it to structlog contextvars; logs one access line per request).
- `backend/app/core/request_context.py`: `get_request_id() -> str | None`.
- `backend/app/db/session.py`: `make_engine(url) -> Engine`, `make_session_factory(engine)`, `get_engine()`, `get_sessionmaker()`.
- `backend/app/db/base.py`: `Base(DeclarativeBase)`, naming convention.
- `backend/app/db/models/*.py`: `enums.py`, `users.py`, `cases.py`, `evidence.py` (evidence, custody_log),
  `jobs.py`, `events.py`, `detection.py` (rules, alerts, alert_events, iocs), `entities.py`,
  `collaboration.py` (notes, bookmarks, saved_queries, notifications), `reports.py`, `ai.py`
  (ai_interactions, event_chunks), `audit.py` (audit_log, signing_keys, anchors), `ops.py`
  (playbooks, playbook_runs, agents, agent_tasks, integrations, settings).
- `backend/app/deps.py`: `get_app_settings`, `get_db` (yields `Session`), `get_redis`, `get_storage`.
- `backend/app/services/health.py` (no FastAPI imports): `check_database(engine)`, `check_redis(client)`,
  `check_storage(client, bucket)` each `-> CheckResult`; `run_readiness(...) -> ReadinessReport`.
- `backend/app/storage.py`: `make_minio_client(settings) -> Minio`.
- `backend/app/api/v1/health.py`: `GET /api/v1/health`, `GET /api/v1/ready`.
- `backend/app/schemas/health.py`: `HealthResponse`, `ReadinessResponse`, `ErrorResponse`.
- `backend/app/workers/celery_app.py`: `celery_app` (queues `default, parse, ai, reports`; `acks_late`,
  `task_reject_on_worker_lost`, prefetch 1, time limits); `backend/app/workers/tasks/system.py`: `ping() -> str`.
- `backend/alembic/versions/0001_baseline.py`.

## Data model changes
Baseline migration `0001_baseline` creates everything in guide 7.2 exactly (column names/types/defaults)
plus the 7.3 tables with the same conventions (uuid PK `gen_random_uuid()`, `timestamptz`, `jsonb`).
Decisions:
- **events partitioning**: `PARTITION BY RANGE (ts)` as in 7.2 (Standard profile, retention by dropping
  partitions per 7.6). The baseline creates a `events_default` DEFAULT partition so inserts never fail,
  and a SQL function `dfir_ensure_events_partition(ts timestamptz)` that creates the monthly partition
  `events_yYYYYmMM`. Ingest (Phase 2) must call it for each month before bulk insert so rows do not land
  in the default partition.
- **Append-only**: `forbid_mutation()` row trigger (BEFORE UPDATE OR DELETE) plus a statement-level
  BEFORE TRUNCATE trigger on `custody_log` and on `audit_log` (audit trail is also excluded from purges per 7.6).
- `event_chunks.embedding vector(384)` + HNSW cosine index; `EMBEDDING_DIM` must match (Phase 7).
- Downgrade drops everything (dev only; never downgrade a production evidence DB).

## API changes
- `GET /api/v1/health` → `200 {"status":"ok","service":"dfirbench-api","version":"0.1.0","time":"...Z"}` (no dependency checks).
- `GET /api/v1/ready` → `200 {"status":"ready","checks":{"database":{"ok":true,...},"redis":{...},"storage":{...}}}`
  or `503` with the 15.3 envelope: `{"error":{"code":"not_ready","message":...,"details":{"checks":...},"request_id":...}}`.
- All errors (404, 405, 422, 500, `AppError`) use the 15.3 envelope and carry `request_id`; responses carry `X-Request-ID`.
- OpenAPI at `/api/v1/openapi.json`, docs at `/api/v1/docs`.

## Test plan
- Unit (no Docker): config defaults/env parsing/prod fail-fast/CORS parsing; health 200 body; ready 200 and
  503 with fake checks via dependency overrides; error envelope for 404/405/422/500/AppError; request-id
  echo and rejection of unsafe inbound ids; readiness service functions with fakes; Celery `ping` task eager;
  models metadata contains every expected table; `forbid_mutation` present in migration.
- Integration (`tests/integration`, marked `integration`, skip cleanly if Postgres unreachable): create a
  throwaway database, `alembic upgrade head`, assert all tables/enums/extensions exist, `events` is
  partitioned with default partition and `dfir_ensure_events_partition` works, UPDATE/DELETE/TRUNCATE on
  `custody_log` raise, INSERT works; models match the migrated schema (Alembic `compare_metadata`);
  `alembic downgrade base` then `upgrade head` round-trips.
- Frontend: Vitest + Testing Library renders the shell and shows status from a mocked `/api/v1/health`.

## Acceptance criteria (executable)
1. `docker compose -f infra/compose.yaml up -d --build` → `docker compose -f infra/compose.yaml ps` shows
   postgres, redis, minio, api, worker, web `healthy` (migrate and minio-init exited 0).
2. `curl -fsS localhost:8000/api/v1/health` returns `"status":"ok"`; `curl -fsS localhost:8000/api/v1/ready` returns `"status":"ready"`;
   `curl -fsS localhost:8080/api/v1/health` works through the web container proxy.
3. `cd backend && .venv/Scripts/alembic upgrade head` succeeds against compose Postgres (idempotent).
4. `cd backend && .venv/Scripts/python -m pytest -q` passes (integration tests run when compose Postgres is up).
5. `.venv/Scripts/ruff check . && .venv/Scripts/ruff format --check . && .venv/Scripts/mypy app` pass.
6. `cd frontend && npm ci && npm run lint && npm run typecheck && npm test && npm run build` pass.

## Verification command
```bash
bash scripts/verify-phase0.sh
```
(brings the stack up, waits for health, curls health/ready, runs alembic, backend tests + lint + types,
frontend lint/typecheck/test/build; exits non-zero on any failure).
