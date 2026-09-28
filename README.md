# dfirbench

Digital Forensics and Incident Response (DFIR) is a cybersecurity discipline used to detect, investigate,
contain, and recover from cyberattacks while preserving digital evidence. **dfirbench** is an AI-assisted
DFIR workbench built to the **Standard profile** of [`docs/BUILD_GUIDE.md`](docs/BUILD_GUIDE.md):
FastAPI + PostgreSQL 16 (pgvector) + Redis/Celery + MinIO evidence vault + React/TypeScript UI.

Status: **Phase 0 (Foundation)**. See [`docs/specs/ROADMAP.md`](docs/specs/ROADMAP.md) and
[`docs/specs/PHASE-0.md`](docs/specs/PHASE-0.md).

## Quickstart (Docker)

Requirements: Docker with Compose v2.24+.

```bash
docker compose -f infra/compose.yaml up -d --build
bash scripts/wait-healthy.sh          # waits for postgres, redis, minio, api, worker, web

curl http://127.0.0.1:8000/api/v1/health   # liveness  -> {"status":"ok",...}
curl http://127.0.0.1:8000/api/v1/ready    # readiness -> database, redis, storage checks
open http://127.0.0.1:8080                 # web UI (nginx also proxies /api)
```

The stack runs two one-shot jobs first: `migrate` (`alembic upgrade head`) and `storage-init` (creates the
`evidence` bucket with Object Lock / COMPLIANCE retention, and the `artifacts` bucket).

| Service | Host port | Notes |
|---|---|---|
| api | 127.0.0.1:8000 | FastAPI; OpenAPI at `/api/v1/docs` |
| web | 127.0.0.1:8080 | React build served by nginx; `/api` proxied to api |
| postgres | 127.0.0.1:5432 | `pgvector/pgvector` PostgreSQL 16, db/user `dfirbench`/`dfir` |
| redis | 127.0.0.1:6379 | Celery broker/result backend |
| minio | 127.0.0.1:9000 (console 9001) | S3 evidence vault |

Default credentials are **development placeholders** (see [`.env.example`](.env.example)); `APP_ENV=prod`
refuses to start with them. To override, `cp .env.example .env`, edit, and run compose with
`--env-file .env`. Stop with `docker compose -f infra/compose.yaml down` (add `-v` to wipe data).

### First login and evidence (Phase 1)

```bash
# create the first admin (password from the environment, never on the command line)
DFIR_ADMIN_PASSWORD='choose-a-long-passphrase' docker compose -f infra/compose.yaml exec -T \
  -e DFIR_ADMIN_PASSWORD api python -m app.cli create-admin --email admin@example.org
```

Then `POST /api/v1/auth/login`, create users (`/users`), a case (`/cases`), an evidence record
(`/cases/{id}/evidence`), stream the file with `PUT /evidence/{eid}/upload`
(`application/octet-stream`), `POST /evidence/{eid}/finalize`, and check integrity with
`POST /evidence/{eid}/verify`. OpenAPI docs: http://127.0.0.1:8000/api/v1/docs. The compose `keygen`
job creates the dev Ed25519 custody signing key in the `custodykeys` volume; for a host-run API use
`bash scripts/dev-keygen.sh` and set `CUSTODY_SIGNING_KEY_PATH=../var/keys/custody-dev.pem`.

## Local development

```bash
bash scripts/bootstrap.sh            # backend/.venv (Python 3.12) + frontend node_modules + .env
docker compose -f infra/compose.yaml up -d postgres redis minio

cd backend
.venv/Scripts/alembic upgrade head                 # Linux/macOS: .venv/bin/...
.venv/Scripts/python -m app.storage init           # create vault buckets
.venv/Scripts/uvicorn app.main:app --reload        # http://127.0.0.1:8000
.venv/Scripts/celery -A app.workers.celery_app worker -Q default,parse,ai,reports -P solo

cd ../frontend && npm run dev                      # http://127.0.0.1:5173 (proxies /api)
```

On Windows use `127.0.0.1`, not `localhost`, in connection URLs (IPv6 resolution stalls).

## Tests and checks

```bash
cd backend
.venv/Scripts/python -m pytest -q      # unit + integration (integration skips if Postgres is down)
.venv/Scripts/ruff check . && .venv/Scripts/ruff format --check . && .venv/Scripts/mypy app

cd ../frontend
npm run lint && npm run typecheck && npm test && npm run build

bash scripts/verify-phase0.sh          # everything above plus the compose stack, end to end
bash scripts/verify-phase1.sh          # stack + live smoke/tamper demo + backend checks (keeps stack up)
```

Integration tests create a throwaway database on the compose Postgres (or `TEST_DATABASE_URL`), run the
Alembic baseline, and assert the schema, the append-only custody/audit triggers, and events partitioning.

## Repository layout

```
backend/    FastAPI app (app/), Alembic migrations, tests (unit/, integration/)
frontend/   React + TypeScript + Vite + Tailwind UI
infra/      compose.yaml and Dockerfiles (api, worker, web) + nginx config
collector/  triage collection scripts (Phase 5)
data/       rules, playbooks, small public samples
scripts/    bootstrap, wait-healthy, phase verification
docs/       build guide, phase specs, backlog
```

## Forensic integrity

Originals are read-only (vault bucket has Object Lock), timestamps are stored as UTC `timestamptz` with the
original string kept in `ts_original`, and `custody_log` / `audit_log` are append-only at the database level
(UPDATE, DELETE and TRUNCATE are rejected by triggers).
