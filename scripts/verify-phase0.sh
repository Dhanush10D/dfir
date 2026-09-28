#!/usr/bin/env bash
# Phase 0 verification (docs/specs/PHASE-0.md). Exits non-zero on the first failure.
#   bash scripts/verify-phase0.sh            # full: stack + backend + frontend
#   KEEP_STACK=1 bash scripts/verify-phase0.sh   # leave the compose stack running afterwards
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infra/compose.yaml")
step() { printf '\n==> %s\n' "$*"; }

cd "$ROOT/backend"
if [[ -x .venv/Scripts/python ]]; then BIN=.venv/Scripts; else BIN=.venv/bin; fi

step "compose up --build"
"${COMPOSE[@]}" up -d --build
bash "$ROOT/scripts/wait-healthy.sh" 300

step "HTTP probes"
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/health | tee /dev/stderr | grep -q '"status":"ok"'
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/ready | tee /dev/stderr | grep -q '"status":"ready"'
curl -fsS -m 10 http://127.0.0.1:8080/api/v1/health | grep -q '"status":"ok"'
curl -fsS -m 10 http://127.0.0.1:8080/ | grep -q '<div id="root">'
echo

step "worker round-trip (Celery ping via Redis)"
"${COMPOSE[@]}" exec -T api python -c \
  "from app.workers.tasks.system import ping; assert ping.apply_async().get(timeout=30) == 'pong'; print('pong')"

step "alembic upgrade head + drift check (host -> compose Postgres)"
"$BIN/alembic" upgrade head
"$BIN/alembic" check

step "backend: ruff, mypy, bandit, pytest"
"$BIN/ruff" check .
"$BIN/ruff" format --check .
"$BIN/mypy" app
"$BIN/bandit" -c pyproject.toml -r app -q
"$BIN/python" -m pytest -q --cov=app --cov-fail-under=80

step "frontend: lint, typecheck, test, build"
cd "$ROOT/frontend"
[[ -d node_modules ]] || npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm test
npm run build

if [[ "${KEEP_STACK:-0}" != "1" ]]; then
  step "compose down"
  "${COMPOSE[@]}" down
fi
step "PHASE 0 VERIFIED"
