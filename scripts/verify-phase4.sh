#!/usr/bin/env bash
# Phase 4 verification (docs/specs/PHASE-4.md): earlier phases plus the analysis API and UI.
# Exits non-zero on the first failure.
#   bash scripts/verify-phase4.sh              # stack + live smokes + backend + frontend checks
#   STOP_STACK=1 bash scripts/verify-phase4.sh # also `compose down` at the end (default: keep it up)
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
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/health | grep -q '"status":"ok"'
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/ready | tee /dev/stderr | grep -q '"status":"ready"'
curl -fsS -m 10 http://127.0.0.1:8080/api/v1/health | grep -q '"status":"ok"'
echo

step "web: strict CSP on the SPA"
curl -fsS -m 10 -D - -o /dev/null http://127.0.0.1:8080/cases | tee /dev/stderr \
  | grep -i '^content-security-policy:' | grep -q "script-src 'self'"

step "app runs as the least-privilege role"
"${COMPOSE[@]}" exec -T api python -c "
from sqlalchemy import text
from app.db.session import get_engine
with get_engine().connect() as conn:
    role = conn.execute(text('SELECT current_user')).scalar_one()
assert role == 'dfirbench_app', role
print('role', role)"

step "app role cannot rewrite custody, audit, events, alert history, note history, entities"
for stmt in "UPDATE custody_log SET action = 'x'" "DELETE FROM audit_log" \
            "UPDATE signing_keys SET public_key = 'x'" "UPDATE events SET message = 'x'" \
            "TRUNCATE events" "DELETE FROM jobs" "DELETE FROM alerts" \
            "UPDATE alert_history SET reason = 'x'" "DELETE FROM rule_versions" \
            "DELETE FROM notes" "UPDATE notes SET case_id = case_id" "UPDATE notes SET author_id = author_id" \
            "UPDATE note_versions SET body_md = 'x'" "DELETE FROM note_versions" \
            "UPDATE bookmarks SET comment = 'x'" "DELETE FROM entities" "DELETE FROM entity_links" \
            "DELETE FROM entity_aliases" "UPDATE entity_aliases SET alias = 'x'"; do
  out="$("${COMPOSE[@]}" exec -T postgres psql -U dfir -d dfirbench -v ON_ERROR_STOP=1 \
         -c "BEGIN; SET LOCAL ROLE dfirbench_app; $stmt; ROLLBACK;" 2>&1 || true)"
  if ! grep -q "permission denied" <<<"$out"; then
    echo "app role was NOT denied: $stmt -> $out" >&2
    exit 1
  fi
  echo "denied: $stmt"
done

step "alembic upgrade head + drift check (host -> compose Postgres)"
"$BIN/alembic" upgrade head
"$BIN/alembic" current | grep -q '(head)'
"$BIN/alembic" check

step "alembic round trip of migration 0007 (downgrade 0006 -> upgrade head)"
"$BIN/alembic" downgrade 0006
"$BIN/alembic" current | grep -q '0006'
"$BIN/alembic" upgrade head
"$BIN/alembic" current | grep -q '(head)'
"$BIN/alembic" check

step "live smokes (Phases 1-4) through the running API"
ADMIN_EMAIL="verify-admin-$(date +%s)-$RANDOM@dfirbench.test"
DFIR_ADMIN_PASSWORD="Phase4-Check-$RANDOM-Passphrase-$(date +%s)"  # policy: not the e-mail name
export DFIR_ADMIN_PASSWORD
"${COMPOSE[@]}" exec -T -e DFIR_ADMIN_PASSWORD api \
  python -m app.cli create-admin --email "$ADMIN_EMAIL" --name "Verify Admin" >/dev/null
"$BIN/python" "$ROOT/scripts/phase1-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase2-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase3-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 4 live smoke: search, facets, histogram, notes, bookmarks, entities, graph, tree, export, cookie, CSP"
"$BIN/python" "$ROOT/scripts/phase4-smoke.py" --admin-email "$ADMIN_EMAIL"
unset DFIR_ADMIN_PASSWORD

step "backend: ruff, mypy, bandit, pytest (unit + integration + MinIO)"
"$BIN/ruff" check .
"$BIN/ruff" format --check .
"$BIN/mypy" app
"$BIN/bandit" -c pyproject.toml -r app -q
"$BIN/python" -m pytest -q -p no:cacheprovider --cov=app --cov-fail-under=80

step "frontend: lint, typecheck, vitest, build"
cd "$ROOT/frontend"
npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm test
npm run build

if [[ "${STOP_STACK:-0}" == "1" ]]; then
  step "compose down"
  "${COMPOSE[@]}" down
fi
step "PHASE 4 VERIFIED"
