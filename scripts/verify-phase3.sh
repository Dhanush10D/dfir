#!/usr/bin/env bash
# Phase 3 verification (docs/specs/PHASE-3.md): earlier phases plus detection. Exits non-zero on the first failure.
#   bash scripts/verify-phase3.sh              # stack + live smoke/tamper demo + backend checks
#   STOP_STACK=1 bash scripts/verify-phase3.sh # also `compose down` at the end (default: keep it up)
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

step "custody signer loaded and app runs as the least-privilege role"
"${COMPOSE[@]}" exec -T api python -c "
from sqlalchemy import text
from app.db.session import get_engine
from app.deps import get_custody_signer
signer = get_custody_signer()
assert signer is not None, 'custody signer not loaded'
with get_engine().connect() as conn:
    role = conn.execute(text('SELECT current_user')).scalar_one()
assert role == 'dfirbench_app', role
print('signer', signer.key_id, 'role', role)"

step "app role cannot rewrite custody, audit, signing keys, events, run manifests, alert history"
for stmt in "UPDATE custody_log SET action = 'x'" "DELETE FROM audit_log"             "UPDATE signing_keys SET public_key = 'x'" "DELETE FROM signing_keys"             "UPDATE events SET message = 'x'" "TRUNCATE events" "DELETE FROM jobs"             "DELETE FROM events_default" "DELETE FROM alerts" "UPDATE alert_history SET reason = 'x'" "DELETE FROM rule_versions" "DELETE FROM iocs" "UPDATE alert_events SET alert_id = alert_id"; do
  out="$("${COMPOSE[@]}" exec -T postgres psql -U dfir -d dfirbench -v ON_ERROR_STOP=1          -c "BEGIN; SET LOCAL ROLE dfirbench_app; $stmt; ROLLBACK;" 2>&1 || true)"
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

step "alembic round trip of migrations 0004-0006 (downgrade 0003 -> upgrade head)"
"$BIN/alembic" downgrade 0003
"$BIN/alembic" current | grep -q '0003'
"$BIN/alembic" upgrade head
"$BIN/alembic" current | grep -q '(head)'
"$BIN/alembic" check

step "live smoke + tamper demo through the running API"
ADMIN_EMAIL="verify-admin-$(date +%s)-$RANDOM@dfirbench.test"
DFIR_ADMIN_PASSWORD="Phase3-Check-$RANDOM-Passphrase-$(date +%s)"  # policy: not the e-mail name
export DFIR_ADMIN_PASSWORD
"${COMPOSE[@]}" exec -T -e DFIR_ADMIN_PASSWORD api \
  python -m app.cli create-admin --email "$ADMIN_EMAIL" --name "Verify Admin" >/dev/null
"$BIN/python" "$ROOT/scripts/phase1-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 2 live smoke: API -> Redis -> Celery worker -> events -> timeline"
"$BIN/python" "$ROOT/scripts/phase2-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 3 live smoke: parse -> auto detection (detect queue) -> alerts -> lifecycle -> IOC"
"$BIN/python" "$ROOT/scripts/phase3-smoke.py" --admin-email "$ADMIN_EMAIL"
unset DFIR_ADMIN_PASSWORD

step "backend: ruff, mypy, bandit, pytest (unit + integration + MinIO)"
"$BIN/ruff" check .
"$BIN/ruff" format --check .
"$BIN/mypy" app
"$BIN/bandit" -c pyproject.toml -r app -q
"$BIN/python" -m pytest -q -p no:cacheprovider --cov=app --cov-fail-under=80

if [[ "${STOP_STACK:-0}" == "1" ]]; then
  step "compose down"
  "${COMPOSE[@]}" down
fi
step "PHASE 3 VERIFIED"
