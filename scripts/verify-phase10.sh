#!/usr/bin/env bash
# Phase 10 verification (docs/specs/PHASE-10.md): earlier phases plus hardening and validation
# (parser sandbox container, app-role database login, auth rate limits, /metrics, security
# headers, backup -> restore drill with re-verification, scans, benchmark, tool validation).
# No real LLM and no outbound traffic from the app: ENABLE_AI=true LLM_PROVIDER=fake,
# ENRICHMENT_FAKE=true, OUTBOUND_ALLOW_HOSTS=api. The scans need network (advisory databases).
# Exits non-zero on failure.
#   bash scripts/verify-phase10.sh               # everything
#   KEEP_STACK=1 bash scripts/verify-phase10.sh  # leave the stack running (default: `compose stop`)
# Memory (7.8 GB host): the api/worker/web/sandbox containers are stopped before pytest, the
# benchmark, the image scans and the frontend build, which run one after the other.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"  # pwd -W: C:/... in Git Bash (MSYS_NO_PATHCONV below)
COMPOSE=(docker compose -f "$ROOT/infra/compose.yaml")
step() { printf '\n==> %s\n' "$*"; }
# grep that reads all of its input: `grep -q` exits on the first match, so under pipefail the
# writer (curl, docker) can fail with SIGPIPE / "error on write" and abort the script.
gq() { grep "$@" >/dev/null; }
# Native Windows curl gets arguments unconverted (MSYS_NO_PATHCONV), so /dev/null is NUL there.
if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* ]]; then DEVNULL=NUL; else DEVNULL=/dev/null; fi
export MSYS_NO_PATHCONV=1  # Git Bash: container paths stay as written

cd "$ROOT/backend"
if [[ -x .venv/Scripts/python ]]; then BIN=.venv/Scripts; else BIN=.venv/bin; fi
PY="$ROOT/backend/$BIN/python"

step "collectors: trust list current, Python syntax (3.6+ subset linted as py37), shell syntax"
"$BIN/python" "$ROOT/scripts/update-collector-hashes.py" --check
"$BIN/python" -m py_compile "$ROOT/collector/collect_linux.py"
"$BIN/ruff" check --isolated --target-version py37 --line-length 100 --select E4,E7,E9,F,B "$ROOT/collector"
for sh in "$ROOT"/collector/acquire/*.sh; do bash -n "$sh" && echo "bash -n ok: $(basename "$sh")"; done
if command -v powershell.exe >/dev/null 2>&1; then
  for ps in "$ROOT"/collector/*.ps1 "$ROOT"/collector/acquire/*.ps1; do
    win=$(cygpath -w "$ps" 2>/dev/null || echo "$ps")
    out=$(powershell.exe -NoProfile -NonInteractive -Command \
      "\$e=\$null;\$t=\$null;[void][System.Management.Automation.Language.Parser]::ParseFile('$win',[ref]\$t,[ref]\$e);'{0}|{1}' -f \$PSVersionTable.PSVersion.Major,\$e.Count" | tr -d '\r')
    [[ "$out" == "5|0" ]] || { echo "PowerShell 5.1 parse failed for $ps: $out" >&2; exit 1; }
    echo "PS 5.1 parse ok: $(basename "$ps")"
  done
else
  echo "powershell.exe not available: 5.1 parse check skipped (unit tests still check syntax)"
fi

step "compose up --build (AI fake, enrichment fake, outbound only to api, metrics token, auth limits)"
export ENABLE_AI=true LLM_PROVIDER=fake ENABLE_ENRICHMENT=true ENRICHMENT_FAKE=true
export OUTBOUND_ALLOW_HTTP=true OUTBOUND_ALLOW_HOSTS=api
METRICS_TOKEN="verify-metrics-$(date +%s)-$RANDOM-$RANDOM-token"
export METRICS_TOKEN
# The Phase 1-9 smokes log in often from one address; the refresh limit is low so the Phase 10
# smoke can reach it quickly (the per-IP logic itself is covered by integration tests).
export AUTH_RATE_LIMIT_PER_MINUTE=1000 AUTH_REFRESH_RATE_LIMIT_PER_MINUTE=40
"${COMPOSE[@]}" up -d --build
bash "$ROOT/scripts/wait-healthy.sh" 300

step "HTTP probes"
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/health | gq '"status":"ok"'
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/ready | tee /dev/stderr | gq '"status":"ready"'
curl -fsS -m 10 http://127.0.0.1:8080/api/v1/health | gq '"status":"ok"'
echo

step "web: strict CSP on the SPA"
curl -fsS -m 10 -D - -o "$DEVNULL" http://127.0.0.1:8080/cases | tee /dev/stderr \
  | grep -i '^content-security-policy:' | gq "script-src 'self'"

step "the migrate job provisioned the app login; the app runs as dfirbench_app; worker tasks"
"${COMPOSE[@]}" logs --no-color migrate | gq "login=True member_of=\[\] role=dfirbench_app"
"${COMPOSE[@]}" exec -T api python -c "
from sqlalchemy import text
from app.db.session import get_engine
with get_engine().connect() as conn:
    role, login = conn.execute(text('SELECT current_user, session_user')).one()
assert role == 'dfirbench_app' and login == 'dfirbench_app', (role, login)
print('role', role, 'login', login)"
"${COMPOSE[@]}" exec -T worker python -c "
from app.config import get_settings
from app.workers.celery_app import celery_app
celery_app.loader.import_default_modules()  # the 'include' list, as the worker loads it
assert 'dfirbench.ingest_bundle' in celery_app.tasks, sorted(celery_app.tasks)
assert 'dfirbench.process_outbound' in celery_app.tasks, sorted(celery_app.tasks)
assert get_settings().sandbox_mode == 'spool'
from app.collection.trust import load_trusted_collectors
assert load_trusted_collectors(), 'trusted collector list missing from the image'
print('worker tasks ok, parsers sandboxed')"

step "worker image: Sleuth Kit, Volatility 3 (own venv, pinned with hashes), Python engines"
"${COMPOSE[@]}" exec -T worker sh -c '
set -e
cat /opt/dfir/tool-versions.txt
grep -q "^sleuthkit 4.11" /opt/dfir/tool-versions.txt
grep -q "^volatility3 2.28.2" /opt/dfir/tool-versions.txt
fls -V | grep -q "Sleuth Kit"
mmls -V | grep -q "Sleuth Kit"
HOME=/tmp vol --help | grep -q "Volatility 3 Framework 2.28.2"
/opt/dfir/vol3/bin/pip list --format=freeze 2>/dev/null | grep -v "^pip==\|^setuptools==" | sort > /tmp/vol3.txt
printf "pefile==2024.8.26\nvolatility3==2.28.2\n" | diff - /tmp/vol3.txt
if command -v zeek >/dev/null 2>&1; then echo "zeek unexpectedly present" >&2; exit 1; fi
python -c "import yara, pefile, dpkt, LnkParse3; print(\"python engines ok\", yara.YARA_VERSION)"
python -c "import importlib.util as u; assert u.find_spec(\"volatility3\") is None, \"volatility3 must not be importable by the app\""
python -c "from app.parsers.registry import all_parsers; n = sorted(all_parsers()); print(n); assert len(n) == 16"
'

step "api image: AI settings, offline eval harness, rendering pins, KEK, playbooks"
"${COMPOSE[@]}" exec -T api python -c "
from app.config import get_settings
s = get_settings()
assert s.enable_ai and s.llm_provider == 'fake', (s.enable_ai, s.llm_provider)
import anthropic, httpx2
print('anthropic', anthropic.__version__)"
"${COMPOSE[@]}" exec -T api python -m app.ai.eval --suite all
"${COMPOSE[@]}" exec -T api python -c "
import importlib.metadata as md
pins = {'Jinja2': '3.1.6', 'markdown-it-py': '4.2.0', 'reportlab': '5.0.1'}
for name, version in pins.items():
    assert md.version(name) == version, (name, md.version(name))
import app.reports.render_pdf
from reportlab import rl_config
assert rl_config.trustedSchemes == [] and rl_config.trustedHosts == [], 'reportlab fetching enabled'
from app.config import get_settings
from app.integrations.crypto import Keyring, integration_aad
k = Keyring.from_settings(get_settings())
assert k.open(k.seal({'s': 'x' * 32}, integration_aad('p')), integration_aad('p')) == {'s': 'x' * 32}
from app.response.schema import builtin_texts, parse_playbook
assert len([parse_playbook(t) for t in builtin_texts().values()]) == 8
print('api image ok')"

step "app role cannot rewrite custody, audit, events, history, evidence, AI, reports, response records, or become another role"
for stmt in "UPDATE custody_log SET action = 'x'" "DELETE FROM audit_log" \
            "UPDATE signing_keys SET public_key = 'x'" "UPDATE events SET message = 'x'" \
            "TRUNCATE events" "DELETE FROM jobs" "DELETE FROM alerts" \
            "UPDATE alert_history SET reason = 'x'" "DELETE FROM rule_versions" \
            "DELETE FROM notes" "UPDATE notes SET case_id = case_id" "UPDATE notes SET author_id = author_id" \
            "UPDATE note_versions SET body_md = 'x'" "DELETE FROM note_versions" \
            "UPDATE bookmarks SET comment = 'x'" "DELETE FROM entities" "DELETE FROM entity_links" \
            "DELETE FROM entity_aliases" "UPDATE entity_aliases SET alias = 'x'" \
            "DELETE FROM evidence" "TRUNCATE evidence" "UPDATE evidence SET parent_evidence_id = NULL" \
            "UPDATE evidence SET storage_uri = 'x'" "UPDATE evidence SET case_id = case_id" \
            "UPDATE evidence SET label = 'x'" "UPDATE bundle_members SET status = 'verified'" \
            "DELETE FROM bundle_members" "TRUNCATE bundle_members" \
            "DELETE FROM ai_interactions" "TRUNCATE ai_interactions" \
            "UPDATE ai_interactions SET output = '{}'::jsonb" "UPDATE ai_interactions SET model = 'x'" \
            "UPDATE ai_interactions SET status = 'valid'" "UPDATE ai_interactions SET prompt_text = 'x'" \
            "UPDATE ai_interactions SET citations = '[]'::jsonb" "UPDATE event_chunks SET text = 'x'" \
            "TRUNCATE event_chunks" "DELETE FROM ai_index_state" "TRUNCATE ai_index_state" \
            "DELETE FROM reports" "TRUNCATE reports" "UPDATE reports SET context = '{}'::jsonb" \
            "UPDATE reports SET context_sha256 = 'x'" "UPDATE reports SET case_id = case_id" \
            "UPDATE reports SET kind = 'ioc'" "UPDATE reports SET family_id = id" \
            "UPDATE reports SET version = 9" "UPDATE reports SET created_by = NULL" \
            "DELETE FROM playbooks" "TRUNCATE playbooks" "DELETE FROM playbook_runs" \
            "UPDATE playbook_runs SET definition = '{}'::jsonb" "UPDATE playbook_runs SET alert_id = NULL" \
            "UPDATE playbook_runs SET started_by = NULL" "UPDATE playbook_runs SET case_id = case_id" \
            "DELETE FROM playbook_run_steps" "TRUNCATE playbook_run_steps" \
            "UPDATE playbook_run_steps SET requires_approval = false" \
            "UPDATE playbook_run_steps SET action = 'notify.team'" "UPDATE playbook_run_steps SET run_id = run_id" \
            "DELETE FROM action_requests" "TRUNCATE action_requests" \
            "UPDATE action_requests SET requested_by = requested_by" "UPDATE action_requests SET params = '{}'::jsonb" \
            "UPDATE action_requests SET action = 'x'" "UPDATE action_requests SET expires_at = now()" \
            "UPDATE action_requests SET step_id = step_id" \
            "DELETE FROM integrations" "TRUNCATE integrations" \
            "DELETE FROM outbound_events" "UPDATE outbound_events SET payload = '{}'::jsonb" \
            "UPDATE outbound_events SET event_type = 'x'" "DELETE FROM outbound_deliveries" \
            "TRUNCATE outbound_deliveries" "UPDATE outbound_deliveries SET integration_id = integration_id" \
            "UPDATE outbound_deliveries SET event_id = event_id" "UPDATE outbound_deliveries SET max_attempts = 99" \
            "DELETE FROM inbound_deliveries" "TRUNCATE inbound_deliveries" "UPDATE inbound_deliveries SET items = 0" \
            "DELETE FROM ioc_enrichments" "TRUNCATE ioc_enrichments" \
            "DELETE FROM notifications" "UPDATE notifications SET payload = '{}'::jsonb" \
            "UPDATE notifications SET user_id = user_id" \
            "CREATE ROLE dfir_rogue LOGIN" \
            "ALTER ROLE dfirbench_app CREATEDB" "ALTER ROLE dfirbench_app BYPASSRLS" \
            "GRANT dfir TO dfirbench_app" "CREATE SCHEMA rogue" "UPDATE alembic_version SET version_num = 'x'"; do
  out="$("${COMPOSE[@]}" exec -T postgres psql -U dfir -d dfirbench -v ON_ERROR_STOP=1 \
         -c "BEGIN; SET LOCAL ROLE dfirbench_app; $stmt; ROLLBACK;" 2>&1 || true)"
  if ! grep -q "permission denied" <<<"$out"; then
    echo "app role was NOT denied: $stmt -> $out" >&2
    exit 1
  fi
  echo "denied: $stmt"
done

step "the real app login (password from DATABASE_URL) cannot become the owner or another role"
# (SET ROLE inside the loop above runs with the owner as session user, so it is checked here.)
APP_PW="${DATABASE_APP_PASSWORD:-dfir_app_dev_password}"
for stmt in "SET ROLE dfir" "SET SESSION AUTHORIZATION dfir" "RESET ROLE; SET ROLE dfir" \
            "CREATE ROLE dfir_rogue LOGIN" "ALTER ROLE dfirbench_app SUPERUSER" \
            "GRANT dfir TO dfirbench_app" "UPDATE custody_log SET action = 'x'"; do
  out="$("${COMPOSE[@]}" exec -T -e PGPASSWORD="$APP_PW" postgres psql -h 127.0.0.1 \
         -U dfirbench_app -d dfirbench -v ON_ERROR_STOP=1 -c "$stmt" 2>&1 || true)"
  if ! grep -q "permission denied" <<<"$out"; then
    echo "app login was NOT denied: $stmt -> $out" >&2
    exit 1
  fi
  echo "denied (app login): $stmt"
done
"${COMPOSE[@]}" exec -T -e PGPASSWORD="$APP_PW" postgres psql -h 127.0.0.1 -U dfirbench_app \
  -d dfirbench -At -c "SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname = current_user" \
  | gq -x f
unset APP_PW

step "alembic upgrade head + drift check (host -> compose Postgres, owner login)"
"$BIN/alembic" upgrade head
"$BIN/alembic" current | gq '(head)'
"$BIN/alembic" check

step "alembic round trip of migrations 0009-0012 (downgrade 0008 -> upgrade head)"
"$BIN/alembic" downgrade 0008
"$BIN/alembic" current | gq '0008'
"$BIN/alembic" upgrade head
"$BIN/alembic" current | gq '(head)'
"$BIN/alembic" check

step "live smokes (Phases 1-9) through the running API (parsing now runs in the sandbox)"
ADMIN_EMAIL="verify-admin-$(date +%s)-$RANDOM@dfirbench.test"
DFIR_ADMIN_PASSWORD="Phase10-Check-$RANDOM-Passphrase-$(date +%s)"  # policy: not the e-mail name
export DFIR_ADMIN_PASSWORD
"${COMPOSE[@]}" exec -T -e DFIR_ADMIN_PASSWORD api \
  python -m app.cli create-admin --email "$ADMIN_EMAIL" --name "Verify Admin" >/dev/null
for n in 1 2 3 4 5 6 7 8 9; do
  step "Phase $n live smoke"
  "$BIN/python" "$ROOT/scripts/phase$n-smoke.py" --admin-email "$ADMIN_EMAIL"
done
step "Phase 10 live smoke: sandbox container, sandboxed jobs, app login, metrics, headers, integrity, auth limit"
"$BIN/python" "$ROOT/scripts/phase10-smoke.py" --admin-email "$ADMIN_EMAIL"
unset DFIR_ADMIN_PASSWORD

step "the app login survives a migration round trip on live data (0012 down/up), then still connects"
"$BIN/alembic" downgrade 0011
"$BIN/alembic" upgrade head
"$BIN/alembic" check
"${COMPOSE[@]}" restart api >/dev/null
bash "$ROOT/scripts/wait-healthy.sh" 180
curl -fsS -m 10 http://127.0.0.1:8000/api/v1/ready | gq '"status":"ready"'

step "backup -> restore drill into a separate project, verified against the signed manifest"
DRILL="$ROOT/var/verify-drill-$(date +%s)"
mkdir -p "$DRILL"
BACKUP_PASSPHRASE="verify-$RANDOM-$RANDOM-$(date +%s)-backup-passphrase"
export BACKUP_PASSPHRASE
"${COMPOSE[@]}" run --rm --no-deps -T api python -m app.core.signing show \
  /var/lib/dfirbench/keys/custody-dev.pem > "$DRILL/pub.txt" 2>/dev/null
"$PY" - "$DRILL" <<'PYEOF'
import json, sys
from pathlib import Path
drill = Path(sys.argv[1])
lines = (drill / "pub.txt").read_text().splitlines()
key_id, pem = lines[0].strip(), "\n".join(lines[1:]).strip() + "\n"
assert key_id.startswith("ed25519-") and "PUBLIC KEY" in pem, lines[:2]
(drill / "trusted.json").write_text(json.dumps({key_id: pem}))
print("trust anchor (from the live key, not from the backup):", key_id)
PYEOF
"$PY" "$ROOT/scripts/backup.py" --out "$DRILL/backup"
bash "$ROOT/scripts/wait-healthy.sh" 180
"$PY" "$ROOT/scripts/restore.py" --from "$DRILL/backup" --project dfirbench-restore \
  --trusted-keys "$DRILL/trusted.json" --tmp-dir "$DRILL" > "$DRILL/restore.json"
step "a tampered backup and a wrong passphrase are refused before anything is restored"
cp -r "$DRILL/backup" "$DRILL/tampered"
"$PY" -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[4096]^=1; open(p,'wb').write(b)" \
  "$DRILL/tampered/db.dump.enc"
if "$PY" "$ROOT/scripts/restore.py" --from "$DRILL/tampered" --project dfirbench-restore \
     --trusted-keys "$DRILL/trusted.json" --tmp-dir "$DRILL"; then
  echo "a tampered backup was restored" >&2; exit 1
fi
if BACKUP_PASSPHRASE="a-wrong-passphrase-that-is-long" "$PY" "$ROOT/scripts/restore.py" \
     --from "$DRILL/backup" --project dfirbench-restore --trusted-keys "$DRILL/trusted.json" \
     --tmp-dir "$DRILL"; then
  echo "a wrong passphrase was accepted" >&2; exit 1
fi
if docker volume ls -q | gq '^dfirbench-restore_'; then
  echo "restore drill left volumes behind" >&2; exit 1
fi
rm -rf "$DRILL"
unset BACKUP_PASSPHRASE

step "free memory for the test run: stop web, api, worker and the sandbox (postgres/minio/redis stay up)"
"${COMPOSE[@]}" stop web api worker parser-sandbox

step "backend: ruff, mypy, bandit, pytest (unit + integration + MinIO)"
"$BIN/ruff" check .
"$BIN/ruff" format --check .
"$BIN/mypy" app
"$BIN/bandit" -c pyproject.toml -r app -q
"$BIN/python" -m pytest -q -p no:cacheprovider --cov=app --cov-fail-under=80
step "AI eval harness (offline fixtures; targets: citation validity 100%, injection ASR 0%)"
"$BIN/python" -m app.ai.eval --suite all

step "tool validation appendix is current (guide 22.7)"
"$BIN/python" "$ROOT/scripts/tool-validation.py" --check

step "benchmark: 200 000 events (parse, ingest, search, detection) with floors"
"$BIN/python" "$ROOT/scripts/benchmark.py" --events 200000 --search-runs 20 \
  --min-parse-lps 20000 --min-ingest-eps 2000 --max-search-p95-ms 2000 --max-detect-s 300 \
  --json-out "$ROOT/var/benchmark.json"

step "scans: gitleaks, pip-audit, npm audit, Trivy (api, worker) + SBOMs"
bash "$ROOT/scripts/scan.sh"

step "frontend: lint, typecheck, vitest, build"
cd "$ROOT/frontend"
npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm test
npm run build

if [[ "${KEEP_STACK:-0}" != "1" ]]; then
  step "compose stop"
  "${COMPOSE[@]}" stop
fi
step "PHASE 10 VERIFIED"
