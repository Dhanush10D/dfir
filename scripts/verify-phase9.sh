#!/usr/bin/env bash
# Phase 9 verification (docs/specs/PHASE-9.md): earlier phases plus response and integrations
# (grants and guards of the new tables, outbox task in the worker, live smoke with playbooks, four
# eyes, signed webhooks to a receiver inside the compose network, SIEM ingest, enrichment with the
# offline fake, and a 0012 round trip on the live data the smokes left). No real LLM and no
# network: ENABLE_AI=true LLM_PROVIDER=fake, ENRICHMENT_FAKE=true, and outbound traffic may only
# reach the `api` container (OUTBOUND_ALLOW_HOSTS=api). Exits non-zero on failure.
#   bash scripts/verify-phase9.sh               # stack + live smokes + backend + frontend checks
#   KEEP_STACK=1 bash scripts/verify-phase9.sh  # leave the stack running (default: `compose stop`)
# Memory (7.6 GB host): the api/worker/web containers are stopped before pytest and the frontend
# build, which run one after the other.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/infra/compose.yaml")
step() { printf '\n==> %s\n' "$*"; }

cd "$ROOT/backend"
if [[ -x .venv/Scripts/python ]]; then BIN=.venv/Scripts; else BIN=.venv/bin; fi

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

step "compose up --build (AI on with the offline provider; enrichment fake; outbound only to api)"
export ENABLE_AI=true LLM_PROVIDER=fake ENABLE_ENRICHMENT=true ENRICHMENT_FAKE=true
export OUTBOUND_ALLOW_HTTP=true OUTBOUND_ALLOW_HOSTS=api
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

step "app runs as the least-privilege role; worker has the bundle task"
"${COMPOSE[@]}" exec -T api python -c "
from sqlalchemy import text
from app.db.session import get_engine
with get_engine().connect() as conn:
    role = conn.execute(text('SELECT current_user')).scalar_one()
assert role == 'dfirbench_app', role
print('role', role)"
"${COMPOSE[@]}" exec -T worker python -c "
from app.workers.celery_app import celery_app
celery_app.loader.import_default_modules()  # the 'include' list, as the worker loads it
assert 'dfirbench.ingest_bundle' in celery_app.tasks, sorted(celery_app.tasks)
assert 'dfirbench.process_outbound' in celery_app.tasks, sorted(celery_app.tasks)
from app.collection.trust import load_trusted_collectors
assert load_trusted_collectors(), 'trusted collector list missing from the image'
print('worker tasks ok')"

step "worker image: Sleuth Kit, Volatility 3 (own venv), Python engines; Zeek deliberately absent"
"${COMPOSE[@]}" exec -T worker sh -c '
set -e
cat /opt/dfir/tool-versions.txt
grep -q "^sleuthkit 4.11" /opt/dfir/tool-versions.txt
grep -q "^volatility3 2.28.2" /opt/dfir/tool-versions.txt
fls -V | grep -q "Sleuth Kit"
mmls -V | grep -q "Sleuth Kit"
HOME=/tmp vol --help | grep -q "Volatility 3 Framework 2.28.2"
if command -v zeek >/dev/null 2>&1; then echo "zeek unexpectedly present" >&2; exit 1; fi
python -c "import yara, pefile, dpkt, LnkParse3; print(\"python engines ok\", yara.YARA_VERSION)"
python -c "import importlib.util as u; assert u.find_spec(\"volatility3\") is None, \"volatility3 must not be importable by the app\""
python -c "from app.parsers.registry import all_parsers; n = sorted(all_parsers()); print(n); assert len(n) == 16"
'

step "api image: AI settings, SDK present, offline eval harness passes inside the image"
"${COMPOSE[@]}" exec -T api python -c "
from app.config import get_settings
s = get_settings()
assert s.enable_ai and s.llm_provider == 'fake', (s.enable_ai, s.llm_provider)
import anthropic, httpx2
print('anthropic', anthropic.__version__, 'models', s.llm_model_fast, s.llm_model_strong)"
"${COMPOSE[@]}" exec -T api python -m app.ai.eval --suite all

step "api image: pinned rendering libraries; PDF renderer cannot fetch URLs or read files"
"${COMPOSE[@]}" exec -T api python -c "
import importlib.metadata as md
pins = {'Jinja2': '3.1.6', 'markdown-it-py': '4.2.0', 'reportlab': '5.0.1'}
for name, version in pins.items():
    assert md.version(name) == version, (name, md.version(name))
import app.reports.render_pdf
from reportlab import rl_config
assert rl_config.trustedSchemes == [] and rl_config.trustedHosts == [], 'reportlab fetching enabled'
print('rendering pins ok', pins)"
"${COMPOSE[@]}" exec -T api python -m app.reports.verify --help >/dev/null

step "api image: integration secrets can be sealed (KEK outside the DB), outbound policy as configured"
"${COMPOSE[@]}" exec -T api python -c "
from app.config import get_settings
from app.integrations.crypto import Keyring, integration_aad
from app.integrations.outbound import OutboundPolicy
s = get_settings()
k = Keyring.from_settings(s)
sealed = k.seal({'signing_secret': 'x' * 32}, integration_aad('probe'))
assert k.open(sealed, integration_aad('probe')) == {'signing_secret': 'x' * 32}
p = OutboundPolicy.from_settings(s)
assert p.allow_hosts == frozenset({'api'}) and p.allow_networks == (), p
assert s.enable_enrichment and s.enrichment_fake
print('kek', sealed.key_id, 'outbound allow', sorted(p.allow_hosts))"
"${COMPOSE[@]}" exec -T api python -c "
from app.response.schema import builtin_texts, parse_playbook
ids = sorted(parse_playbook(t).id for t in builtin_texts().values())
assert len(ids) == 8, ids
print('playbooks', ids)"

step "app role cannot rewrite custody, audit, events, history, entities, evidence, bundle verdicts, AI records, reports, response and integration records"
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
            "UPDATE notifications SET user_id = user_id"; do
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

step "alembic round trip of migrations 0009-0012 (downgrade 0008 -> upgrade head)"
"$BIN/alembic" downgrade 0008
"$BIN/alembic" current | grep -q '0008'
"$BIN/alembic" upgrade head
"$BIN/alembic" current | grep -q '(head)'
"$BIN/alembic" check

step "live smokes (Phases 1-8) through the running API"
ADMIN_EMAIL="verify-admin-$(date +%s)-$RANDOM@dfirbench.test"
DFIR_ADMIN_PASSWORD="Phase8-Check-$RANDOM-Passphrase-$(date +%s)"  # policy: not the e-mail name
export DFIR_ADMIN_PASSWORD
"${COMPOSE[@]}" exec -T -e DFIR_ADMIN_PASSWORD api \
  python -m app.cli create-admin --email "$ADMIN_EMAIL" --name "Verify Admin" >/dev/null
"$BIN/python" "$ROOT/scripts/phase1-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase2-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase3-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase4-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase5-smoke.py" --admin-email "$ADMIN_EMAIL"
"$BIN/python" "$ROOT/scripts/phase6-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 7 live smoke: AI features, citations, injection handling, review, RBAC"
"$BIN/python" "$ROOT/scripts/phase7-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 8 live smoke: snapshot, QA gate, four eyes, sign, verify, tamper, AI draft, export package"
"$BIN/python" "$ROOT/scripts/phase8-smoke.py" --admin-email "$ADMIN_EMAIL"
step "Phase 9 live smoke: playbooks, four eyes, signed webhooks, SIEM ingest, enrichment, secrets"
"$BIN/python" "$ROOT/scripts/phase9-smoke.py" --admin-email "$ADMIN_EMAIL"
unset DFIR_ADMIN_PASSWORD

step "free memory for the test run: stop api, worker and web (postgres/minio/redis stay up)"
"${COMPOSE[@]}" stop web api worker

step "0012 round trip on the live data the smokes left (runs, requests, deliveries, secrets)"
"$BIN/alembic" downgrade 0011
"$BIN/alembic" current | grep -q '0011'
"$BIN/alembic" upgrade head
"$BIN/alembic" current | grep -q '(head)'
"$BIN/alembic" check

step "backend: ruff, mypy, bandit, pytest (unit + integration + MinIO)"
"$BIN/ruff" check .
"$BIN/ruff" format --check .
"$BIN/mypy" app
"$BIN/bandit" -c pyproject.toml -r app -q
"$BIN/python" -m pytest -q -p no:cacheprovider --cov=app --cov-fail-under=80
step "AI eval harness (offline fixtures; targets: citation validity 100%, injection ASR 0%)"
"$BIN/python" -m app.ai.eval --suite all

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
step "PHASE 9 VERIFIED"
