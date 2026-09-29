# PHASE 3: Detection

## Goal
Turn the normalized timeline into triageable alerts. A pure, bounded rule engine evaluates
Sigma-inspired YAML rules (single-event, threshold, sequence), built-in anti-forensics detectors
and case IOCs over a case's events; a Celery detection job (queued automatically after every
parse job that ends `succeeded`/`partial`, or on demand) upserts deduplicated, scored alerts,
links them to events, tags the events with ATT&CK ids and records a run manifest with the exact
rule versions. Analysts work alerts through a locked, audited lifecycle; leads/admins manage rules
(custom YAML, Sigma subset import); the ATT&CK coverage table is generated from the rules.

## In scope / Out of scope
In scope: rule format + strict schema, condition language, RE2 regexes, engine (single, threshold
incl. distinct-count, sequence), 25 built-in rules (Appendix B WIN-0001..0012, 0026, 0027 + audit
policy change WIN-0029, command-line log clearing WIN-0030, LNX-0001..0004, 0011, anti-forensics
AF-0001..0003, IOC-0001), Sigma subset converter, IOC normalization/import (CSV, JSON, STIX 2.1
subset)/matching, anti-forensics detectors (EVTX record gaps, out-of-order timestamps, logging
gaps, log truncation vs. acquisition time, 1102/104 clears, audit-policy changes), alert lifecycle,
dedup, scoring (alert/host/case), ATT&CK view, coverage table (endpoint + doc), detection jobs.

Out of scope (see `docs/BACKLOG.md`): suppressions, incident grouping, YARA, statistical
analytics (beaconing, DGA, rare parent-child), SQL push-down of rules, streaming detection at
ingest, MISP import and VT/MISP enrichment, global IOC API, Celery beat (reaper, re-verify,
anchors), asset criticality inventory, Hayabusa.

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/detection/yamlsafe.py` | `safe_yaml(text)`: `yaml.safe_load` after event-stream caps (size, nodes, depth), anchors/aliases rejected |
| `backend/app/detection/fields.py` | allowed fields (Appendix A columns + `raw.<a>.<b>` up to 4 levels), `get_value`, `parse_duration` |
| `backend/app/detection/rules.py` | `RuleModel` (pydantic, `extra="forbid"`), `load_rule(text) -> CompiledRule`, matchers, condition parser (`and/or/not`, `()`, `1 of/any of/all of x*/them`) |
| `backend/app/detection/detectors.py` | `record_gap`, `out_of_order`, `time_gap`, `log_truncation` (record-order source detectors), `ioc_match` |
| `backend/app/detection/engine.py` | `DetectionEngine(rules, iocs, limits).feed(event)`, `.feed_source(source, events)`, `.results() -> [AlertDraft]`, `dedup_key` |
| `backend/app/detection/ioc.py` | `normalize(type, value)`, `IocIndex.match(event)`, `parse_csv/json/stix` |
| `backend/app/detection/sigma.py` | `convert(text, rule_id=None) -> (rule, yaml, notes)`, raises `SigmaError(errors=[...])` |
| `backend/app/detection/scoring.py`, `attack.py`, `coverage.py` | risk formulas, technique format + tactic table, coverage rows/markdown |
| `backend/app/detection/builtin/*.yml` | the built-in pack (one rule per file) |
| `backend/app/services/rules.py` | `RuleService.sync_builtin/list_rules/get/create/update/import_sigma/test/coverage/load_enabled` |
| `backend/app/services/detection.py` | `DetectionJobs.submit` (API + post-parse), `DetectionService.run(job_id)` (worker) |
| `backend/app/services/alerts.py` | `AlertService.list_alerts/get/update/events/attack_matrix/risk` |
| `backend/app/services/iocs.py` | `IocService.list_iocs/create/import_/deactivate` |
| `backend/app/workers/tasks/detect.py` | `dfirbench.detect_case(job_id)` on queue `detect` |
| `backend/app/workers/tasks/parse.py` | `after_parse` hook: queue detection when a parse job ends succeeded/partial |
| `backend/app/api/v1/detection.py`, `schemas/detection.py` | HTTP layer |
| `scripts/phase3-smoke.py`, `scripts/verify-phase3.sh`, `docs/detection-coverage.md` | live smoke, verification, generated coverage doc |

## Rule format
Guide 11.2 keys: `id` (`DFIR-WIN-0001` style), `title`, `status` (stable/test/experimental/
deprecated), `level`, `confidence` (default by status 0.8/0.6/0.4/0.2), `attack` (validated
`T1234[.001]`), `description`, `author`, `references`, `false_positives`, `logsource`
(`source_type`, `channel`, `provider`, `event_category`, `action`), `detection`, `dedup_window`
(1m-30d, default 1d), `response`, `origin_ref`. Unknown keys anywhere are rejected. Selection keys
are `field[|op][|all|any]` with ops `contains startswith endswith re cidr gt gte lt lte exists`;
string comparisons are case-insensitive. `re` uses RE2 (`google-re2==1.1.20251105`, wheels for
Windows and manylinux 2.28 verified): linear time, patterns <= 512 chars, backreferences and
lookaround rejected at load. Bounds: 32 selections x 32 fields x 256 values, condition 2048 chars /
depth 32, threshold count 2-100000 and window <= 1 day, sequence 2-8 steps, `min_count` <= 1000,
`within` <= 7 days, <= 64 raw paths per rule, YAML <= 64 KiB.

## Engine semantics
* single: every match joins the alert keyed by (rule, `group_by` values or `host`, day bucket).
* threshold: per group, `count` matches within `window` (or `count` distinct values of
  `distinct`); events missing a group field are skipped (counted in warnings).
* sequence: per `join_on` key, steps in order within `within` of the first event; step-0 events
  accumulate and extend while waiting for the next step.
* source detectors: per (evidence, source file) in record order; one alert per source and rule.
* dedup key = `rule_id:` + SHA-256(entity, bucket)[:40]; deterministic across runs.
* Limits (`EngineLimits`, settings `DETECT_MAX_ALERTS`, `DETECT_MAX_LINKS_PER_ALERT`): alerts per
  run 20000, linked events per alert 500 (`event_count` keeps the true count), groups per rule
  100000, runs per sequence key 8, events per distinct window 10000. Hitting one -> run `partial`.

## Scoring (deterministic, `app/detection/scoring.py`)
`alert_risk = weight(level) x confidence x asset_criticality` (weights info 5, low 20, medium 45,
high 70, critical 90; criticality 1.0 until an asset inventory exists), one decimal.
`host_risk = 100 x (1 - prod(1 - r/100))`. `case_risk = min(100, max(host_risk) + 10 x
min(distinct tactics, 3))` (guide's "+0.1 per tactic" read on a 0-1 scale). False-positive and
stale alerts do not score.

## Data model changes (`0006_detection.py`)
* rules: `status`, `kind`, `confidence`, `sha256`, `created_by`, `created_at`, CHECKs.
* `rule_versions` (append-only: triggers + SELECT/INSERT grants) - every version of every rule.
* alerts: `dedup_key` NOT NULL (so `UNIQUE (case_id, dedup_key)` dedups), `rule_version`,
  `details`, `status_reason`, `updated_at`, `last_detected_at`, `last_job_id`, `stale`; indexes.
* `alert_history` (append-only) - created/status/assign rows with user or job.
* alert_events: index on `event_id`. iocs: `value_original`, `active`, `created_by`,
  `created_at`, UNIQUE NULLS NOT DISTINCT, CHECKs on type/tlp/confidence.
* jobs: `uq_jobs_queued_detect (case_id) WHERE kind='detect' AND status='queued'`.
* Grants for `dfirbench_app`: rules S/I/U; rule_versions, alert_history S/I; alerts S/I/U;
  alert_events S/I + UPDATE(event_ts); iocs S/I/U; events additionally UPDATE(attack_tags) only.
  No new SECURITY DEFINER functions.

## Concurrency, idempotency and reprocess
* Submit: `FOR SHARE` on the case + open re-check (case close takes `FOR UPDATE` and refuses while
  jobs are active); `INSERT ... ON CONFLICT DO NOTHING` on `uq_jobs_queued_detect`, else merge the
  rule subset into the queued job under `FOR NO KEY UPDATE`.
* Run: claim/lease/fencing token as parse jobs; every batch heartbeats and re-checks
  `(status, attempts)` under the job row lock (cancel stops the run before any further write).
* Alerts: `INSERT ... ON CONFLICT (case_id, dedup_key) DO UPDATE ... WHERE last_detected_at <=
  excluded.last_detected_at` - concurrent runs cannot duplicate (DB constraint) and an older run
  never overwrites a newer one; drafts are flushed in dedup-key order (same lock order). Status,
  assignee and reason are never touched by detection.
* A complete run marks alerts of the evaluated rules it did not reproduce as `stale` and realigns
  `alert_events.event_ts` with the events.
* Reprocess deletes and re-inserts the same deterministic event ids, so links stay valid; the
  post-parse detection run refreshes timestamps, re-tags events and marks non-matching alerts
  stale. Between the reprocess and that run a linked event may be missing: `GET
  /alerts/{id}/events` reports `missing: true`.
* Alert updates: `FOR SHARE` case + open re-check, `FOR NO KEY UPDATE` on the alert, transition
  validated against the locked status, optional `expected_status` -> 409; history + audit rows.

## API changes (all under `/api/v1`)
| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/cases/{id}/detect` | `evidence:add` on the case | `{rules?}` -> 202 `{job, created}`; 409 closed case; 422 unknown rules |
| GET | `/cases/{id}/alerts` | `case:read` | `status`, `severity` (min), `host`, `rule_id`, `technique`, `assignee_id`, `include_stale`, `limit`, `offset` |
| GET/PATCH | `/alerts/{id}` | `case:read` / `alert:update` | detail with history; PATCH `{status?, assignee_id?, reason?, expected_status?}` |
| GET | `/alerts/{id}/events` | `case:read` | linked events with `missing` flag |
| GET | `/cases/{id}/attack`, `/cases/{id}/risk` | `case:read` | technique counts; host/case risk with contributors |
| GET | `/rules`, `/rules/{id}`, `/rules/coverage` | authenticated | built-in pack synced lazily |
| POST/PATCH | `/rules`, `/rules/{id}` | `rules:manage` (lead, admin) | built-ins: enable/disable only; `expected_version` -> 409 |
| POST | `/rules/import/sigma` | `rules:manage` | 422 `unsupported_sigma` lists every unsupported feature |
| POST | `/rules/test` | `investigate` | run a rule over <= 500 sample events |
| GET/POST | `/cases/{id}/iocs` | `case:read` / `investigate` | POST normalizes (refangs) |
| POST | `/cases/{id}/iocs/import` | `investigate` | `{format: csv|json|stix, content, tlp?}` -> created/updated/rejected |
| DELETE | `/cases/{id}/iocs/{ioc_id}` | `investigate` | deactivates (kept for alerts) |
Existing `/jobs/{id}` (manifest), `/cancel`, `/retry` work for detection jobs. Cross-case ids
(alert, IOC, job) answer 404.

## Run manifest (detection)
`job_id, case_id, kind, attempt, worker, trigger, requested_rules, started_at, run_started_at,
tools{python, dfirbench, detection_engine}, builtin_sync, rules[{id, version, sha256, kind}],
rule_warnings, iocs, limits, counts{events_scanned, source_events_scanned, rules, matches, alerts,
alerts_created, alerts_updated, alerts_skipped_older_run, alerts_marked_stale, links_written,
events_tagged}, matches_by_rule, warnings, finished_at, duration_ms, outcome, error`.

## Test plan
* Unit (no Docker): every built-in rule has a positive and a negative fixture
  (`tests/unit/detection_fixtures.py`), metadata/ATT&CK format, coverage doc matches the pack,
  real parser output (golden files) triggers the expected rules, idempotent engine output;
  hostile YAML (aliases, python tags, nesting, size, multi-doc), strict schema rejections, RE2
  rejection + linear-time check, bounds, condition grammar, limits, Sigma subset conversion and
  rejections, IOC normalization/imports/matching, scoring, post-parse trigger.
* Integration (compose Postgres): end-to-end detection via API, idempotent reruns, reprocess
  (same params and changed timezone) keeps links valid, concurrent runs + DB unique constraint,
  8 concurrent submits -> 1 queued job, rule subsets/disabled rules, cancel before flush + retry,
  alert lifecycle/RBAC/404 cross-case/audit/history, concurrent status changes (one wins), closed
  case read-only, rule management + Sigma import + rule test, IOC import/match/deactivate ->
  stale, app-role grants and append-only triggers, migration drift/round trip.
* Live: `scripts/phase3-smoke.py` (also in CI).

## Acceptance criteria (executable)
1. Rule engine (single/threshold/sequence): `pytest tests/unit/test_detection_engine.py tests/unit/test_detection_rules.py`.
2. Starter rules with positive/negative fixtures: `pytest tests/unit/test_detection_rules.py -k "fixture"`.
3. Sigma subset import: `pytest tests/unit/test_detection_engine.py -k sigma` and `tests/integration/test_detection.py::test_rule_management`.
4. IOC matching: `-k ioc` in both suites.
5. Anti-forensics detectors: fixtures for WIN-0001/0002/0027/0029/0030, AF-0001..0003.
6. Alert lifecycle, dedup, scoring: `tests/integration/test_detection.py -k "lifecycle or concurrent or idempotent"`, `-k scoring`.
7. Coverage table: `test_coverage_doc_is_current`, `GET /rules/coverage`.
8. Live: `scripts/phase3-smoke.py` prints `PHASE 3 SMOKE PASSED`.

## Verification command
```bash
bash scripts/verify-phase3.sh
```

## Implementation notes / deliberate deviations
* Rules are evaluated in Python over streamed events (Python "store adapter"), not translated to
  SQL; the AST is store-independent. SQL push-down is in the backlog.
* Sigma: own converter for a documented subset instead of pySigma (no PostgreSQL backend fit);
  unsupported features are rejected with a list, never approximated.
* Permission `rules:manage` (global; lead, admin) added per endpoint table 15.2.
* ATT&CK tags are written to `events.attack_tags` through a column-level UPDATE grant; tags are
  only added (a later non-match does not remove a tag).
* Asset criticality is 1.0 (no inventory yet); case risk tactic bonus interpreted as above.
* EVTX parser 1.0.1 fixes `EventRecordID` -> `source_record_id` (needed for record-gap detection).
