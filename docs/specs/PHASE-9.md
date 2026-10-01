# PHASE 9: Response + integrations

## Goal
Give a case a guided response (guide 19): YAML playbooks loaded into the database and run as
checklists of manual steps and allowlisted actions; impactful actions gated by a four-eyes approval
that can be rejected or expire and that executes at most once; notification rules with
deduplication and rate limits (in-app, Slack, Teams, e-mail); signed outbound webhooks delivered
by a Celery task with bounded retries and a delivery log; HMAC-authenticated SIEM/EDR webhook
ingest that turns untrusted payloads into alerts of the case the integration is configured for;
and indicator enrichment (VirusTotal, MISP) behind a provider interface with a fake, a cache, a
policy switch and TLP rules. Integration credentials are envelope-encrypted and write-only. All
outbound network traffic of this phase leaves through one module with SSRF protection. This is the
**Standard** profile: there is no remote agent, so endpoint actions (`agent.*`) are never executed
by the platform; they are recorded as `not_executed` and finished by a person.

## In scope / Out of scope
In scope:
* `app/response/`: playbook schema and loader (safe YAML, caps, strict Pydantic, duplicate ids),
  closed action registry, eight starter playbooks (guide 19.1).
* `app/integrations/`: `outbound.py` (the only outbound HTTP/SMTP module), `crypto.py` (envelope
  encryption), `webhooks.py` (HMAC signing/verification), `messages.py` (event payloads and
  notification rendering with escaping), `inbound.py` (payload mapping), `enrichment.py`
  (providers + fake, TLP policy).
* Services: `playbooks.py`, `integrations.py`, `outbox.py` (event emission, fan-out, delivery),
  `ingest.py`, `enrichment.py`, `notifications.py` (in-app list/read, rules).
* Migration 0012, models, API routers, Celery task, frontend (case tab "Response", admin page
  "Integrations", notifications panel), `docs/response.md`, smoke + verify scripts, tests.

Out of scope (see `docs/BACKLOG.md`): the remote agent and real endpoint actions (guide 9.4, P2);
ticketing (Jira/ServiceNow) sync; S3 bulk log import; SSO; OpenCTI; MISP event pull/import and
TAXII publishing; fetching logs from a SIEM API; a scheduler (Celery beat) for delivery sweeps and
approval expiry (both are done on access/dispatch here); redelivery of failed webhooks from the
UI; AI playbook recommendation (A11; deterministic trigger matching is in scope); alert
suppressions, incident grouping, asset inventory, new detection rules, global IOC API, user YARA
rules (re-targeted in the backlog).

## Standard-profile decisions (made without the owner; recorded here)
1. **One outbound module.** `app/integrations/outbound.py` is the only module that opens sockets
   to integration endpoints (HTTP via `http.client`, SMTP via `smtplib`); a unit test scans the
   package imports to keep it so (`ai/gateway.py` stays the only LLM caller, `storage.py` the
   only object-store client). No third-party HTTP client is used here, so PyMISP is not used
   either: the MISP and VirusTotal providers call their REST APIs through `OutboundHttp`.
2. **SSRF policy.** `https` only (`http` only with `OUTBOUND_ALLOW_HTTP=true`, refused in prod);
   no credentials in URLs; ports 1-65535; the host is resolved once through an injectable
   resolver; every resolved address must be public unless `OUTBOUND_ALLOW_HOSTS` (host names or
   CIDRs) permits it: loopback, RFC 1918/ULA private, link-local (incl. the 169.254.169.254
   metadata address and `fd00:ec2::254`), CGNAT 100.64/10, multicast, unspecified, reserved,
   IPv4-mapped/6to4/NAT64 forms of those are refused. A host-name entry permits that host's
   private, loopback and CGNAT addresses; link-local/metadata, multicast and unspecified addresses
   are permitted only by a CIDR entry that contains them. The connection is made to the validated
   IP (TLS SNI and certificate check use the host name; no second resolution), redirects are
   never followed, connect and read timeouts and a total deadline apply, the response is read as
   a stream up to a cap and the request body is capped.
3. **Secrets.** `integrations.config_encrypted` holds the secret JSON encrypted with AES-256-GCM
   under a random per-record data key; the data key is wrapped with AES-256-GCM under the
   key-encryption key (KEK) derived from `INTEGRATION_KEK` / `INTEGRATION_KEK_PATH` (outside the
   DB), with `secret_key_id` stored for rotation (`INTEGRATION_KEK_PREVIOUS_PATH` holds retired
   KEKs; `python -m app.cli rewrap-integration-secrets` re-wraps data keys). The integration id
   is the AAD. The API never returns secrets: only `has_secret` and a keyed fingerprint (HMAC
   under a KEK-derived key, 12 hex characters). Secrets are never put in audit rows, logs, error
   messages, delivery logs or Celery arguments (tasks take no arguments at all).
4. **Events and the outbox.** Business services call `emit_event(session, ...)`, which inserts an
   `outbound_events` row inside a SAVEPOINT and never raises; an `after_commit` session hook then
   asks the dispatcher (from `session.info`, set only by the process-wide session factory, so
   tests are inert by default) to run the Celery task `dfirbench.process_outbound` (no
   arguments). The task fans events out to matching integrations and in-app recipients and
   delivers due deliveries: attempts are claimed under `FOR UPDATE SKIP LOCKED`, at most
   `OUTBOUND_MAX_ATTEMPTS` (5) with exponential backoff, ending `delivered` or the terminal
   `failed`; `suppressed` records a notification dropped by deduplication or the rate limit.
   Guide events: `alert.created`, `case.status_changed`, `report.signed`,
   `evidence.verification_failed`; internal ones: `playbook.run_started`,
   `playbook.approval_requested`, `playbook.notice`.
5. **Webhook signature (guide 15.6).** `X-Timestamp` (Unix seconds), `X-Signature:
   sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>`, `X-Event`, `X-Delivery-Id`.
   Receivers reject old timestamps. The same scheme authenticates inbound ingest.
6. **Notification content.** Messages are built from constant text and a closed set of payload
   fields (ids, case number, severity, counts, status names, a link when `PUBLIC_BASE_URL` is
   set). Evidence-derived text (alert titles, hosts) is included only when a channel sets
   `include_details`, is never used as a template, is stripped of control characters and escaped
   for the target (Slack `& < >` with markup off, Teams Markdown, e-mail headers without CR/LF).
   Rules: per-channel `events` and `min_severity`; in-app rules in `settings.notification_rules`
   (defaults: alert of severity high or above -> case lead; evidence verification failed ->
   admins; report signed -> case members; approval requested -> case approvers). Deduplication
   window `NOTIFY_DEDUP_WINDOW_S` and per-channel `NOTIFY_RATE_LIMIT_PER_HOUR`.
7. **Inbound ingest.** `POST /ingest/webhook/{integration_id}`: the body cap is enforced from
   `Content-Length` and again while streaming, before authentication; unknown source, bad
   signature and stale timestamp all answer the same 401; the replay key is the signed digest
   (UNIQUE per integration in `inbound_deliveries`, append-only); a replayed delivery is answered
   idempotently without changes. The target case comes from the integration row only. Items are
   mapped with length caps through `normalize.clean_text/clean_json/clean_ip` into `alerts`
   (`rule_id` NULL, `dedup_key = ext:<integration>:<sha256(external id)>`), with an
   `alert_history` row and `alert.created`; a malformed item is one counted error. Closed cases
   answer 409. Rate limits per source and per client address (Redis, fail closed).
8. **Playbooks.** Packaged YAML (`app/response/builtin/*.yml`) is synced into `playbooks` under
   an advisory lock (version bump on change); custom playbooks can be imported by rules managers.
   A run stores a snapshot of the definition and one `playbook_run_steps` row per step (guide 7.3
   keeps step state in JSONB; rows are needed for DB-enforced approvals).
9. **Actions.** A closed registry (dict) maps action names to handlers; unknown names are
   rejected at load time. `agent.isolate_host`, `agent.kill_process`, `agent.disable_account`
   are impactful (approval always required, whatever the YAML says) and, like
   `agent.memory_dump` and `agent.collect_triage`, have no executor in this profile: executing
   them records `not_executed` with the reason, and the step stays open until a person records
   that it was done by hand (`completed_manually`) or skips it. `notify.team` is the real
   action (writes an outbox event in the same transaction, so it happens exactly once).
10. **Approvals.** An impactful step needs an `action_requests` row approved by someone with
    `approve` on the case who is not the requester. Requests expire
    (`APPROVAL_TTL_MINUTES`, default 240) and can be rejected (or withdrawn by the requester).
    Service and database both enforce it: a trigger compares with `OLD`, keeps requester, action
    and parameters immutable, allows only `pending -> approved|rejected|expired` and
    `approved -> finished|expired`, requires `decided_by <> OLD.requested_by` for approval before
    `OLD.expires_at`, and freezes finished rows; CHECK constraints describe every state. Every
    read-modify-write takes row locks in the order case (share), run, step, request and
    re-checks state after locking. Execution moves `approved -> finished` under the lock, once.
11. **Dry run.** `dry_run: true` on run creation returns the plan (steps, what each action would
    do, approvals needed, notifications) and writes nothing; `dry_run` on a step returns the
    action plan without changing state.
12. **Enrichment.** Off unless `ENABLE_ENRICHMENT=true` and the provider's integration is enabled.
    Only `ip`, `domain`, `url`, `sha256/sha1/md5` values are sent, never files or evidence
    content. TLP: VirusTotal gets `clear/white/green` only; MISP up to the integration's
    `max_tlp` (default `green`, never `red`); an IOC without TLP counts as `amber`. Sightings are
    exported only to MISP and under the same rule. Results are cached in `ioc_enrichments` for
    `ENRICHMENT_CACHE_TTL_H`. `ENRICHMENT_FAKE=true` (refused in prod) swaps every provider for
    the deterministic fake; tests and smokes use only the fake.
13. **Environment variables.** The Phase 0 placeholders `VT_API_KEY`, `MISP_URL`, `MISP_KEY`,
    `SLACK_WEBHOOK_URL`, `SMTP_*` are removed: credentials are configured through the API and
    stored encrypted.

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/integrations/outbound.py` | `OutboundPolicy`, `check_url`, `OutboundHttp.request`, `OutboundMailer.send`, `OutboundBlockedError`, `OutboundError` |
| `backend/app/integrations/crypto.py` | `Keyring.from_settings`, `seal`, `open_sealed`, `fingerprint`, `rewrap` |
| `backend/app/integrations/webhooks.py` | `sign(secret, ts, body)`, `verify(secret, ts, body, signature, now, window)` |
| `backend/app/integrations/messages.py` | event payload builders, `render_slack/teams/email/webhook`, escaping |
| `backend/app/integrations/inbound.py` | `parse_items(body)`, `map_item(item, field_map) -> ExternalAlert` |
| `backend/app/integrations/enrichment.py` | `EnrichmentProvider`, `VirusTotalProvider`, `MispProvider`, `FakeEnrichmentProvider`, `tlp_allows` |
| `backend/app/response/schema.py`, `registry.py`, `builtin/*.yml` | `parse_playbook(text)`, `ACTIONS`, starter playbooks |
| `backend/app/services/playbooks.py` | `PlaybookService` (sync, import, runs, steps, approvals) |
| `backend/app/services/integrations.py` | `IntegrationService` (admin CRUD, write-only secrets, test, delivery log) |
| `backend/app/services/outbox.py` | `emit_event`, `OutboundService.process` |
| `backend/app/services/ingest.py` | `WebhookIngestService.ingest` |
| `backend/app/services/enrichment.py` | `EnrichmentService.enrich`, `export_sighting` |
| `backend/app/services/notifications.py` | in-app notifications, rules |
| `backend/app/api/v1/response.py`, `integrations.py`, `ingest.py` + schemas | API |
| `backend/app/workers/tasks/outbound.py` | `dfirbench.process_outbound` |
| `backend/alembic/versions/0012_response.py`, `backend/app/db/models/response.py`, `ops.py` | schema |
| `frontend/src/features/response/*`, `frontend/src/features/integrations/*` | UI |
| `docs/response.md` | playbooks, approvals, integrations, signatures, SSRF policy |

## Data model changes (migration 0012, after `0011_reporting`)
* `playbooks` + `sha256`, `origin` (builtin/custom), `notify`, `created_by`; no DELETE.
* `playbook_runs` + `alert_id`, `dry_run`-free snapshot `definition`, `playbook_sha256`; CHECKs on
  status (`running`, `completed`, `cancelled`) and `finished`; guard trigger; the app may UPDATE
  only `status`, `finished_at`. `step_states` stays (holds archived steps after a downgrade).
* `playbook_run_steps` (new): identity columns immutable, status machine and CHECKs, guard trigger
  that requires an approved/finished request for approval steps; no DELETE.
* `action_requests` (new): see decision 10; UNIQUE idempotency key; one open request per step.
* `integrations` + `config`, `case_id`, `secret_wrapped_key`, `secret_key_id`,
  `secret_fingerprint`, audit columns; CHECKs on type and secret consistency; no DELETE.
* `outbound_events`, `outbound_deliveries` (new; guard trigger freezes terminal deliveries),
  `inbound_deliveries` (new, append-only), `ioc_enrichments` (new cache).
* `notifications` + `case_id`, `dedup_key` (partial UNIQUE per user); UPDATE of `read_at` only.
* Downgrade: archives steps into `playbook_runs.step_states`, cancels running runs, drops the new
  tables, clears integration secrets (the wrapped key is dropped) and disables those
  integrations. The upgrade applies the same rules to any pre-0012 rows.

## API changes
| Method | Path | Access |
|---|---|---|
| GET | `/playbooks`, `/playbooks/{id}` | any user |
| POST | `/playbooks` (YAML import) | `rules:manage` |
| GET | `/alerts/{aid}/playbooks` (trigger matches) | case read |
| POST/GET | `/cases/{id}/playbook-runs` (`dry_run`) | start: `investigate`; list: case read |
| GET | `/playbook-runs/{rid}` | case read |
| PATCH | `/playbook-runs/{rid}/steps/{key}` (`op`: complete, skip, request, execute) | `investigate` |
| POST | `/playbook-runs/{rid}/cancel` | `investigate` |
| GET | `/cases/{id}/action-requests` | case read |
| POST | `/action-requests/{id}/approve`, `/reject` | `approve` (reject: or the requester) |
| GET/POST | `/integrations`; GET/PATCH `/integrations/{id}`; POST `/integrations/{id}/test`; GET `/integrations/{id}/deliveries` | `users:manage` |
| GET/PUT | `/settings/notification-rules` | `users:manage` |
| GET | `/notifications`; POST `/notifications/{id}/read` | the user |
| POST | `/ingest/webhook/{integration_id}` | HMAC |
| POST | `/cases/{id}/iocs/enrich`; GET `/cases/{id}/enrichments`; POST `/cases/{id}/iocs/{ioc}/sighting` | `investigate` / case read |

## Settings (new)
`INTEGRATION_KEK`, `INTEGRATION_KEK_PATH`, `INTEGRATION_KEK_ID`, `INTEGRATION_KEK_PREVIOUS_PATH`,
`OUTBOUND_ALLOW_HTTP`, `OUTBOUND_ALLOW_HOSTS`, `OUTBOUND_CONNECT_TIMEOUT_S`,
`OUTBOUND_READ_TIMEOUT_S`, `OUTBOUND_MAX_RESPONSE_KB`, `OUTBOUND_MAX_REQUEST_KB`,
`OUTBOUND_MAX_ATTEMPTS`, `OUTBOUND_BACKOFF_BASE_S`, `PUBLIC_BASE_URL`, `NOTIFY_DEDUP_WINDOW_S`,
`NOTIFY_RATE_LIMIT_PER_HOUR`, `INGEST_MAX_BODY_KB`, `INGEST_MAX_ITEMS`,
`INGEST_TIMESTAMP_WINDOW_S`, `INGEST_RATE_LIMIT_PER_MINUTE`, `APPROVAL_TTL_MINUTES`,
`ENABLE_ENRICHMENT`, `ENRICHMENT_FAKE`, `ENRICHMENT_CACHE_TTL_H`, `ENRICHMENT_MAX_PER_REQUEST`.

## Test plan
* Unit (no DB, no network): SSRF table (each address class, IPv4-mapped, allowlist, scheme,
  userinfo, port), pinned connect + no redirects + response cap + timeout against a loopback
  server reached through the injected resolver, request cap; envelope encryption round trip, AAD
  binding, wrong KEK, rotation/rewrap, fingerprint; HMAC sign/verify, window, constant-time
  compare; message rendering and escaping (Slack, Teams, CRLF in e-mail headers, no sensitive
  fields by default); inbound mapping (caps, malformed items, depth); playbook schema (unknown
  action, duplicate ids, size/nesting caps, aliases, impactful forces approval), every starter
  playbook loads; TLP policy; fake/VT/MISP providers against a fake transport; import scan for
  the single outbound module.
* Integration (compose Postgres, app role): playbook sync + run lifecycle, dry run changes
  nothing, four eyes (service and trigger attacks as the app role and as owner), reject, expiry,
  execute once under concurrency, closed case, RBAC and case isolation; integrations CRUD with
  write-only secrets (not in responses, audit, logs); outbox emission never breaks the business
  transaction; fan-out, signing, retries to terminal failure, SSRF-blocked delivery, dedup and
  rate limit; ingest (auth matrix with uniform 401, replay, size cap, malformed items,
  idempotency, closed case, rate limit); enrichment (policy switch, TLP, cache, indicators
  only, sighting); grants; migration round trip with rows in every state.
* Live: `scripts/phase9-smoke.py`.

## Acceptance criteria (executable)
1. `pytest tests/unit/test_outbound.py tests/unit/test_integrations_*.py
   tests/unit/test_playbooks.py tests/integration/test_response.py
   tests/integration/test_integrations.py`
2. A playbook run records user, time, result and the triggering alert for every step; an
   impactful action cannot run without approval by a second person, runs once, and is recorded as
   `not_executed` in this profile; a dry run writes nothing.
3. A signed outbound webhook reaches a receiver that verifies `X-Signature`; a delivery to a
   private address is refused and ends `failed` after bounded retries.
4. A signed SIEM delivery creates alerts in the configured case; replays, bad signatures, stale
   timestamps and oversized bodies are refused; malformed items are counted.
5. Enrichment returns cached verdicts from the fake provider and refuses amber/red indicators.
6. Secrets never appear in API responses, audit rows or delivery logs.
7. Live: `scripts/phase9-smoke.py` prints `PHASE 9 SMOKE PASSED`.
8. Earlier phases: Phase 1-8 smokes, app-role denials, 0012 round trip, backend
   lint/format/type/bandit/tests (coverage >= 80), AI eval, frontend checks.

## Amendments during the build
* 0012 also has CHECK `ck_playbook_run_steps_impactful` (the impactful `agent.*` actions always
  require approval); the step guard requires a new step to belong to a running run of its case;
  the request guard requires a new request to match an open approval step of its run (same case
  and action) and refuses approval and execution once the database clock is past the expiry.
* Enrichment entries also return the indicator type and value (case readers can see the case's
  IOCs anyway), so the Response tab can show them.
* Frontend: the Integrations page also edits the in-app notification rules and shows a source's
  ingest endpoint; the Response tab also has an enrichment panel and playbook suggestions for an
  alert id. Editing an existing integration's non-secret configuration in the UI is backlogged
  (the API supports it).
* `.github/workflows/ci.yml` needs no new variables: the tests build their settings explicitly
  (test KEK, strict outbound policy, fake enrichment) and never read the CI environment. The
  compose stack passes the Phase 9 settings with dev defaults (a placeholder KEK that prod
  refuses).

## Verification command
```bash
bash scripts/verify-phase9.sh
```
