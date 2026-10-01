# Response and integrations (Phase 9)

Guided response for a case (guide 19): YAML playbooks run as checklists, four-eyes approvals for
impactful actions, notifications, signed outbound webhooks, HMAC-authenticated SIEM/EDR ingest and
indicator enrichment. The spec is `docs/specs/PHASE-9.md`; deferred items are in
`docs/BACKLOG.md` ("From Phase 9").

**Standard profile: there is no remote agent.** Endpoint actions (`agent.*`) are never executed by
the platform. Executing one records the outcome `not_executed` with the reason, the UI says
"NOT EXECUTED by the platform", and the step stays open until a person records how and where the
action was carried out by hand (`completed_manually`, notes required) or skips it with a reason.
Nothing in the platform ever claims that a host was isolated or an account disabled.

## Playbooks

Packaged playbooks live in `backend/app/response/builtin/*.yml` (eight starters: ransomware,
credential compromise, exfiltration, log tampering, malware, phishing, cloud, web shell). They
are synced into the `playbooks` table on first use and by `python -m app.cli sync-playbooks`
(under an advisory lock; a changed file bumps the version; a file that is no longer shipped is
disabled, never deleted, because runs reference it). Rules managers can import custom playbooks
with `POST /playbooks` (`{"yaml": "..."}`); a custom playbook cannot take a built-in id.

```yaml
id: PB-RANSOMWARE-01                 # PB-[A-Z0-9-]
title: Suspected ransomware
description: Contain, preserve, recover.
trigger: { attack: [T1486, T1490], rules: [DFIR-WIN-0010] }   # suggestions for an alert
phases:
  - name: Containment
    steps:
      - { id: c1, text: "Isolate affected hosts", action: agent.isolate_host, requires_approval: true }
      - { id: c2, text: "Disable compromised accounts", manual: true }
      - { id: c3, text: "Tell the team", action: notify.team }
notify: { channels: [in_app, slack, email], roles: [lead] }
```

Loading treats the file as hostile input: `yaml.safe_load` through the shared size, node and
nesting caps (64 KiB, 5000 nodes, depth 8), anchors/aliases and duplicate keys refused, then a
strict Pydantic schema (unknown keys and wrong types are errors, no coercion), unique phase names
and step ids, at most 200 steps, and action names from the closed registry only.

### Actions (closed registry, `app/response/registry.py`)

| Action | Impactful (approval always required) | Executor in this profile |
|---|---|---|
| `agent.isolate_host` (host) | yes | none: recorded `not_executed` |
| `agent.kill_process` (host, pid, process) | yes | none |
| `agent.disable_account` (account, host) | yes | none |
| `agent.memory_dump` (host) | no | none |
| `agent.collect_triage` (host) | no | none |
| `notify.team` | no | platform: one `playbook.notice` outbox event in the same transaction |

`GET /playbook-actions` lists the registry. A playbook file can add `requires_approval` to any
action but can never remove it from an impactful one; the database enforces the same rule
(CHECK `ck_playbook_run_steps_impactful`).

### Runs and steps

`POST /cases/{id}/playbook-runs` (`investigate`) starts a run, optionally for a triggering alert
(`alert_id`). The run stores a snapshot of the definition (`definition`, `playbook_sha256`) and
one `playbook_run_steps` row per step. `GET /alerts/{id}/playbooks` lists playbooks whose trigger
names the alert's rule or one of its ATT&CK techniques (deterministic matching; no AI).

With `dry_run: true` the same call returns the plan (steps, what each action would do, approvals
needed, notifications) with status 200 and writes nothing. `PATCH .../steps/{key}` with
`dry_run: true` does the same for one step.

`PATCH /playbook-runs/{rid}/steps/{key}` takes `op`:

| op | Allowed for | Effect |
|---|---|---|
| `complete` | a pending manual step; an action step that is `not_executed` (notes required) | `done` (`completed` or `completed_manually`) |
| `skip` | pending, failed or not_executed steps; reason in `notes` required | `skipped` |
| `request` | an action step that needs approval | creates an `action_requests` row (`pending`), step `awaiting_approval` |
| `execute` | an action without approval (pending/failed), or an `approved` step | runs the handler once: `done`, `failed` or `not_executed` |

Every step records who changed it and when (`updated_by/at`, `completed_by/at`), its outcome and
result, and the run carries the triggering alert. Every operation is audited (parameters only as a
SHA-256). `POST /playbook-runs/{rid}/cancel` (reason required) ends a run; its pending requests are
rejected. Closed cases refuse every change (409). Case isolation answers 404 to outsiders.

## Four-eyes approvals

An impactful step runs only through an `action_requests` row approved by someone with `approve`
on the case who is **not** the requester. Requests expire after `APPROVAL_TTL_MINUTES` (default
240), can be rejected by an approver, or withdrawn by the requester (reason required). The
requester, action and parameters are fixed when the request is made; execution with different
parameters is refused (`params_changed`).

Enforced twice:

* **Service** (`services/playbooks.py`): every read-modify-write locks, in this order, the case row
  (`FOR SHARE`), the run, the step and the request (`FOR UPDATE`) and re-checks state after the
  locks. Execution moves the request `approved -> finished` under the locks, so an approved action
  executes at most once (a concurrent second attempt gets 409). Expiry is applied on access: every
  read of a run or the request list and every decision first expires overdue requests.
* **Database** (migration 0012). The app role may UPDATE only the workflow columns
  (`status`, decision and outcome columns), never the requester, action, parameters or expiry.
  The trigger `action_requests_guard` compares with `OLD`: a new request must be pending and must
  match an open approval step of its run (same case and action); only
  `pending -> approved | rejected | expired` and `approved -> finished | expired` are allowed;
  approval needs `decided_by <> OLD.requested_by` before `OLD.expires_at` (by the recorded time
  and by the database clock); decision and outcome columns change only with their transition;
  finished, rejected and expired rows are frozen. CHECK constraints describe every state
  (`ck_action_requests_four_eyes` and friends hold even with triggers bypassed). The step trigger
  lets an approval step reach an executed state only after its request was approved by a second
  person and finished with the same outcome. `tests/integration/test_response.py` attacks all of
  this as the app role (requester swap and self-approval in one UPDATE, approval without a
  decider or after expiry, skipping the approval, rewriting a decision, executing twice, forged
  steps and requests).

## Events, notifications and the outbox

Business services call `emit_event(session, ...)` (`services/outbox.py`): it inserts an
`outbound_events` row inside a SAVEPOINT of the caller's transaction and never raises, so an event
can never fail or roll back the business change. After the commit, the API asks the worker to run
`dfirbench.process_outbound`, a task **without arguments**: event ids, URLs and secrets never travel
through the broker. Events: `alert.created`, `case.status_changed`, `report.signed`,
`evidence.verification_failed`, `playbook.run_started`, `playbook.approval_requested`,
`playbook.notice`, and `integration.test` (the test button).

The task fans every new event out to the enabled integrations that subscribe to it (`events`,
`min_severity`, optional `case_ids`; a playbook's `notify.channels` narrow its own events) and to
in-app recipients per the notification rules, then delivers what is due:

* each attempt is claimed under `FOR UPDATE SKIP LOCKED` with a lease and sent with no
  transaction open; the result is recorded under the row lock;
* transient failures (timeouts, connection errors, HTTP 408/425/429/5xx) are retried with
  exponential backoff (`OUTBOUND_BACKOFF_BASE_S * 2^(attempt-1)`, at most 1 h) up to
  `OUTBOUND_MAX_ATTEMPTS`, then the delivery ends `failed`; a refused address, a TLS error or
  another permanent error ends it `failed` at once;
* `last_error` stores an error category only (e.g. `blocked:address_private`, `http_500`,
  `timeout`), never a URL, header, body or secret. The delivery log is
  `GET /integrations/{id}/deliveries`.

**Notification content.** Messages are built from fixed text and a closed set of payload fields
(ids, case number, severity, counts, status names, and a link when `PUBLIC_BASE_URL` is set).
Evidence-derived text (alert title, host, evidence label) is included only when a channel sets
`include_details`; it is never used as a template, is stripped of control and bidirectional
characters, and is escaped for the target: Slack `& < >` with `mrkdwn` off, Teams Markdown
escaping, e-mail subjects without CR/LF. Notifications to people (Slack, Teams, e-mail, in-app)
are deduplicated within `NOTIFY_DEDUP_WINDOW_S` and limited to `NOTIFY_RATE_LIMIT_PER_HOUR` per
channel (and per in-app user); a dropped one is recorded as `suppressed`.

**In-app rules** (`GET/PUT /settings/notification-rules`, admin; editable on the Integrations
page). Defaults: alert of severity high or above -> case lead; evidence verification failed ->
administrators; report signed -> case members; approval requested -> case approvers. The actor
of an event is not notified about it. Users read their own notifications on the Notifications
page (`GET /notifications`, `POST /notifications/{id}/read`, `POST /notifications/read-all`).

## Integrations and secrets

`/integrations` (admin, `users:manage`) configures `webhook_out`, `webhook_in`, `slack`, `teams`,
`email`, `virustotal` and `misp`. `config` is non-secret and validated per type; the secret is a
separate, write-only field:

| Type | Secret field |
|---|---|
| `webhook_out`, `webhook_in` | `signing_secret` (at least 32 characters) |
| `slack`, `teams` | `webhook_url` (the incoming-webhook URL is the credential) |
| `email` | `password` (optional) |
| `virustotal`, `misp` | `api_key` |

**Envelope encryption** (`app/integrations/crypto.py`): each secret gets a random 256-bit data
key; the secret JSON is encrypted with AES-256-GCM under it, and the data key is wrapped with
AES-256-GCM under the key-encryption key (KEK). The integration id is the associated data, so a
ciphertext copied to another row does not decrypt. The KEK is derived (HKDF-SHA256) from
`INTEGRATION_KEK` or the file `INTEGRATION_KEK_PATH` and never touches the database; its id
(`INTEGRATION_KEK_ID`) is stored with every secret. Without a KEK the platform runs but secrets
cannot be saved (`secrets_available: false`, 503 on save).

The API never returns a secret: only `has_secret`, the key id and a keyed fingerprint (HMAC under a
KEK-derived key, 12 hex characters). Audit rows record which names changed and whether the secret
changed. An integration can be enabled only when it is complete (required secret, events chosen,
an ingest source bound to a case). Integrations are never deleted (delivery logs reference them);
disable them instead.

**KEK rotation.** Put the old key material into a JSON file `{"<old id>": "<old material>"}`,
point `INTEGRATION_KEK_PREVIOUS_PATH` at it, set the new `INTEGRATION_KEK` and a new
`INTEGRATION_KEK_ID`, restart, then run `python -m app.cli rewrap-integration-secrets` (re-wraps the
data keys; the ciphertext of the secrets is unchanged). Remove the previous key once every row
reports the new key id.

## Outbound network policy (SSRF)

`app/integrations/outbound.py` is the **only** module that opens connections to integration
endpoints (HTTP via `http.client`, SMTP via `smtplib`); a unit test scans the imports to keep it
so. Every request:

* `https` only (`http://` and SMTP without TLS only with `OUTBOUND_ALLOW_HTTP=true`, refused in
  prod); no credentials, spaces, control characters or backslashes in the URL; ports 1-65535;
  `GET`/`POST` only; header names and values validated;
* the host is resolved **once**; every resolved address must be public. Refused unless allowed:
  loopback, RFC 1918 and ULA private, link-local including the cloud metadata addresses
  `169.254.169.254` and `fd00:ec2::254`, CGNAT `100.64.0.0/10`, multicast, unspecified, reserved,
  and IPv6 forms that embed an IPv4 address (IPv4-mapped, compatible, NAT64, 6to4, Teredo);
* `OUTBOUND_ALLOW_HOSTS` takes host names and CIDRs. A host-name entry unlocks that host's
  private, loopback and CGNAT addresses; link-local/metadata, multicast and unspecified addresses
  are allowed only by a CIDR entry that contains them;
* the connection goes to the validated address (TLS SNI and the certificate check still use the
  host name), so a second DNS answer cannot redirect it (DNS rebinding); redirects are never
  followed (a 3xx is a failed delivery);
* connect and read timeouts, a total deadline that bounds every socket wait, a streamed response
  cap (`OUTBOUND_MAX_RESPONSE_KB`) and a request cap (`OUTBOUND_MAX_REQUEST_KB`).

IP literals are judged when an integration is saved (422 with the reason); host names are judged
at send time against the address actually connected to.

## Signed webhooks (guide 15.6)

Outbound webhooks carry:

```
X-Timestamp: <Unix seconds>
X-Signature: sha256=<hex HMAC-SHA256(signing_secret, timestamp + "." + raw body)>
X-Event: alert.created
X-Delivery-Id: <delivery id, the same on every retry>
```

The body is canonical JSON `{"id", "type", "created_at", "data"}`; `data` has `details` only for
channels with `include_details`. A receiver should recompute the HMAC over the raw bytes, compare
in constant time, reject timestamps older than a few minutes and deduplicate on `X-Delivery-Id`:

```python
import hashlib, hmac, time
def verify(secret: bytes, ts: str, body: bytes, signature: str) -> bool:
    expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature) and abs(time.time() - int(ts)) <= 300
```

## SIEM/EDR webhook ingest

`POST /api/v1/ingest/webhook/{integration_id}` accepts alerts from a `webhook_in` source, signed
with the same scheme. Order of checks:

1. The body cap (`INGEST_MAX_BODY_KB`) is enforced from `Content-Length` and again while
   streaming, before anything is buffered or authenticated (413).
2. A per-client-address rate limit, then authentication: HMAC over timestamp + raw body,
   constant-time compare, timestamp within `INGEST_TIMESTAMP_WINDOW_S`. An unknown or disabled
   source, a bad signature and a stale timestamp all get the same 401, and the HMAC is computed in
   every case so the timing does not tell them apart. Then a per-source limit
   (`INGEST_RATE_LIMIT_PER_MINUTE`; Redis, fail closed: 503).
3. Replay protection: the signed digest is the delivery's nonce, UNIQUE per integration in the
   append-only `inbound_deliveries`. A replay is answered with the stored counts and
   `duplicate: true`, and changes nothing.
4. **The case comes from the saved integration, never from the payload.** A closed case answers
   409.
5. Items (a JSON object with `alerts`/`items`/`events`/`results`, a list, or one object; at most
   `INGEST_MAX_ITEMS`) are mapped through the integration's `field_map` (dotted paths) or the
   default paths, with length caps and the parser pipeline's cleaning helpers. A malformed item
   is one counted error (`error_reasons`), never a 500. Good items are upserted into `alerts`
   (`rule_id` NULL, `dedup_key = ext:<integration>:<sha256(external id)>`), so a re-sent alert
   updates its row; new alerts get an `alert_history` row and an `alert.created` event.

Timestamps must carry a time zone (or be epoch numbers); the original string is kept in
`details.ts_original`.

## Enrichment

`POST /cases/{id}/iocs/enrich` (`investigate`), `GET /cases/{id}/enrichments` (case read) and
`POST /cases/{id}/iocs/{ioc}/sighting` (MISP only). Off unless `ENABLE_ENRICHMENT=true` **and**
the provider's integration is enabled. Only indicator values of type `ip`, `domain`, `url`,
`sha256`, `sha1`, `md5` are sent, never files or evidence content. TLP: VirusTotal receives
`clear/white/green` only; MISP up to its integration's `max_tlp` (default `green`, never `red`);
an IOC without a TLP counts as `amber`. Verdicts are cached in `ioc_enrichments` for
`ENRICHMENT_CACHE_TTL_H`; at most `ENRICHMENT_MAX_PER_REQUEST` indicators per call; no lock or
transaction is held while a provider is called, and the case is re-checked afterwards.
`ENRICHMENT_FAKE=true` (refused in prod) replaces every provider with a deterministic offline
fake; tests and smokes use only the fake.

## Database (migration 0012)

New tables: `playbook_run_steps`, `action_requests`, `outbound_events`, `outbound_deliveries`,
`inbound_deliveries` (append-only), `ioc_enrichments`. Changed: `playbooks`, `playbook_runs`,
`integrations`, `notifications`. Least privilege for `dfirbench_app`: no DELETE or TRUNCATE on
any of them; UPDATE only on workflow columns (runs: `status, finished_at`; steps: status and
outcome columns; requests: status, decision and outcome columns; deliveries: delivery state;
events: `fanned_out_at`; notifications: `read_at`); none on `inbound_deliveries`. Guard triggers
keep run, step, request and delivery identity immutable and freeze finished rows.
`scripts/verify-phase9.sh` checks the denials live.

The downgrade archives every step into `playbook_runs.step_states`, cancels running runs, drops
the new tables, clears integration secrets (the wrapped data key goes away, so a secret cannot
survive) and disables those integrations; the upgrade applies the same rules to any rows it finds,
so a down/up round trip with data in every state leaves consistent rows
(`test_response_migration_roundtrip_with_rows_in_every_state`).

## Configuration

All settings are in `.env.example` ("Response + integrations"). The compose stack passes them
through with dev defaults (a placeholder KEK that `APP_ENV=prod` refuses). `verify-phase9.sh` runs
the stack with `ENABLE_ENRICHMENT=true ENRICHMENT_FAKE=true OUTBOUND_ALLOW_HTTP=true
OUTBOUND_ALLOW_HOSTS=api`, so the live smoke's webhook receiver inside the `api` container is the
only reachable destination.

## Deliberate deviations from the guide

* Credentials are not environment variables (`VT_API_KEY`, `MISP_*`, `SLACK_WEBHOOK_URL`,
  `SMTP_*` from guide 21 are gone): they are entered through the API and stored encrypted; only
  the KEK is configuration.
* PyMISP and third-party HTTP clients are not used: the MISP and VirusTotal providers call the
  REST APIs through the single outbound module, so one SSRF policy covers everything.
* Step state lives in `playbook_run_steps` rows rather than only in `playbook_runs.step_states`
  (guide 7.3), because the database must enforce approvals per step.
* No Celery beat: delivery retries schedule themselves and approval expiry is applied on access.
