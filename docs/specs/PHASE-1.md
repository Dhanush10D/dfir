# PHASE 1: Evidence core + IAM

## Goal
Make dfirbench a usable, defensible evidence store: people sign in (Argon2id passwords, short-lived JWT
access tokens, rotated server-side refresh tokens, TOTP MFA with recovery codes, lockout), every
request is authorized by a 5-role RBAC matrix capped by case membership, analysts create cases and
evidence records, originals stream into the WORM vault while SHA-256 and MD5 are computed, and every
evidence action is recorded in an Ed25519-signed, per-evidence hash chain that a verify endpoint
re-checks together with the stored bytes. All requests and sensitive actions land in the append-only
audit log. Tamper tests prove that edits to the custody log, the vault object, or the evidence
metadata are detected and reported precisely.

## In scope
- IAM (guide 16): Argon2id hashing (argon2-cffi, tunable, rehash on login), password policy (min 12,
  local common-password list, not containing the e-mail), JWT access tokens (HS256 with `kid`, or
  EdDSA when `JWT_PRIVATE_KEY_PATH` is set), opaque refresh tokens stored as SHA-256 hashes with
  rotation, reuse detection (whole family revoked), absolute session lifetime, logout / logout-all,
  sessions list, TOTP enroll/confirm/disable (secret AES-GCM encrypted with a key derived from
  `TOTP_ENC_KEY`, replay-protected by last used time step), 10 single-use hashed recovery codes,
  exponential lockout, API keys (random 32 bytes, hash stored, shown once, `read`/`write` scopes,
  expiry, revocation), admin user management with re-authentication (`admin_password`) for role
  changes, deactivation and MFA reset, `python -m app.cli create-admin` bootstrap.
- RBAC (16.1, 16.3): permission table in code covering every role x permission cell; effective
  permission = global role ∩ case role; admins see all cases, auditors read all cases
  (`AUDITOR_ALL_CASES`); route-level `require_permission` plus service-level `authorize()`; object-level
  checks on every `/{id}` route (non-readable case -> 404, readable but forbidden -> 403).
- Cases: create (auto `IR-YYYY-NNNN`), list (only accessible cases), read, update with validated
  status transitions, members add/remove/list, close.
- Evidence (8.1, 8.2): create record (auto `EV-NNN`), raw streaming upload (`PUT`, body streamed to
  MinIO multipart with bounded memory, SHA-256 + MD5 + size computed on the fly, `MAX_UPLOAD_GB`
  enforced mid-stream, concurrent uploads refused), finalize (re-reads stored bytes server side,
  compares with the streaming hash and any `expected_sha256`/`expected_md5`, records Object Lock
  retention), verify, audited download, list/detail.
- Custody (8.3): `services/custody.py` is the only writer; entries appended in the same transaction
  as the action, under `SELECT ... FOR UPDATE` on the evidence row; `entry_hash =
  SHA-256(canonical_json(body))`, Ed25519 signature over the hex hash; public keys published in
  `signing_keys`; pure `verify_chain()` reports each problem with its exact `seq` and a code.
- Custody signing key: settings `CUSTODY_SIGNING_KEY_PATH` (+ optional
  `CUSTODY_SIGNING_KEY_PASSPHRASE`), `CUSTODY_KEY_ID` (defaults to a fingerprint-derived id);
  `python -m app.core.signing generate` writes a PKCS#8 PEM (0600, optional passphrase).
- Custody trust anchor: verification trusts only the running signer's public key plus the keys in
  `CUSTODY_TRUSTED_KEYS_PATH` (JSON `{key_id: public PEM}`, maintained with
  `python -m app.core.signing trust`). `signing_keys` is a published copy for display/export; an
  entry signed under any other key id, or whose published key differs from the trusted key for its
  id, is `untrusted_key`. Compose gets
  a one-shot `keygen` service that creates the dev key in a named volume; nothing secret is
  committed.
- Audit (16.5): pure-ASGI `AuditMiddleware` writes one `audit_log` row per `/api/v1` request (except
  health/ready/docs) with user, IP, method, path, status, request id; `services/audit.py` records
  semantic actions (`auth.login`, `auth.login_failed`, `user.role_changed`, `evidence.download`,
  `evidence.verify`, ...); `GET /audit` for admins and auditors.
- Least-privilege DB role (BACKLOG item): migration 0002 creates `dfirbench_app` (NOLOGIN) with DML on
  all tables except `custody_log`/`audit_log` (SELECT, INSERT only) and default privileges for future
  tables; the API/worker run every session as that role via `DATABASE_APP_ROLE`.
- Integrity notifications: an integrity failure creates a `notifications` row for every active admin.

## Out of scope (later phases)
Evidence export packages (Phase 8), processing jobs (Phase 2), custody anchors / Merkle roots and
RFC 3161 time stamps (BACKLOG), periodic re-verification job (Phase 2 scheduler), browser cookie
delivery + CSRF (Phase 4 UI), per-IP auth rate limiting (Phase 10), OIDC/SSO and WebAuthn (P2),
breached-password k-anonymity API (needs egress; local list only), `/cases/{id}/summary` (needs
events/alerts, Phase 4).

## Files and interfaces
- `app/core/exceptions.py` (no FastAPI): `AppError`, `NotFoundError`, `ConflictError`,
  `UnauthenticatedError`, `ForbiddenError`; re-exported by `app/core/errors.py`.
- `app/core/security.py`: `make_password_hasher(settings)`, `hash_password`, `verify_password ->
  (ok, needs_rehash)`, `check_password_policy(password, email) -> list[str]`, `new_token(nbytes)`,
  `sha256_hex`, `JwtCodec(settings)` with `issue_access(...)`, `issue_mfa_challenge(...)`,
  `decode(token, expected_type)`, `SecretBox(key_material)` (AES-GCM), `totp_*` helpers.
- `app/core/signing.py`: `CustodySigner(key_id, private_key)` (`sign`, `public_key_pem`),
  `load_signer(settings)`, `generate_key_file(path, passphrase)`, `key_fingerprint_id(pub)`,
  CLI `python -m app.core.signing generate --out PATH [--if-missing] [--passphrase-env VAR]`.
- `app/core/permissions.py`: `Permission` (StrEnum), `ROLE_PERMISSIONS`, `permissions_for(role)`,
  `effective_permissions(global_role, case_role)`, `Principal` dataclass.
- `app/core/audit_middleware.py`: `AuditMiddleware(app, sink_getter)`; `AuditRecord`.
- `app/repositories/vault.py`: `VaultStore` protocol + `MinioVault` (put_stream, iter_object,
  stat, retention, latest_version); `HashingReader`.
- `app/services/custody.py`: `canonical`, `GENESIS`, `entry_body`, `compute_entry_hash`,
  `verify_chain(entries, public_keys) -> ChainReport`, `CustodyService.append/list/verify/ensure_key`.
- `app/services/iam.py`: `IAMService` (login, verify_mfa, refresh, logout, logout_all, sessions,
  principal_from_access_token, principal_from_api_key, users CRUD, password change, MFA, API keys).
- `app/services/authz.py`: `authorize(principal, permission, case_role)`, `CaseAccess`.
- `app/services/cases.py`: `CaseService`; `app/services/evidence.py`: `EvidenceService`;
  `app/services/audit.py`: `AuditService` + `DbAuditSink`; `app/services/notifications.py`.
- `app/api/security.py`: `current_principal`, `require_permission(p)`; routers `auth.py`, `users.py`
  (`/me`, `/users`), `cases.py`, `evidence.py`, `audit.py`.
- `app/schemas/{auth,users,cases,evidence,audit}.py`; `app/cli.py` (`create-admin`).
- `infra/compose.yaml`: `keygen` one-shot, `custodykeys` volume, `DATABASE_APP_ROLE`, key env.
- `scripts/verify-phase1.sh`, `scripts/dev-keygen.sh`.

## Data model changes (`0002_iam_evidence.py`, `0003_trust_hardening.py`)
- `users.totp_last_step bigint` (TOTP replay protection).
- `refresh_tokens(id, user_id FK cascade, family_id, token_hash char(64) unique, issued_at,
  expires_at, session_started_at, revoked_at, revoked_reason, replaced_by, user_agent, ip inet)`.
- `mfa_recovery_codes(id, user_id FK cascade, code_hash char(64), used_at, created_at)`.
- `api_keys.key_prefix text`, `api_keys.last_used_at`, unique index on `api_keys.key_hash`.
- `evidence.expected_sha256 char(64)`, `expected_md5 char(32)`, `storage_version_id text`,
  `retain_until timestamptz`.
- Indexes: `audit_log(ts)`, `audit_log(user_id, ts)`, `case_members(user_id)`,
  `refresh_tokens(user_id)`, `refresh_tokens(family_id)`, `mfa_recovery_codes(user_id)`.
- Role `dfirbench_app` (NOLOGIN, created if missing): USAGE on schema; SELECT/INSERT/UPDATE/DELETE on
  tables; USAGE/SELECT on sequences; `custody_log`/`audit_log` restricted to SELECT, INSERT;
  `alembic_version` SELECT only; default privileges for tables/sequences the owner creates later.
  Downgrade revokes; the cluster-wide role is not dropped.
- 0003: `dfirbench_app` gets only SELECT/INSERT on `signing_keys`; `users.email` values are
  lower-cased and kept so by `CHECK (email::text = lower(email::text))` (citext UNIQUE stays);
  `GRANT dfirbench_app TO CURRENT_USER` so a non-superuser owner can `SET ROLE`.
- Evidence status values: `uploading` (record created, awaiting bytes) -> `uploaded` (bytes stored,
  `ingested` custody entry) -> `stored` (finalized: re-hashed, compared, locked) | `failed`
  (hash mismatch). Later phases add `processing`/`processed`/`partial`/`archived`.

## Custody entry format
`body = {evidence_id, seq, ts (UTC ISO 8601, microseconds, "Z"), actor_id|null, actor_label, action,
detail, prev_hash}`; `entry_hash = sha256(json.dumps(body, sort_keys, (",",":"),
ensure_ascii=False))`; `signature = Ed25519(entry_hash ascii).hex()`. `ts` is written by the service
(not `now()`) so it round-trips through `timestamptz`; `detail` accepts only JSON types that
round-trip through `jsonb` (no floats, no NUL). Actions: `created`, `ingested`, `hash_verified`,
`hash_failed`, `verification_failed`, `locked`, `downloaded`, `note`. A finalize mismatch (stored
bytes vs. streaming/expected hash or declared size) writes `verification_failed` (guide 8.1 step 3);
verify writes `hash_failed` when the stored object no longer matches and `verification_failed` when
only the chain is broken. Problem codes from `verify_chain`: `seq_gap`, `duplicate_seq`,
`broken_link`, `hash_mismatch`, `bad_signature`, `untrusted_key`, `evidence_mismatch`,
`empty_chain`. Tail truncation is not detectable without anchors (BACKLOG).

## API changes (all under `/api/v1`)
| Method | Path | Access |
|---|---|---|
| POST | `/auth/login` -> tokens or `{mfa_required, mfa_challenge}` | public |
| POST | `/auth/mfa/verify` (`code` or `recovery_code`) | challenge |
| POST | `/auth/refresh`, `/auth/logout` | refresh token |
| POST | `/auth/logout-all` | any |
| GET | `/me`, `/me/sessions` ; POST `/me/password` | any |
| POST | `/me/mfa/enroll`, `/me/mfa/confirm`, `/me/mfa/disable` | any |
| GET/POST/DELETE | `/me/api-keys[/{id}]` | any |
| GET/POST | `/users` ; PATCH/DELETE `/users/{id}` | admin |
| GET/POST | `/cases` | read: any (filtered) / create: A,L,N |
| GET/PATCH | `/cases/{id}` | case read / case update (A,L,N; reopen needs L) |
| GET/POST/DELETE | `/cases/{id}/members[/{user_id}]` | read / A,L |
| POST | `/cases/{id}/close` | A,L |
| POST/GET | `/cases/{id}/evidence` | A,L,N / case read |
| GET | `/evidence/{eid}` | case read |
| PUT | `/evidence/{eid}/upload` (raw `application/octet-stream` body) | A,L,N |
| POST | `/evidence/{eid}/finalize` | A,L,N |
| POST | `/evidence/{eid}/verify` | A,L,N,U |
| GET | `/evidence/{eid}/custody` | A,L,N,U |
| GET | `/evidence/{eid}/download` | A,L,U |
| GET | `/signing-keys` | any |
| GET | `/audit` | A,U |

Auth: `Authorization: Bearer <access>` or `X-API-Key`. Errors use the 15.3 envelope; codes include
`invalid_credentials`, `account_locked` (429 + `Retry-After`), `mfa_invalid`, `token_invalid`,
`refresh_reused`, `forbidden`, `weak_password`, `upload_in_progress`, `upload_too_large`,
`invalid_state`, `reauth_required`.

## Test plan
- Unit (no Docker): password hashing/policy; JWT (roundtrip, expiry, wrong type, `alg=none`,
  tampered, EdDSA); SecretBox; TOTP step matching; signer key file (plain, passphrase, CLI
  `--if-missing`); permission matrix (every role x permission cell) and capping; custody chain (valid,
  edited detail/ts/actor, reordered, deleted, forged with other key, unknown key, wrong signature,
  garbage signature) with exact `seq`; hypothesis property "any single mutation is detected";
  HashingReader limits; audit middleware with a fake sink; custody writer boundary (static check);
  config additions.
- Integration (compose Postgres; skip when unreachable), with a fake in-memory vault unless noted:
  migration head, new tables, app-role privileges (UPDATE/DELETE/TRUNCATE on custody/audit denied as
  `dfirbench_app`); auth flows (login, wrong password, lockout + expiry, inactive user, MFA
  enroll/confirm/login, TOTP replay, recovery code single use, refresh rotation + reuse detection,
  logout/logout-all, password change, API keys + read-only scope); RBAC matrix over the API for all 5
  roles, non-member 404, case-role capping; evidence create/upload/finalize/verify/download; expected
  hash mismatch; tampered vault object; tampered `evidence.sha256`; custody row edited, reordered,
  deleted, forged via the owner with `session_replication_role = replica` -> verify reports the exact
  `seq`; oversize and concurrent uploads; audit rows for requests and semantic actions.
- Integration with real MinIO (skip when unreachable; own Object-Lock test bucket in GOVERNANCE mode,
  cleaned up with bypass): multipart streaming upload whose hash equals an independent `hashlib`
  digest; retention recorded; overwrite detected by verify; deleting the locked original fails.

## Acceptance criteria (executable)
1. `docker compose -f infra/compose.yaml up -d --build` -> all services healthy; `keygen`, `migrate`,
   `storage-init` exit 0.
2. `alembic upgrade head` reaches `0003`; `alembic check` reports no drift.
3. Live smoke through the running API (`scripts/phase1-smoke.py`): create admin, login, create
   analyst/viewer/auditor, case, evidence, stream-upload a file, finalize, verify ok with the
   stored SHA-256 equal to an independent `hashlib.sha256`; viewer denied (403) on upload; auditor
   downloads the file byte-identical; audit rows present.
4. Live tamper demo: edit one custody row in Postgres as the owner with triggers bypassed ->
   `POST /evidence/{id}/verify` returns `ok=false` with the exact broken `seq`.
5. `pytest -q` passes (integration + MinIO tests run with the stack up) with coverage >= 80%;
   `ruff check`, `ruff format --check`, `mypy app`, `bandit` pass.

## Verification command
```bash
bash scripts/verify-phase1.sh
```
(brings the stack up, waits for health, runs migrations + drift check, the live smoke and tamper
demo, then backend lint/format/types/bandit and the full test suite; leaves the stack running).

## Implementation notes
- **Deliberate RBAC choices** (guide 16.1 and 15.2 disagree): the global `/audit` log is admin + auditor
  (15.2); custody view includes analysts, who add and verify evidence (16.1 lists A, L, U). Every
  cell is pinned by `tests/unit/test_permissions.py` and exercised over HTTP for all five roles in
  `tests/integration/test_rbac_cases_api.py`.
- **Least-privilege role**: applied with the libpq startup option `-c role=dfirbench_app` on the
  owner login (see `app/db/session.py`). This enforces the grants on every app statement, but the
  owner could `RESET ROLE`; a separate LOGIN role is in BACKLOG (Phase 10). Integration tests run the
  API under this role, and prove UPDATE/DELETE/TRUNCATE on custody/audit and
  `SET session_replication_role` are denied to it.
- **Concurrent uploads**: refused with a session-level `pg_try_advisory_lock` held on a dedicated
  connection for the duration of the stream (no transaction stays open while bytes flow; a crashed
  process releases the lock with its connection).
- **Verify** hashes the recorded object *version*, checks that the latest version at the key is still
  that version (`object_replaced` otherwise), and cross-checks `evidence.sha256/size_bytes` against
  the signed `ingested` custody entry (`metadata_mismatch`), so edits to the evidence row are caught.
  Object problems set the evidence to `failed`; chain problems add a `verification_failed` entry;
  both notify every active admin and write `evidence.integrity_failure` to the audit log.
- **Finalize** refuses (503 `vault_not_worm`) if the stored version has no Object Lock retention.
- **Tokens** are returned in JSON (Bearer); cookie delivery + CSRF waits for the UI (Phase 4).
- **Account lockout** answers 429 `account_locked` with `Retry-After`; unknown users and wrong
  passwords give the same 401 and burn one Argon2 computation. Login, MFA verify/confirm/disable,
  password change and admin re-authentication lock the user row (`SELECT ... FOR UPDATE`), so the
  failure counter and the TOTP replay guard cannot race; failed re-authentication (wrong current
  password, wrong admin password, wrong TOTP when disabling MFA) counts towards the same lockout.
- **Uploads** re-check the evidence status after taking the advisory lock, so a finished upload
  that raced the first check cannot be followed by a second object version.
- **Closed cases** accept only a reopen (`status: open`, needs case:manage); any other PATCH is 409.
- **Upload limits**: settings validation rejects `MAX_UPLOAD_GB` / `UPLOAD_PART_SIZE_MB`
  combinations that exceed S3's 10,000-part limit.
- **E-mails** are normalized to lower case on write and compared lower-cased on lookup.
- A tampered published copy of the running signer's key does not block custody writes (the trust
  anchor is outside the DB); it is logged and reported as `untrusted_key` by every verification.
- `app/core/exceptions.py` holds the framework-free domain errors (re-exported by `core/errors.py`).
- The compose `keygen` one-shot creates `custody-dev.pem` in the `custodykeys` volume (mounted
  read-only into api and worker); host-side dev keys go to the git-ignored `var/keys/` via
  `scripts/dev-keygen.sh`.
- CI starts MinIO with `docker run` (service containers cannot pass `server /data`) and the
  compose-smoke job runs `scripts/phase1-smoke.py`.
