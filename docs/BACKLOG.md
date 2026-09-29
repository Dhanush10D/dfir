# Backlog (deferred items)

Items consciously deferred from a phase, with the phase expected to pick them up.

## From Phase 0

| Item | Why deferred | Target |
|---|---|---|
| ~~Separate least-privilege DB role for the app~~ **Partly done in Phase 1**: migration 0002 creates `dfirbench_app` (no UPDATE/DELETE/TRUNCATE on `custody_log`/`audit_log`) and the API/worker run every session as it (`DATABASE_APP_ROLE`, `SET ROLE` at connect). Remaining: a separate LOGIN role with its own password so a compromised app cannot `RESET ROLE` back to the owner; migrations keep the owner login | Needs secret provisioning for a second DB password in compose/CI | Phase 10 |
| ~~`AuditMiddleware` writing `audit_log` rows per request~~ | Done in Phase 1 | - |
| ~~Events partition maintenance~~ **Done in Phase 2** (ingest ensures partitions, the function moves stray `events_default` rows). Remaining: retention by dropping partitions | Needs a scheduler and a retention policy | Phase 10 |
| Reverse proxy with TLS (Caddy) in compose | Dev stack binds to 127.0.0.1 only | Phase 10 |
| `/metrics` (Prometheus), OpenTelemetry traces | Observability hardening | Phase 10 |
| pip-audit, Trivy image scan, gitleaks, SBOM (Syft), cosign signing in CI | Security pipeline | Phase 10 |
| Forensic binaries in the worker image (Plaso, TSK, Volatility 3, Hayabusa, Zeek, tshark, YARA, libewf) with pinned versions in `/opt/dfir/tool-versions.txt` | Phase scope | Phase 6 |
| Per-job sandbox containers (`--network none`, read-only evidence mount) | Phase scope | Phase 10 |
| Generated TypeScript API client (`openapi-typescript`), router, shadcn/ui | UI work | Phase 4 |
| Split worker images (`worker-parse`, `worker-ai`) per guide 21.2 | Only one worker needed now | Phase 6/7 |
| Evaluate replacing the `pgsty/minio` community image if upstream images return, or pin by digest | Upstream `minio/minio` images are no longer published on Docker Hub/quay | Phase 10 |
| `EMBEDDING_DIM` != 384 requires a migration of `event_chunks.embedding` | Model not chosen yet | Phase 7 |
| ~~`dfir_ensure_events_partition` fails if `events_default` already holds rows for that month~~ | Done in Phase 2 (migration 0004) | - |

## From Phase 1

| Item | Why deferred | Target |
|---|---|---|
| ~~`dfir_ensure_events_partition()` as `SECURITY DEFINER`~~ | Done in Phase 2 (0004; the app role has no privileges on partitions) | - |
| Custody anchors: periodic signed Merkle root over recent `entry_hash` values into `anchors`, optional RFC 3161 time stamp. Without anchors, deleting the *newest* custody entries of an item (tail truncation) is not detectable by the chain alone | Needs a scheduler (Celery beat); not added in Phase 2 | Phase 3 (scheduler) / Phase 8 |
| Scheduled re-verification of all originals (`nightly_verify_all`, guide 8.1 step 6). Phase 2 re-hashes every original before parsing it | Needs Celery beat | Phase 3 |
| Evidence export package (`manifest.json`, `custody.json`, `manifest.sig`, guide 8.4) | Reporting/export phase | Phase 8 |
| Browser token delivery via `HttpOnly; Secure; SameSite=Strict` cookies + CSRF token; Phase 1 returns tokens in JSON (Bearer) | Needs the UI | Phase 4 |
| Per-IP rate limiting on `/auth/*` (guide 14.3) and alerting on suspicious login patterns | Account lockout covers brute force per account for now | Phase 10 |
| Breached-password check through a k-anonymity API (HIBP-style); Phase 1 uses a bundled offline list | Needs egress; tests must stay offline | Phase 10 (optional) |
| OIDC/SSO (Keycloak/Authlib) and WebAuthn | P2 in the guide | Later |
| Accept several JWT `kid`s at once for zero-downtime JWT key rotation; `TOTP_ENC_KEY` rotation (re-wrap) | Single key per purpose is enough for dev | Phase 10 |
| Resumable/chunked uploads (tus or presigned S3 multipart) for very large images; Phase 1 streams one `PUT` (multipart to MinIO, bounded memory) | Works for the Standard profile; resumability is a UX improvement | Phase 5/10 |
| Reaper for evidence stuck in `uploaded` (never finalized) and for orphaned object versions left by a failed DB commit after a successful vault write | Rare; detectable (finalize/verify compare versions); needs Celery beat | Phase 3 |
| `/cases/{id}/summary` | Needs events/alerts | Phase 4 |
| ~~Workers writing custody entries (`processed`)~~ | Done in Phase 2 (worker signs `processed` / `hash_failed`) | - |
| `audit_log` growth: partition by month or archive (never purge) | Volume is small in dev | Phase 10 |
| Custody signing keys in Vault/KMS or an HSM, with the trusted-keys file (`CUSTODY_TRUSTED_KEYS_PATH`) distributed from the secret manager; today both are files (dev key in the `custodykeys` volume) | Needs a secret manager | Phase 10 |
| Two admins changing each other concurrently can deadlock in `update_user` (target read unlocked, acting admin locked in `_reauth`); Postgres aborts one as a 500. Lock both rows in id order, or map the deadlock to 409 | Rare; no data harm | Phase 10 |
| Notify admins when the published `signing_keys` row differs from the trusted key (today it is logged and reported only when someone runs verify) | Needs the scheduler / periodic re-verify | Phase 3 |
| Test migration 0003's `GRANT dfirbench_app TO CURRENT_USER` with a non-superuser (CREATEROLE) owner on PG16 | Compose and CI owners are superusers | Phase 10 |

## From Phase 2

| Item | Why deferred | Target |
|---|---|---|
| Job reaper (Celery beat): re-dispatch `queued` jobs whose broker message was lost (e.g. `self.retry()` could not reach Redis) and `running` jobs whose lease expired with no redelivery pending. Today they are recoverable with `POST /jobs/{id}/retry` after a cancel | Needs the scheduler | Phase 3 |
| Progress over Redis pub/sub + WebSocket/SSE (guide 10.6); Phase 2 persists `progress`/`heartbeat_at` on the job row (poll `GET /jobs/{id}`) | UI arrives in Phase 4 | Phase 4 |
| `POST /cases/{id}/events/search` with the search language, histogram, facets, context, export (guide 15.2) | Explorer UI work; Phase 2 ships `GET /cases/{id}/events` with filters + keyset cursor | Phase 4 |
| Evidence status `processing` / `processed` / `partial` (guide 4.4) derived from its jobs | Job state carries progress today; needs a rule for multiple parsers per item | Phase 4 |
| Reprocess swaps events in separate short transactions (delete, then batches), so a reader can briefly see a partial timeline for that evidence. Option: build into a staging `job_id` and swap visibility at finish | Final state is always correct (deterministic ids); cost/benefit | Phase 10 |
| Backpressure: pause parsing when inserts lag (guide 10.6); batches are synchronous today, which bounds memory but not DB load across many workers | Single worker in dev | Phase 10 |
| More `linux_auth` inputs: `journalctl -o json` exports, wtmp/btmp/lastlog, bash/zsh history (guide 10.3 catalogue) | Scope | Phase 5/6 |
| Hayabusa/Sigma enrichment of EVTX events; richer EVTX mappings (e.g. 4611/4673 get only a generic message) | Detection phase | Phase 3 |
| Per-job sandbox containers for parsers (`--network none`, read-only evidence mount, CPU/memory/pids limits); today the parser runs in the worker process on a 0400 scratch copy | Phase scope (already listed above) | Phase 10 |
| `container_image_digest` in run manifests: set `DFIR_IMAGE_DIGEST` in the worker image at build/deploy time | Needs the release pipeline (cosign) | Phase 10 |
| The app role has DELETE on `events` (reprocess). Option: route deletes through a `SECURITY DEFINER` function keyed by job so ad-hoc deletes are impossible | Defense in depth | Phase 10 |
