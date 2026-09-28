# Backlog (deferred items)

Items consciously deferred from a phase, with the phase expected to pick them up.

## From Phase 0

| Item | Why deferred | Target |
|---|---|---|
| ~~Separate least-privilege DB role for the app~~ **Partly done in Phase 1**: migration 0002 creates `dfirbench_app` (no UPDATE/DELETE/TRUNCATE on `custody_log`/`audit_log`) and the API/worker run every session as it (`DATABASE_APP_ROLE`, `SET ROLE` at connect). Remaining: a separate LOGIN role with its own password so a compromised app cannot `RESET ROLE` back to the owner; migrations keep the owner login | Needs secret provisioning for a second DB password in compose/CI | Phase 10 |
| ~~`AuditMiddleware` writing `audit_log` rows per request~~ | Done in Phase 1 | - |
| Events partition maintenance: call `dfir_ensure_events_partition()` before bulk insert; job to move stray rows out of `events_default`; retention by dropping partitions | No ingest yet | Phase 2 |
| Reverse proxy with TLS (Caddy) in compose | Dev stack binds to 127.0.0.1 only | Phase 10 |
| `/metrics` (Prometheus), OpenTelemetry traces | Observability hardening | Phase 10 |
| pip-audit, Trivy image scan, gitleaks, SBOM (Syft), cosign signing in CI | Security pipeline | Phase 10 |
| Forensic binaries in the worker image (Plaso, TSK, Volatility 3, Hayabusa, Zeek, tshark, YARA, libewf) with pinned versions in `/opt/dfir/tool-versions.txt` | Phase scope | Phase 6 |
| Per-job sandbox containers (`--network none`, read-only evidence mount) | Phase scope | Phase 10 |
| Generated TypeScript API client (`openapi-typescript`), router, shadcn/ui | UI work | Phase 4 |
| Split worker images (`worker-parse`, `worker-ai`) per guide 21.2 | Only one worker needed now | Phase 6/7 |
| Evaluate replacing the `pgsty/minio` community image if upstream images return, or pin by digest | Upstream `minio/minio` images are no longer published on Docker Hub/quay | Phase 10 |
| `EMBEDDING_DIM` != 384 requires a migration of `event_chunks.embedding` | Model not chosen yet | Phase 7 |
| `dfir_ensure_events_partition` fails if `events_default` already holds rows for that month; ingest must move them first | Covered by partition maintenance work | Phase 2 |

## From Phase 1

| Item | Why deferred | Target |
|---|---|---|
| `dfir_ensure_events_partition()` runs `CREATE TABLE`; the `dfirbench_app` role has no CREATE on the schema. Make the function `SECURITY DEFINER` (owned by the migration owner, fixed `search_path`) or pre-create partitions in a migration/job. Default privileges already grant DML on new partitions | Ingest arrives in Phase 2 | Phase 2 |
| Custody anchors: periodic signed Merkle root over recent `entry_hash` values into `anchors`, optional RFC 3161 time stamp. Without anchors, deleting the *newest* custody entries of an item (tail truncation) is not detectable by the chain alone | Needs a scheduler (Celery beat) | Phase 2 (scheduler) / Phase 8 |
| Scheduled re-verification of all originals (`nightly_verify_all`, guide 8.1 step 6) | Needs job orchestration | Phase 2 |
| Evidence export package (`manifest.json`, `custody.json`, `manifest.sig`, guide 8.4) | Reporting/export phase | Phase 8 |
| Browser token delivery via `HttpOnly; Secure; SameSite=Strict` cookies + CSRF token; Phase 1 returns tokens in JSON (Bearer) | Needs the UI | Phase 4 |
| Per-IP rate limiting on `/auth/*` (guide 14.3) and alerting on suspicious login patterns | Account lockout covers brute force per account for now | Phase 10 |
| Breached-password check through a k-anonymity API (HIBP-style); Phase 1 uses a bundled offline list | Needs egress; tests must stay offline | Phase 10 (optional) |
| OIDC/SSO (Keycloak/Authlib) and WebAuthn | P2 in the guide | Later |
| Accept several JWT `kid`s at once for zero-downtime JWT key rotation; `TOTP_ENC_KEY` rotation (re-wrap) | Single key per purpose is enough for dev | Phase 10 |
| Resumable/chunked uploads (tus or presigned S3 multipart) for very large images; Phase 1 streams one `PUT` (multipart to MinIO, bounded memory) | Works for the Standard profile; resumability is a UX improvement | Phase 5/10 |
| Reaper for evidence stuck in `uploaded` (never finalized) and for orphaned object versions left by a failed DB commit after a successful vault write | Rare; detectable (finalize/verify compare versions) | Phase 2 |
| `/cases/{id}/summary` | Needs events/alerts | Phase 4 |
| Workers writing custody entries (`processed`) need the signer: the key volume is already mounted read-only into the worker | No processing yet | Phase 2 |
| `audit_log` growth: partition by month or archive (never purge) | Volume is small in dev | Phase 10 |
