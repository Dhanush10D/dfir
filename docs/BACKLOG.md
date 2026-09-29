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
| ~~Router~~ (done in Phase 4: own History-API router). Remaining: generated TypeScript API client (`openapi-typescript`) and shadcn/ui; Phase 4 hand-writes `frontend/src/api/types.ts` | No new npm dependencies in Phase 4 | Phase 10 |
| Split worker images (`worker-parse`, `worker-ai`) per guide 21.2 | Only one worker needed now | Phase 6/7 |
| Evaluate replacing the `pgsty/minio` community image if upstream images return, or pin by digest | Upstream `minio/minio` images are no longer published on Docker Hub/quay | Phase 10 |
| `EMBEDDING_DIM` != 384 requires a migration of `event_chunks.embedding` | Model not chosen yet | Phase 7 |
| ~~`dfir_ensure_events_partition` fails if `events_default` already holds rows for that month~~ | Done in Phase 2 (migration 0004) | - |

## From Phase 1

| Item | Why deferred | Target |
|---|---|---|
| ~~`dfir_ensure_events_partition()` as `SECURITY DEFINER`~~ | Done in Phase 2 (0004; the app role has no privileges on partitions) | - |
| Custody anchors: periodic signed Merkle root over recent `entry_hash` values into `anchors`, optional RFC 3161 time stamp. Without anchors, deleting the *newest* custody entries of an item (tail truncation) is not detectable by the chain alone | Needs a scheduler (Celery beat); not added in Phase 2 | Phase 10 (scheduler, deferred from 3) / Phase 8 |
| Scheduled re-verification of all originals (`nightly_verify_all`, guide 8.1 step 6). Phase 2 re-hashes every original before parsing it | Needs Celery beat | Phase 10 (scheduler, deferred from 3) |
| Evidence export package (`manifest.json`, `custody.json`, `manifest.sig`, guide 8.4) | Reporting/export phase | Phase 8 |
| ~~Browser token delivery via `HttpOnly; Secure; SameSite=Strict` cookies + CSRF~~ | Done in Phase 4 (`X-Token-Delivery: cookie`; the custom header is the CSRF defence) | - |
| Per-IP rate limiting on `/auth/*` (guide 14.3) and alerting on suspicious login patterns | Account lockout covers brute force per account for now | Phase 10 |
| Breached-password check through a k-anonymity API (HIBP-style); Phase 1 uses a bundled offline list | Needs egress; tests must stay offline | Phase 10 (optional) |
| OIDC/SSO (Keycloak/Authlib) and WebAuthn | P2 in the guide | Later |
| Accept several JWT `kid`s at once for zero-downtime JWT key rotation; `TOTP_ENC_KEY` rotation (re-wrap) | Single key per purpose is enough for dev | Phase 10 |
| Resumable/chunked uploads (tus or presigned S3 multipart) for very large images; Phase 1 streams one `PUT` (multipart to MinIO, bounded memory) | Works for the Standard profile; resumability is a UX improvement (not needed for Phase 5 bundles) | Phase 10 |
| Reaper for evidence stuck in `uploaded` (never finalized) and for orphaned object versions left by a failed DB commit after a successful vault write | Rare; detectable (finalize/verify compare versions); needs Celery beat | Phase 10 (scheduler, deferred from 3) |
| ~~`/cases/{id}/summary`~~ | Done in Phase 4 | - |
| ~~Workers writing custody entries (`processed`)~~ | Done in Phase 2 (worker signs `processed` / `hash_failed`) | - |
| `audit_log` growth: partition by month or archive (never purge) | Volume is small in dev | Phase 10 |
| Custody signing keys in Vault/KMS or an HSM, with the trusted-keys file (`CUSTODY_TRUSTED_KEYS_PATH`) distributed from the secret manager; today both are files (dev key in the `custodykeys` volume) | Needs a secret manager | Phase 10 |
| Two admins changing each other concurrently can deadlock in `update_user` (target read unlocked, acting admin locked in `_reauth`); Postgres aborts one as a 500. Lock both rows in id order, or map the deadlock to 409 | Rare; no data harm | Phase 10 |
| Notify admins when the published `signing_keys` row differs from the trusted key (today it is logged and reported only when someone runs verify) | Needs the scheduler / periodic re-verify | Phase 10 (scheduler, deferred from 3) |
| Test migration 0003's `GRANT dfirbench_app TO CURRENT_USER` with a non-superuser (CREATEROLE) owner on PG16 | Compose and CI owners are superusers | Phase 10 |

## From Phase 2

| Item | Why deferred | Target |
|---|---|---|
| Job reaper (Celery beat): re-dispatch `queued` jobs whose broker message was lost (e.g. `self.retry()` could not reach Redis) and `running` jobs whose lease expired with no redelivery pending. Today they are recoverable with `POST /jobs/{id}/retry` after a cancel | Needs the scheduler | Phase 10 (scheduler, deferred from 3) |
| Progress over Redis pub/sub + WebSocket/SSE (guide 10.6); Phase 2 persists `progress`/`heartbeat_at` on the job row; the Phase 4 UI polls `GET /jobs/{id}` | Polling is enough for the Standard profile | Phase 10 |
| ~~`POST /cases/{id}/events/search` with the search language, histogram, facets, context, export~~ | Done in Phase 4 | - |
| Evidence status `processing` / `processed` / `partial` (guide 4.4) derived from its jobs | Job state carries progress today (the UI shows jobs per evidence); needs a rule for multiple parsers per item and for bundles with derived children. Phase 5 also narrowed the app role's UPDATE on `evidence` to the upload/finalize columns, so this needs a grant | Phase 10 |
| Reprocess swaps events in separate short transactions (delete, then batches), so a reader can briefly see a partial timeline for that evidence. Option: build into a staging `job_id` and swap visibility at finish | Final state is always correct (deterministic ids); cost/benefit | Phase 10 |
| Backpressure: pause parsing when inserts lag (guide 10.6); batches are synchronous today, which bounds memory but not DB load across many workers | Single worker in dev | Phase 10 |
| More `linux_auth` inputs: `journalctl -o json` exports, wtmp/btmp/lastlog, bash/zsh history (guide 10.3 catalogue). Phase 5 collectors already gather them; a new parser plus a bundle reprocess will derive them | Scope | Phase 6 |
| Hayabusa enrichment of EVTX events; richer EVTX mappings (e.g. 4611/4673/4616 get only a generic message; 4616 time delta) | Phase 3 shipped its own rule engine + Sigma subset | Phase 6 |
| Per-job sandbox containers for parsers (`--network none`, read-only evidence mount, CPU/memory/pids limits); today the parser runs in the worker process on a 0400 scratch copy | Phase scope (already listed above) | Phase 10 |
| `container_image_digest` in run manifests: set `DFIR_IMAGE_DIGEST` in the worker image at build/deploy time | Needs the release pipeline (cosign) | Phase 10 |
| The app role has DELETE on `events` (reprocess). Option: route deletes through a `SECURITY DEFINER` function keyed by job so ad-hoc deletes are impossible | Defense in depth | Phase 10 |

## From Phase 3

| Item | Why deferred | Target |
|---|---|---|
| Celery beat: job reaper (Phase 2 item), nightly re-verify, custody anchors, uploaded-evidence reaper | Phase 3 did not need a scheduler; detection jobs recover like parse jobs (lease + retry) | Phase 10 |
| Suppressions (`POST /alerts/{id}/suppress`: rule + entity + expiry + reason) and incident grouping of alerts by host/user/time | Out of Phase 4 scope (analysis UI first) | Phase 9 |
| SQL push-down of rule predicates (prefilter by event_code/source_type) and streaming single-event detection at ingest; today every run rescans the case in Python | Correct and bounded; performance work | Phase 10 |
| Detection runs are full-case rescans; incremental runs over new events only | Simplicity/idempotency first | Phase 10 |
| Statistical analytics (beaconing, DGA, rare parent-child, IsolationForest), YARA, remaining Appendix B rules (WIN-0013..0025, 0028, LNX-0005..0010, NET-*) that need data sources not parsed yet | Needs Sysmon/PowerShell/DNS/PCAP/MFT/history parsers | Phases 6/7 |
| MISP import, VirusTotal/MISP enrichment, global (case_id NULL) IOC management API; IOC CIDR ranges | Integrations phase | Phase 9 |
| Asset inventory for `asset_criticality` in the risk score (1.0 today) | Phase 4 entities exist; criticality needs an admin/asset UI | Phase 9 |
| ATT&CK tags on events are only added; a tag from an alert that later goes stale stays on the event | Needs per-event tag provenance (out of Phase 4 scope) | Phase 10 |
| A detection run may read a partially reprocessed timeline (reprocess swaps events non-atomically); the post-parse run corrects it and marks non-matching alerts stale | Same root cause as the Phase 2 staging-swap item | Phase 10 |
| pySigma evaluation for wider Sigma coverage (modifiers `windash`, `base64offset`, keywords, correlations) | Own converter covers a strict, documented subset | Later |

## From Phase 4

| Item | Why deferred | Target |
|---|---|---|
| Monaco query editor with autocomplete popup; saved queries API | Plain input with client-side validation mirroring the server grammar is enough for now | Phase 10 |
| Virtualized event table | Server keyset paging + "load more" keeps the DOM bounded | Phase 10 |
| ECharts / Cytoscape for charts and the graph | Small hand-written SVG components; no new npm dependencies | Later |
| Entity merge suggestions + analyst approval; time-scoped IP-to-host mapping; domain and file entities; alert nodes in the graph; shortest path | Deterministic resolution first | Phase 7/10 |
| File browser (TSK listing) | Needs the Phase 6 disk parsers | Phase 6 |
| Playwright end-to-end tests of the UI | Vitest + Testing Library cover components; live API smoke covers the backend | Phase 11 |
| MFA enrolment UI and admin screens (users, rules, IOCs) | Login with TOTP works; enrolment/admin via API | Phase 10 |
| Export as a background job (larger than `EXPORT_MAX_ROWS`) | Synchronous capped export (10 000 rows) is audited with its hash | Phase 8 |
| Serve the CSP / security headers from one nginx include file instead of repeating them per location | Single-file config copied into the image; `phase4-smoke.py` checks every location | Phase 10 |
| DB trigger on `notes` requiring `version = OLD.version + 1` with a matching `note_versions` row, so history can't be skipped by the app role | The service layer writes history under a row lock; the app role can't delete or alter versions | Phase 11 |

## From Phase 5

| Item | Why deferred | Target |
|---|---|---|
| Parsers for the other artifacts the collectors gather: registry hives, Prefetch, Amcache, LNK/Jump Lists, browser history, SRUM, journal JSON, wtmp/btmp, shell histories, the volatile JSON listings. A bundle reprocess then derives them (members are already verified and listed as `verified`) | Phase scope (deep parsers) | Phase 6 |
| Raw NTFS / VSS reads in the Windows collector for locked files (`$MFT`, `$UsnJrnl:$J`, loaded `Amcache.hve`/`SRUDB.dat`, other users' loaded hives): recorded as collection errors today | Needs a raw-volume reader shipped with the collector; the Standard profile collects them from disk images instead | Phase 10 |
| Signed collector releases (Authenticode for the PowerShell script, minisign for the Python/bash scripts) with signature checks at ingest; today trust = SHA-256 list outside the DB | Needs the release pipeline and key management | Phase 10 |
| Multi-segment evidence sets (E01 `.E02...`, split raw `.001/.002`) as one evidence item with a combined manifest (guide 8.5) | The evidence model is one object per item; the docs say to use single-segment images | Phase 6 |
| Import of `*.acquisition.json` (memory/disk wrappers) to prefill evidence fields and check memory image size against RAM | Analysts copy the values by hand today | Phase 6 |
| Bundle formats other than ZIP (tar.gz, 7z), a bash-only Linux collector for hosts without Python 3, a Windows disk-imaging wrapper, a macOS collector | ZIP-only is a deliberate hostile-input decision; Python 3 is on practically every server; FTK Imager/ewfacquire procedure documented | Later |
| Reaper for vault objects written by a bundle job whose DB commit then failed (derived bytes without an evidence row); same class as the Phase 1 orphaned-version item | Rare, detectable (key prefix `{case}/{bundle}/derived/` without a row); needs the scheduler | Phase 10 |
| UI view of per-member bundle verdicts (`GET /evidence/{id}/bundle`); the Evidence tab shows derived items and their parent only | API complete; UI polish | Phase 10 |
| Remote agent (guide 9.4), cloud/SaaS collectors (9.5), mobile/email ingest (9.6) | P2 in the guide | Later |
