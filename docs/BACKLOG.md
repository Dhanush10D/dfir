# Backlog (deferred items)

Items consciously deferred from a phase, with the phase expected to pick them up.

Phase 10 went through every item targeted at it: each is now marked **Done in Phase 10**,
**Partly done in Phase 10** (the rest named), or **Post-v1** with a one-line reason (after the
v1 release that Phase 11 documents; not planned for a numbered phase). See also the decision
list in `docs/specs/PHASE-10.md`.

## From Phase 0

| Item | Why deferred | Target |
|---|---|---|
| ~~Separate least-privilege DB role for the app~~ **Partly done in Phase 1**: migration 0002 creates `dfirbench_app` (no UPDATE/DELETE/TRUNCATE on `custody_log`/`audit_log`) and the API/worker run every session as it (`DATABASE_APP_ROLE`, `SET ROLE` at connect). Remaining: a separate LOGIN role with its own password so a compromised app cannot `RESET ROLE` back to the owner; migrations keep the owner login | Needs secret provisioning for a second DB password in compose/CI | **Done in Phase 10**: API/worker log in as `dfirbench_app` (provision-app-login, `DATABASE_MIGRATE_URL`); RESET ROLE/SET ROLE denied (verify, smoke) |
| ~~`AuditMiddleware` writing `audit_log` rows per request~~ | Done in Phase 1 | - |
| ~~Events partition maintenance~~ **Done in Phase 2** (ingest ensures partitions, the function moves stray `events_default` rows). Remaining: retention by dropping partitions | Needs a scheduler and a retention policy | Post-v1: retention needs a legal retention policy and a scheduler |
| Reverse proxy with TLS (Caddy) in compose | Dev stack binds to 127.0.0.1 only | Post-v1: dev stack binds 127.0.0.1; deployment TLS goes in the Phase 11 admin guide |
| `/metrics` (Prometheus), OpenTelemetry traces | Observability hardening | **Done in Phase 10** for `/metrics` (token, docs/hardening.md); OpenTelemetry traces post-v1 (new dependencies and a collector service) |
| pip-audit, Trivy image scan, gitleaks, SBOM (Syft), cosign signing in CI | Security pipeline | **Done in Phase 10**: scripts/scan.sh + CI `security` job (pip-audit, npm audit, gitleaks, Trivy, CycloneDX SBOMs); cosign signing post-v1 (needs a registry and release pipeline) |
| ~~Forensic binaries in the worker image~~ **Partly done in Phase 6**: Sleuth Kit (with Debian's libewf), Volatility 3 (own venv), YARA (yara-python) and the tool version file. Remaining: Plaso, Hayabusa, tshark, Suricata (image size / RAM), Zeek (optional engine, wrapper exists) | Image size on the 7.6 GB dev host | Post-v1: Plaso/Hayabusa/tshark/Suricata/Zeek do not fit the 7.8 GB dev host |
| Per-job sandbox containers (`--network none`, read-only evidence mount) | Phase scope | **Done in Phase 10**: `parser-sandbox` container (no network, read-only root and evidence mount, no capabilities, non-root, limits), one job at a time, a process per job (PHASE-10 decision 1) |
| ~~Router~~ (done in Phase 4: own History-API router). Remaining: generated TypeScript API client (`openapi-typescript`) and shadcn/ui; Phase 4 hand-writes `frontend/src/api/types.ts` | No new npm dependencies in Phase 4 | Post-v1: UI tooling, no hardening value |
| Split worker images (`worker-parse`, `worker-ai`) per guide 21.2 | Only one worker needed now; Phase 6 kept one image (engines add ~250 MB); Phase 7 needs no AI worker (the hashing embedder and provider calls run in the API) | Post-v1: one image keeps disk/RAM low; the sandbox is a separate service of the same image |
| Evaluate replacing the `pgsty/minio` community image if upstream images return, or pin by digest | Upstream `minio/minio` images are no longer published on Docker Hub/quay | **Done in Phase 10** for pinning: every service/base image is pinned by tag and index digest; replacing the community image stays post-v1 |
| ~~`EMBEDDING_DIM` != 384 requires a migration of `event_chunks.embedding`~~ **Done in Phase 7**: the default embedder is the local `hashing-v1` (384-d); settings refuse any other `EMBEDDING_DIM`, and remote embedding providers must return 384-d vectors. A different model size still needs a migration | - | - |
| ~~`dfir_ensure_events_partition` fails if `events_default` already holds rows for that month~~ | Done in Phase 2 (migration 0004) | - |

## From Phase 1

| Item | Why deferred | Target |
|---|---|---|
| ~~`dfir_ensure_events_partition()` as `SECURITY DEFINER`~~ | Done in Phase 2 (0004; the app role has no privileges on partitions) | - |
| Custody anchors: periodic signed Merkle root over recent `entry_hash` values into `anchors`, optional RFC 3161 time stamp. Without anchors, deleting the *newest* custody entries of an item (tail truncation) is not detectable by the chain alone. Phase 8 reports and export packages record each chain's head seq/hash, which makes later truncation visible against a signed report | Needs a scheduler (Celery beat) | Partly done in Phase 10: every backup manifest signs all chain heads (restore checks them); periodic anchors post-v1 (needs a scheduler) |
| Scheduled re-verification of all originals (`nightly_verify_all`, guide 8.1 step 6). Phase 2 re-hashes every original before parsing it | Needs Celery beat | Partly done in Phase 10: `python -m app.cli integrity-check` (read-only, cron-able, docs/backup-restore.md); a built-in scheduler is post-v1 |
| ~~Evidence export package (`manifest.json`, `custody.json`, `manifest.sig`, guide 8.4)~~ **Done in Phase 8** (`POST /evidence/{id}/export-package`, offline `python -m app.reports.verify package`). Remaining: optional `original/` and `derived/` members when policy allows (streamed ZIP for multi-GB originals) | Originals can be many GB; `GET /evidence/{id}/download` covers them | Post-v1: `original/`/`derived/` members need streamed multi-GB ZIPs; downloads cover originals |
| ~~Browser token delivery via `HttpOnly; Secure; SameSite=Strict` cookies + CSRF~~ | Done in Phase 4 (`X-Token-Delivery: cookie`; the custom header is the CSRF defence) | - |
| Per-IP rate limiting on `/auth/*` (guide 14.3) and alerting on suspicious login patterns | Account lockout covers brute force per account for now | **Done in Phase 10** for per-IP limits (login+MFA, refresh; 429, audited, fail closed); alerting on login patterns post-v1 (needs a scheduler/alert rules) |
| Breached-password check through a k-anonymity API (HIBP-style); Phase 1 uses a bundled offline list | Needs egress; tests must stay offline | Post-v1: needs egress; the offline list stays |
| OIDC/SSO (Keycloak/Authlib) and WebAuthn | P2 in the guide | Later |
| Accept several JWT `kid`s at once for zero-downtime JWT key rotation; `TOTP_ENC_KEY` rotation (re-wrap) | Single key per purpose is enough for dev | Post-v1: key rotation procedures go into the Phase 11 admin guide; single node needs a planned logout |
| Resumable/chunked uploads (tus or presigned S3 multipart) for very large images; Phase 1 streams one `PUT` (multipart to MinIO, bounded memory) | Works for the Standard profile; resumability is a UX improvement (not needed for Phase 5 bundles) | Post-v1: UX feature, uploads already stream with bounded memory |
| Reaper for evidence stuck in `uploaded` (never finalized) and for orphaned object versions left by a failed DB commit after a successful vault write | Rare; detectable (finalize/verify compare versions); needs Celery beat | Post-v1: needs a scheduler; integrity-check reports such items |
| ~~`/cases/{id}/summary`~~ | Done in Phase 4 | - |
| ~~Workers writing custody entries (`processed`)~~ | Done in Phase 2 (worker signs `processed` / `hash_failed`) | - |
| `audit_log` growth: partition by month or archive (never purge) | Volume is small in dev | Post-v1: needs an archive/retention policy |
| Custody signing keys in Vault/KMS or an HSM, with the trusted-keys file (`CUSTODY_TRUSTED_KEYS_PATH`) distributed from the secret manager; today both are files (dev key in the `custodykeys` volume) | Needs a secret manager | Post-v1: needs a secret manager; backups now carry the key encrypted |
| Two admins changing each other concurrently can deadlock in `update_user` (target read unlocked, acting admin locked in `_reauth`); Postgres aborts one as a 500. Lock both rows in id order, or map the deadlock to 409 | Rare; no data harm | **Done in Phase 10**: `update_user` locks actor, target and all active admins in id order (test_security.py) |
| Notify admins when the published `signing_keys` row differs from the trusted key (today it is logged and reported only when someone runs verify) | Needs the scheduler / periodic re-verify | Partly done in Phase 10: integrity-check reports `signing_key_mismatch`; notifications need the scheduler (post-v1) |
| Test migration 0003's `GRANT dfirbench_app TO CURRENT_USER` with a non-superuser (CREATEROLE) owner on PG16 | Compose and CI owners are superusers | Post-v1: `CREATE EXTENSION vector` needs a superuser or a pre-created extension; documented in the Phase 11 admin guide |

## From Phase 2

| Item | Why deferred | Target |
|---|---|---|
| Job reaper (Celery beat): re-dispatch `queued` jobs whose broker message was lost (e.g. `self.retry()` could not reach Redis) and `running` jobs whose lease expired with no redelivery pending. Today they are recoverable with `POST /jobs/{id}/retry` after a cancel | Needs the scheduler | Post-v1: needs the scheduler; jobs are recoverable with cancel + retry |
| Progress over Redis pub/sub + WebSocket/SSE (guide 10.6); Phase 2 persists `progress`/`heartbeat_at` on the job row; the Phase 4 UI polls `GET /jobs/{id}` | Polling is enough for the Standard profile | Post-v1: polling is enough for the Standard profile |
| ~~`POST /cases/{id}/events/search` with the search language, histogram, facets, context, export~~ | Done in Phase 4 | - |
| Evidence status `processing` / `processed` / `partial` (guide 4.4) derived from its jobs | Job state carries progress today (the UI shows jobs per evidence); needs a rule for multiple parsers per item and for bundles with derived children. Phase 5 also narrowed the app role's UPDATE on `evidence` to the upload/finalize columns, so this needs a grant | Post-v1: needs a grant change and a multi-parser rule |
| Reprocess swaps events in separate short transactions (delete, then batches), so a reader can briefly see a partial timeline for that evidence. Option: build into a staging `job_id` and swap visibility at finish | Final state is always correct (deterministic ids); cost/benefit | Post-v1: final state is always correct (deterministic ids) |
| Backpressure: pause parsing when inserts lag (guide 10.6); batches are synchronous today, which bounds memory but not DB load across many workers | Single worker in dev | Post-v1: the sandbox now runs one parse at a time; inserts are ~10x faster (COPY staging) |
| ~~More `linux_auth` inputs~~ **Done in Phase 6** (`journal_json`, `wtmp`, `shell_history`). Remaining: `lastlog` (sparse per-UID file) | Low value | Later |
| Hayabusa enrichment of EVTX events; richer EVTX mappings (e.g. 4611/4673/4616 get only a generic message; 4616 time delta) | Phase 6 focused on new artifact types; Hayabusa is another large binary | Post-v1: another large binary for the worker image |
| Per-job sandbox containers for parsers (`--network none`, read-only evidence mount, CPU/memory/pids limits); today the parser runs in the worker process on a 0400 scratch copy | Phase scope (already listed above) | **Done in Phase 10**: see the From Phase 0 entry (parser-sandbox container, docs/hardening.md) |
| `container_image_digest` in run manifests: set `DFIR_IMAGE_DIGEST` in the worker image at build/deploy time | Needs the release pipeline (cosign) | Post-v1: needs a registry and release pipeline (cosign) |
| The app role has DELETE on `events` (reprocess). Option: route deletes through a `SECURITY DEFINER` function keyed by job so ad-hoc deletes are impossible | Defense in depth | Post-v1: events are derived data rebuildable from WORM originals; the delete is fenced by the job lock |

## From Phase 3

| Item | Why deferred | Target |
|---|---|---|
| Celery beat: job reaper (Phase 2 item), nightly re-verify, custody anchors, uploaded-evidence reaper | Phase 3 did not need a scheduler; detection jobs recover like parse jobs (lease + retry) | Post-v1: a scheduler is a new always-on service on the 7.8 GB host; integrity-check is cron-able meanwhile |
| Suppressions (`POST /alerts/{id}/suppress`: rule + entity + expiry + reason) and incident grouping of alerts by host/user/time | Out of Phase 4 scope (analysis UI first); not in the Phase 9 scope (response + integrations) | Post-v1: analysis feature, not hardening |
| SQL push-down of rule predicates (prefilter by event_code/source_type) and streaming single-event detection at ingest; today every run rescans the case in Python | Correct and bounded; performance work | Post-v1: correct and bounded; the Phase 10 benchmark measures detection speed |
| Detection runs are full-case rescans; incremental runs over new events only | Simplicity/idempotency first | Post-v1: performance work |
| Statistical analytics (beaconing, DGA, rare parent-child, IsolationForest), ~~YARA~~ (Phase 6 `yara_scan`), remaining Appendix B rules (WIN-0013..0025, 0028, LNX-0005..0010, NET-*) that need data sources not parsed yet | Needs Sysmon/PowerShell/DNS/PCAP/MFT/history parsers | Post-v1: features needing new data sources |
| ~~VirusTotal/MISP enrichment~~ **Done in Phase 9** (indicators only, TLP, cache, sightings to MISP). Remaining: MISP event pull/import, global (case_id NULL) IOC management API, IOC CIDR ranges | Out of the Phase 9 spec | Post-v1: integration features outside hardening |
| Asset inventory for `asset_criticality` in the risk score (1.0 today) | Phase 4 entities exist; criticality needs an admin/asset UI; not in the Phase 9 scope | Post-v1: needs an admin UI |
| ATT&CK tags on events are only added; a tag from an alert that later goes stale stays on the event | Needs per-event tag provenance (out of Phase 4 scope) | Post-v1: needs per-event tag provenance |
| A detection run may read a partially reprocessed timeline (reprocess swaps events non-atomically); the post-parse run corrects it and marks non-matching alerts stale | Same root cause as the Phase 2 staging-swap item | Post-v1: same root cause as the staging-swap item |
| pySigma evaluation for wider Sigma coverage (modifiers `windash`, `base64offset`, keywords, correlations) | Own converter covers a strict, documented subset | Later |

## From Phase 4

| Item | Why deferred | Target |
|---|---|---|
| Monaco query editor with autocomplete popup; saved queries API | Plain input with client-side validation mirroring the server grammar is enough for now | Post-v1: UI feature |
| Virtualized event table | Server keyset paging + "load more" keeps the DOM bounded | Post-v1: UI feature |
| ECharts / Cytoscape for charts and the graph | Small hand-written SVG components; no new npm dependencies | Later |
| Entity merge suggestions + analyst approval; time-scoped IP-to-host mapping; domain and file entities; alert nodes in the graph; shortest path | Deterministic resolution first; Phase 7 kept to the roadmap's AI features | Post-v1: analysis feature |
| File browser (TSK listing) and file extraction (`icat`) | Phase 6 ships the TSK timeline (`tsk_fs`); a browsable listing needs an API + UI | Post-v1: needs an API + UI |
| Playwright end-to-end tests of the UI | Vitest + Testing Library cover components; live API smoke covers the backend | Phase 11 |
| MFA enrolment UI and admin screens (users, rules, IOCs) | Login with TOTP works; enrolment/admin via API | Post-v1: UI feature; enrolment works via the API |
| Export as a background job (larger than `EXPORT_MAX_ROWS`) | Synchronous capped export (10 000 rows) is audited with its hash; Phase 8 reports are also synchronous and capped | Post-v1: needs background render jobs |
| Serve the CSP / security headers from one nginx include file instead of repeating them per location | Single-file config copied into the image; `phase4-smoke.py` checks every location | **Done in Phase 10**: `infra/docker/security-headers.conf`, checked on every location by phase10-smoke.py |
| DB trigger on `notes` requiring `version = OLD.version + 1` with a matching `note_versions` row, so history can't be skipped by the app role | The service layer writes history under a row lock; the app role can't delete or alter versions | Phase 11 |

## From Phase 5

| Item | Why deferred | Target |
|---|---|---|
| ~~Parsers for the other collected artifacts~~ **Done in Phase 6**: registry hives, Prefetch, Amcache, LNK, browser history, journal JSON, wtmp/btmp, shell histories (a bundle reprocess derives them). Remaining: Jump Lists, SRUM, the volatile JSON listings (see From Phase 6) | - | - |
| Raw NTFS / VSS reads in the Windows collector for locked files (`$MFT`, `$UsnJrnl:$J`, loaded `Amcache.hve`/`SRUDB.dat`, other users' loaded hives): recorded as collection errors today | Needs a raw-volume reader shipped with the collector; the Standard profile collects them from disk images instead | Post-v1: needs a raw-volume reader in the collector |
| Signed collector releases (Authenticode for the PowerShell script, minisign for the Python/bash scripts) with signature checks at ingest; today trust = SHA-256 list outside the DB | Needs the release pipeline and key management | Post-v1: needs the release pipeline and key management |
| Multi-segment evidence sets (E01 `.E02...`, split raw `.001/.002`) as one evidence item with a combined manifest (guide 8.5) | The evidence model is one object per item; `tsk_fs` reads single-segment raw/E01 images | Post-v1: evidence model change |
| Import of `*.acquisition.json` (memory/disk wrappers) to prefill evidence fields and check memory image size against RAM | Analysts copy the values by hand today; not a parser concern | Post-v1: convenience feature |
| Bundle formats other than ZIP (tar.gz, 7z), a bash-only Linux collector for hosts without Python 3, a Windows disk-imaging wrapper, a macOS collector | ZIP-only is a deliberate hostile-input decision; Python 3 is on practically every server; FTK Imager/ewfacquire procedure documented | Later |
| Reaper for vault objects written by a bundle job whose DB commit then failed (derived bytes without an evidence row); same class as the Phase 1 orphaned-version item | Rare, detectable (key prefix `{case}/{bundle}/derived/` without a row); needs the scheduler | Post-v1: needs the scheduler |
| UI view of per-member bundle verdicts (`GET /evidence/{id}/bundle`); the Evidence tab shows derived items and their parent only | API complete; UI polish | Post-v1: UI polish |
| Windows collector: recurse directories manually and skip ones with the `ReparsePoint` attribute (PS 5.1 `Get-ChildItem -Recurse` follows junctions under `System32\Tasks`) | Still read-only and bounded by byte caps | Post-v1: read-only and bounded by byte caps; needs a collector re-release |
| Bundle job crash mid-derivation: `_finish_bundle` should add `bundle_members` rows for candidates never processed in that attempt | Run is already marked failed; reprocess re-derives | Post-v1: run is marked failed; reprocess re-derives |
| Remote agent (guide 9.4), cloud/SaaS collectors (9.5), mobile/email ingest (9.6) | P2 in the guide | Later |

## From Phase 6

| Item | Why deferred | Target |
|---|---|---|
| Plaso super-timeline, Hayabusa, tshark, Suricata, capa/FLOSS, ssdeep/TLSH in the worker image | Image size and RAM on the dev host; each needs its own wrapper + fake-binary tests | Post-v1: image size and RAM on the dev host |
| Zeek in an optional derived worker image (`worker-net`) with a CI job that runs the real engine on `capture.pcap` | Zeek is hundreds of MB from a third-party repo; the wrapper is tested with a fake binary only | Post-v1: hundreds of MB from a third-party repo |
| Volatility 3 symbol packs (Windows ISF / Linux kernel ISF) provisioning and a real-memory-image test in CI | Packs are hundreds of MB; no redistributable test image; the live smoke only proves a clean failure | Post-v1: packs are hundreds of MB; no redistributable test image |
| MFT / `$UsnJrnl:$J` parsers (MFTECmd-style) and `$SI` vs `$FN` timestomp checks | Needs raw NTFS reads (collector) or `icat` extraction from images | Post-v1: new parsers |
| Jump Lists (OLE CFB AutomaticDestinations: DestList + embedded LNK), ShellBags (UsrClass/NTUSER), SRUM (ESE database) | Need an OLE and an ESE reader; collected already, re-derived by a bundle reprocess once parsers exist | Post-v1: new parsers |
| Firefox `places.sqlite-wal` replay (open a copy with the WAL applied) | `immutable=1` read-only open ignores the WAL by design; replay needs a writable scratch copy | Post-v1: parser feature |
| The collectors' volatile JSON listings (processes, connections, services) as snapshot events | Not time-series data; needs a "snapshot" event convention | Post-v1: needs a snapshot event convention |
| User-supplied YARA rules through the API (validation, size caps, compile in a sandbox, versioned rule packs) and YARA over files extracted from images / memory regions (Volatility yarascan) | Rules are trusted configuration only in Phase 6; not in the Phase 9 scope | Post-v1: the parser sandbox now exists to compile/run them in; feature work |
| Detection rules for the new sources (Run key persistence, IFEO debugger, BAM/Prefetch of rare binaries, DNS to IOC domains, YARA-match alerts) | Phase 3 engine works on any field; rule content is a separate review; not in the Phase 9 scope | Post-v1: rule content needs its own review |
| Win8.x and Win7 x86 ShimCache layouts; UserAssist focus-time decoding checks against real hives; registry transaction-log replay for dirty hives | Synthetic fixtures only (no redistributable real hives); dirty hives are parsed as-is with a warning | Post-v1: needs real hives |
| Windows: `run_tool` kills only the launcher of a `.bat` test double (no process-group kill on Windows) | Workers run on Linux (process-group kill); Windows only runs unit tests | Later |
| TCP reassembly for HTTP/TLS in the `pcap` parser (today single-segment only) | Zeek covers it when installed | Later |
| Pin Volatility 3's transitive pip dependencies in `infra/docker/worker.Dockerfile` (constraints file with hashes); today only `volatility3==${VOLATILITY3_VERSION}` is pinned | Needs an image rebuild (~250 MB of engines) that the 7.6 GB dev host could not afford at Phase 6 close; `vol` runs in its own venv, offline, through `run_tool` | **Done in Phase 10**: `infra/docker/volatility-requirements.txt`, `--require-hashes --no-deps`; verify checks the venv contents |

## From Phase 7

| Item | Why deferred | Target |
|---|---|---|
| ~~A4 report drafting~~ **Done in Phase 8** (`report_draft`, accepted-only apply, labelled). Remaining: A14 AI report QA (the deterministic QA gate is done) | Deterministic QA covers the court-readiness checks; AI QA needs an eval set | Post-v1: needs an eval set |
| A9 analytics with scikit-learn: IsolationForest on per-host time buckets, beaconing, rare parent-child, DGA scoring, DBSCAN over command lines (guide 11.5, 13.13); `scikit-learn` pin and a labeled sample set | P2 in the guide and not in the Phase 7 roadmap row; adds numpy/scipy (~100 MB) to the images on the 7.6 GB host | Post-v1: adds ~100 MB to the images |
| A6 IOC/entity extraction from free text, A8 standalone ATT&CK mapping suggestions (A2/A7 already return candidates), A10 similar cases, A12 log-format helper, A13 next-step suggestions | Not in the Phase 7 roadmap row | Later |
| A11 AI playbook recommendation (Phase 9 has deterministic trigger matching: `GET /alerts/{id}/playbooks`); one-click IOC creation from A7 indicators | Needs an eval set for recommendations; out of the Phase 9 spec | Post-v1: needs an eval set |
| Chat index and narrative as background jobs on the `ai` Celery queue (with progress), and neural embeddings (sentence-transformers BGE/MiniLM) in a `worker-ai` image | Indexing runs in the request with a cap (`AI_INDEX_MAX_EVENTS`); torch images do not fit the dev host | Post-v1: torch images do not fit the dev host |
| Redaction mapping (`ai_interactions.redactions.mapping`) stored as plain JSONB: encrypt at rest or keep only a keyed reference; NER-based redaction of names in free text | Values already exist in `events`; regex redaction is documented as best effort | Post-v1: values also exist in events; encryption needs a KEK-backed column design |
| The daily budget is checked before a call, so concurrent in-flight calls can overshoot it by a few calls; a Redis reservation would make it exact | Per-user/per-case rate limits bound the overshoot | Post-v1: overshoot bounded by rate limits |
| Multi-turn chat (conversation memory) and streaming answers in the UI | Single-question chat keeps every answer independently verifiable | Later |
| Anthropic prompt caching (`cache_control`) on the stable system prompts | Cost optimisation; needs real traffic to measure | Later |
| A live-model evaluation run (`python -m app.ai.eval --provider live --record ...`) with the report stored next to the prompt versions | Needs an API key and network; the offline suites run in CI | Phase 11 (AI-eval report) |
| Citation links to alerts open the Alerts tab, not the specific alert; deep links for alerts | UI polish | Post-v1: UI polish |
| Run `scripts/phase7-smoke.py` in the CI compose-smoke job (stack started with `ENABLE_AI=true LLM_PROVIDER=fake`) | CI smoke covers Phases 1-3 today; verify-phase7.sh runs it locally | **Done in Phase 10**: CI compose-smoke runs the Phase 1-3, 7, 9 and 10 smokes |

## From Phase 8

| Item | Why deferred | Target |
|---|---|---|
| Charts in reports (timeline histogram, ATT&CK heatmap, entity/attack-path graph images, guide 18.2 item 10 and 18.3 step 2) | Needs a deterministic PNG/SVG renderer (matplotlib adds ~60 MB); tables carry the same data | Post-v1: needs a deterministic image renderer |
| DOCX output, per-organisation templates, examiner qualification block as a configurable section | Standard profile ships HTML/PDF/JSON/STIX/CSV; templates need an admin UI | Later |
| PDF/A and embedded Unicode fonts (today built-in Helvetica/Courier; non-Windows-1252 characters are replaced in the PDF and kept exactly in HTML/JSON) | Font files in the image and PDF/A validation | Post-v1: font files and PDF/A validation |
| RFC 3161 time stamps on report signatures and export packages | Needs a TSA (egress) and its trust chain | Post-v1: needs a TSA (egress) |
| Background render jobs (Celery) with progress for large reports; today rendering is synchronous and bounded by the snapshot caps, a 2000-page PDF cap and `REPORT_RENDER_TIMEOUT_S` (413 `report_too_large`). A report at every cap takes about a minute on the dev host (ReportLab tables, pure-Python string widths); `rl_accel` or fewer table rows would speed it up | Typical reports render in seconds | Post-v1: typical reports render in seconds |
| Report comments / review threads, and a diff view between report versions | UI polish; versions and audit rows exist | Later |
| STIX `observed-data`, `malware` and `relationship` objects (indicator -> attack-pattern needs an analyst mapping); TAXII publishing | Indicators, attack patterns and the report object validate today; TAXII is out of the Phase 9 spec | Post-v1: needs analyst mappings |
| The SPA's own CSP (`style-src 'self'`) also applies to the sandboxed `srcdoc` preview, so the in-app preview is unstyled; the downloaded HTML is styled | Relaxing the SPA CSP for inline styles is not worth it | Later |
| Signed report artifacts live in the plain `artifacts` bucket (tampering is detected by hash + signature, not prevented); optional Object Lock/retention for signed reports | Detection is enough for the Standard profile; WORM needs its own retention policy | Post-v1: tampering is detected (hash + signature); WORM needs a retention policy |
| Reaper for artifacts written by a sign whose DB commit then failed (objects under `reports/.../vN/` for a report that is not signed; a retry overwrites them) | Rare and harmless (never served: downloads check the signed manifest) | Post-v1: needs the scheduler; harmless (never served) |
| Write-once artifact keys (a per-signing prefix or an if-none-match put). Today a re-sign of the same version replaces the objects: after a failed sign, or after a 0011 downgrade/upgrade round trip returned signed reports to drafts. The old hashes stay in the `report.sign` audit row | Needs a storage layout change; both paths are operator/rare events | Post-v1: storage layout change |

## From Phase 9

| Item | Why deferred | Target |
|---|---|---|
| Remote agent and real endpoint actions (`agent.isolate_host`, `kill_process`, `disable_account`, `memory_dump`, `collect_triage`); today they are recorded `not_executed` and completed by hand | Standard profile has no agent (guide 9.4, P2) | Later |
| Celery beat sweeps: outbound deliveries due for a retry and approval expiry. Today a retry is scheduled by the task itself (`countdown`) and the next emitted event, and expiry is applied on access (every read and decision) | No scheduler in the Standard profile yet (see the From Phase 3 Celery beat item) | Post-v1: needs the scheduler; retries and expiry work on access |
| Redelivery of a `failed` webhook from the UI / API (a new delivery row for the same event) | The delivery log shows the failure; the test button sends a fresh event | Post-v1: UI/API feature |
| Ticketing sync (Jira, ServiceNow), S3 bulk log import, fetching logs from a SIEM API, OpenCTI, TAXII publishing | Out of the Phase 9 spec | Later |
| SSO (OIDC/SAML) | Out of the Phase 9 spec | Later |
| Editing an existing integration's non-secret configuration in the UI (the API supports PATCH `config`); today the UI creates, enables/disables, replaces secrets and tests | UI polish | Post-v1: UI polish (API supports it) |
| Total deadline for reading HTTP response headers (bounded by the read timeout per wait and http.client's header limits; SMTP sessions have a total-deadline watchdog) | Bounded today | Post-v1: bounded by per-wait timeouts and header limits |
| Webhook signing secrets are symmetric (HMAC); an option for Ed25519-signed outbound webhooks with a published key | HMAC is what guide 15.6 specifies and receivers expect | Later |
| The keyed secret fingerprint is derived from the current KEK, so it changes after a KEK rotation (the secret itself is unchanged) | Cosmetic; the fingerprint only helps recognise equal secrets | Later |
| Follow-up outbox runs are not deduplicated: every run that leaves a pending delivery schedules one follow-up for its due time, so several commits in the retry window start parallel chains (each ends when nothing is pending; at most ~8 min with the default backoff). A Redis `SET NX` per due second would keep one | Bounded and idempotent (claims use `SKIP LOCKED`) | Post-v1: bounded and idempotent |
| The in-memory rate limiter used by tests and tools never prunes old windows | Production uses Redis with expiry | Later |
| Run `scripts/phase9-smoke.py` in the CI compose-smoke job (needs the stack with `ENABLE_ENRICHMENT=true ENRICHMENT_FAKE=true OUTBOUND_ALLOW_HTTP=true OUTBOUND_ALLOW_HOSTS=api`) | CI smoke covers Phases 1-3 today; verify-phase9.sh runs it locally | **Done in Phase 10**: see the Phase 7 entry |

## From Phase 10

| Item | Why deferred | Target |
|---|---|---|
| Bundle unpacking in the parser sandbox (extract and verify members in the sandbox, upload from the worker) | Needs a second sandbox protocol for derived files; unpacking is stdlib `zipfile` + JSON with the Phase 5 bounds (residual risk in docs/hardening.md) | Post-v1 |
| More than one parse at a time: several sandbox replicas, each with its own spool pair and slot lock | One slot per sandbox keeps one job's evidence visible at a time; the dev host runs one parse at a time anyway | Post-v1 |
| A stronger sandbox runtime (gVisor `runsc` or Kata) for the `parser-sandbox` service | The container shares the host kernel; a runtime is a deployment choice outside this repository | Post-v1 (deployment) |
| WAL archiving / point-in-time recovery and MinIO site replication | Backups are full dumps in a maintenance window (Standard profile) | Post-v1 |
| A containerised backup/restore tool (today the scripts run on the Docker host with the backend venv) | Host scripts can pipe Docker volumes without giving any service the Docker socket | Post-v1 |
| Scheduled `integrity-check` with notifications (and custody anchors between backups) | Needs the scheduler (see the Celery beat items) | Post-v1 |
| Event ingest needs the database's `TEMPORARY` privilege for the COPY staging table; fall back to multi-row INSERT where it is revoked | Default PostgreSQL grants it to `PUBLIC`; documented in docs/hardening.md | Post-v1 |
