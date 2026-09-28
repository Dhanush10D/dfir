# Backlog (deferred items)

Items consciously deferred from a phase, with the phase expected to pick them up.

## From Phase 0

| Item | Why deferred | Target |
|---|---|---|
| Separate least-privilege DB role for the app (`REVOKE UPDATE, DELETE, TRUNCATE ON custody_log, audit_log`); migrations run as owner | Needs role provisioning in compose/CI and connection split; triggers already enforce append-only | Phase 1 (custody) or 10 |
| `AuditMiddleware` writing `audit_log` rows per request | Needs authenticated user context | Phase 1 |
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
| `ensure_buckets` only checks bucket existence: verify/re-apply Object Lock on the vault bucket if missing, and surface it in `/ready` | Must hold before any evidence is uploaded | Phase 1 |
| uvicorn `--forwarded-allow-ips` for the nginx container so `X-Forwarded-For` yields real client IPs for `audit_log.ip` | Needed once audit rows record IPs | Phase 1 |
| `dfir_ensure_events_partition` fails if `events_default` already holds rows for that month; ingest must move them first | Covered by partition maintenance work | Phase 2 |
| Disable or privatize frontend source maps (`build.sourcemap`) in prod builds | Dev convenience today | Phase 10 |
