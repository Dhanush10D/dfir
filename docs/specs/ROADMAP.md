# dfirbench build roadmap (Standard profile)

Source: `docs/BUILD_GUIDE.md` section 23. Each phase is built, verified, then pushed to `main`.

| Phase | Name | Guide sections | Key acceptance |
|---|---|---|---|
| 0 | Foundation | 4-7, 14, 21 | `docker compose up` starts postgres, redis, minio, api, worker, web; `/api/v1/health` ok; Alembic baseline with the core tables; CI workflow; tests + lint pass |
| 1 | Evidence core + IAM | 7, 8, 16, 20.3, 22.3 | Argon2id + JWT + TOTP + 5-role RBAC; cases; streaming-hash upload to MinIO; Ed25519 hash-chained custody + verify; audit log; tamper tests pass |
| 2 | Processing pipeline | 10, 14.5, App. A | Parser framework + registry; Celery jobs with retry/cancel/progress; EVTX + Linux auth/syslog parsers; normalization; run manifests; idempotent reprocess; timeline API |
| 3 | Detection | 11, App. B | YAML rule engine (single/threshold/sequence); starter rules; Sigma subset import; IOC matching; anti-forensics detectors; alert lifecycle, dedup, scoring; coverage table |
| 4 | Analysis UI | 12, 17 | React + TS app: login, cases, evidence/custody, timeline Explorer with search language, facets, histogram, alerts, ATT&CK matrix, notes/bookmarks, entity resolution + graph, process tree |
| 5 | Collection | 9 | Triage collector (Windows PowerShell + Linux bash/Python) with manifest; bundle ingest produces timeline entries; memory/disk acquisition docs + wrappers |
| 6 | Deep parsers | 10 | Browser, registry, prefetch, Amcache, LNK; TSK timeline, Volatility 3, PCAP/Zeek wrappers in the worker image; YARA + PE triage |
| 7 | AI layer | 13, 22.4 | Gateway (Anthropic, Ollama/OpenAI-compatible, fake); evidence packs; citation + schema validators; injection defenses; NL search, alert explain, narrative, RAG chat (pgvector), script explain; AI audit; eval harness + injection suite |
| 8 | Reporting | 18 | Technical, executive, and custody reports; HTML + PDF; STIX 2.1 / CSV / JSON; snapshot + sign + verify; versioning; AI draft approval |
| 9 | Response + integrations | 19 | YAML playbooks, approvals, notifications, outbound webhooks, SIEM/EDR webhook ingest, MISP/VT enrichment (mockable) |
| 10 | Hardening + validation | 20, 21.4, 22 | Sandboxed parser containers (no network, read-only), security tests, scans, perf benchmark, backup/restore, tool validation appendix |
| 11 | Docs + demo | 25 | README, user/admin guides, demo case loader + e2e smoke script, THIRD_PARTY.md, CHANGELOG, test/coverage/AI-eval reports |
