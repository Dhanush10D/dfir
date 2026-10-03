# Test and quality report

What was tested, how, and the results, for dfirbench v0.1.0 (commit `55bac80` plus the Phase 11
documentation changes). Measured on 3 October 2026 on the development laptop described in
[`BENCHMARK.md`](BENCHMARK.md) (Intel Core i3-N305, 7.8 GB RAM, Windows 11, Docker Desktop with
the compose stack providing PostgreSQL, Redis and MinIO).

## Summary

| Area | Result |
|---|---|
| Backend unit tests | **1,114 passed**, 4 skipped (POSIX-only checks; they run on Linux CI) |
| Backend integration tests (real PostgreSQL 16, Redis, MinIO) | **312 passed**, 0 skipped |
| Backend coverage (unit + integration, line and branch) | **91.3 % of lines**, **80.9 % of branches**, 89.1 % combined (CI gate: 80 %) |
| Frontend tests (Vitest + Testing Library, 13 files) | **116 passed** |
| Offline AI evaluation (6 suites) | **all targets met** (table below) |
| Demo end-to-end check (`scripts/demo-check.py`) | **passed**: 4 uploads, 8 jobs, 10 expected alerts, 3 reports signed and verified |
| Dependency audits | pip-audit: no known vulnerabilities; `npm audit --audit-level=high`: 0 vulnerabilities |
| Static checks (CI on every push) | ruff (lint + format), mypy (strict typing of `app/`), bandit, ESLint, `tsc` |
| Secrets scan | gitleaks over the full history of `main`: clean |
| Performance floors | all met (see [`BENCHMARK.md`](BENCHMARK.md)) |

## How to reproduce

```bash
cd backend
.venv/Scripts/python -m pytest tests/unit -q --cov=app --cov-branch                 # unit
.venv/Scripts/python -m pytest tests/integration -q --cov=app --cov-branch --cov-append  # needs the compose stack
.venv/Scripts/python -m coverage report
.venv/Scripts/python -m app.ai.eval                                                # offline AI evaluation
cd ../frontend && npm test && npm audit --audit-level=high
bash scripts/scan.sh                                                               # gitleaks, pip-audit, npm audit, Trivy, SBOMs
```

On a laptop with little free memory, run the integration tests in two halves (as was done for
this report): a full run in one go can be killed by the OS when other applications are open.

## Test layers

| Layer | Where | What it proves |
|---|---|---|
| Unit | `backend/tests/unit/` (48 test files) | Parsers against golden files, hostile-input and fuzz cases (zip bombs, cyclic registry hives, truncated pcaps, oversized fields), the search language, the rule engine, Sigma import, scoring, the AI sanitizer, validators and decoder, report rendering (byte-identical re-renders), STIX/CSV safety, the crypto of backups, the sandbox protocol |
| Integration | `backend/tests/integration/` (22 test files) | The API against a throwaway PostgreSQL database with the real migrations and triggers: RBAC across five roles and case isolation (404 for outsiders), append-only custody and audit tables, tamper detection, MinIO Object Lock, concurrent uploads, jobs, detection, reports with four-eyes approval, response approvals, integrations, provisioning of the least-privilege database role |
| Frontend | `frontend/src/**/*.test.tsx` | Login and MFA, RBAC-dependent controls, evidence upload, the timeline explorer, AI result cards (citations, accept/reject), the response tab |
| Live smoke | `scripts/phase*-smoke.py` | The running compose stack end to end: upload, tamper demo, parsing, detection, AI with the offline provider, reports, response, the parser sandbox (no network, read-only, no capabilities), security headers. CI runs the Phase 1-3, 7, 9 and 10 smokes on every push |
| Demo check | `scripts/demo-check.py` | The demo evidence in `data/demo/` still produces the documented alerts and signed reports |
| Validation | [`TOOL_VALIDATION.md`](TOOL_VALIDATION.md) | Every parser on known inputs with recorded output hashes; every built-in rule with a positive and a near-miss negative case; each integrity requirement mapped to its test |

## Coverage by package

Combined unit and integration run (line coverage, then branch coverage):

| Package | Statements | Lines | Branches | Notes |
|---|---|---|---|---|
| `api` | 1,076 | 99.4 % | 92.9 % | Routers |
| `schemas` | 1,346 | 99.9 % | 78.6 % | Pydantic models |
| `db` | 1,000 | 99.8 % | 86.4 % | Models, provisioning |
| `response` | 213 | 99.1 % | 98.1 % | Playbook schema and registry |
| `analysis` | 473 | 97.0 % | 89.1 % | Entities, process tree |
| `core` | 784 | 96.9 % | 93.2 % | Security, signing, permissions |
| `ops` | 272 | 96.7 % | 88.9 % | Backup encryption, benchmark |
| `collection` | 461 | 96.1 % | 88.5 % | Bundle verification |
| `ai` | 1,914 | 95.0 % | 87.9 % | Gateway, sanitizer, validators, RAG |
| `search` | 408 | 94.9 % | 88.8 % | Search language and SQL compiler |
| `integrations` | 992 | 94.8 % | 89.6 % | Webhooks, outbound policy, enrichment |
| `reports` | 934 | 94.1 % | 86.2 % | Snapshot, rendering, sealing, verification |
| `services` | 7,098 | 90.1 % | 78.2 % | Business logic |
| `repositories` | 100 | 89.0 % | 41.7 % | Vault access (error branches need a failing MinIO) |
| `detection` | 1,870 | 88.1 % | 76.7 % | Rule engine, detectors, IOC matching |
| `parsers` | 3,732 | 87.8 % | 77.7 % | 16 parsers (tool wrappers are tested with fake engines) |
| `sandbox` | 962 | 79.9 % | 73.9 % | The Linux-only parts (uid switch, `/proc` sweep, signals) run in the container and are proven by `phase10-smoke.py`, not counted here |
| `workers` | 211 | 55.9 % | 42.9 % | Celery task wrappers run inside the worker container; their logic lives in `services/` and is covered there, and the live smokes exercise them |
| top level (`main`, `config`, `cli`, `storage`) | 627 | 75.6 % | 75.0 % | CLI commands are exercised by the verify scripts |
| **Total** | **24,473** | **91.3 %** | **80.9 %** | |

## AI evaluation (offline)

`python -m app.ai.eval` with the packaged datasets. The reference answers are hand-written, so these
numbers measure dfirbench's pipeline (prompt rendering, schema and citation validation, the
decoder, the prompt-injection defences), not the quality of a particular model. See
[`docs/ai.md`](../ai.md#evaluation-harness).

| Suite | Items | Metric | Result | Target |
|---|---|---|---|---|
| nlq (plain-language search) | 50 + 5 bad replies | query validity | 1.00 | ≥ 0.95 |
| | | AST match with the expected query | 1.00 | ≥ 0.90 |
| | | bad replies rejected | 1.00 | 1.00 |
| alerts (explanations) | 30 + 4 fabricated | assessment accuracy | 0.93 | ≥ 0.80 |
| | | citation validity of accepted outputs | 1.00 | 1.00 |
| | | fabricated citations rejected | 1.00 | 1.00 |
| narrative | 6 stories | key-event coverage | 1.00 | ≥ 0.80 |
| | | ordering correct | 1.00 | 1.00 |
| chat (RAG) | 10 | answered / insufficient accuracy | 1.00 | ≥ 0.90 |
| scripts (decoder + A7) | 30 | indicator recall / precision | 1.00 / 1.00 | ≥ 0.90 |
| | | ATT&CK hint recall | 1.00 | ≥ 0.80 |
| injection | 30 adversarial samples | attack success rate (delimiter-respecting model) | 0.00 | 0.00 |
| | | manipulated outputs caught (obey-anything model) | 1.00 | 1.00 |
| | | warning rate | 1.00 | 1.00 |

A run against a real model (`python -m app.ai.eval --provider live --record replies.json`) needs an
API key and was not part of this report; see [`docs/limitations.md`](../limitations.md).

## Detection on the demo evidence

`scripts/demo-check.py` against `data/demo/evidence/` (one brute-force-to-exfiltration story):

| Rule | Alerts | Correct? |
|---|---|---|
| DFIR-LNX-0001 SSH brute force | 1 | yes: 24 failures in 4 minutes from one address |
| DFIR-LNX-0002 SSH success after failures | 1 | yes: the 02:14:05 login, 25 linked events |
| DFIR-LNX-0003 Root login over SSH | 1 | yes |
| DFIR-LNX-0004 New Linux user created | 1 | yes: `backupsvc` |
| DFIR-LNX-0011 User added to a privileged group | 1 | yes: `backupsvc` to `sudo` |
| DFIR-IOC-0001 IOC match | 5 | yes: both IPs and both domains (the attacker IP once for log events, once for packet flows) |
| False positives | 0 | the admin's normal logins and cron sessions raise nothing |

The rule-by-rule positive and negative scenarios for all 25 built-in rules are in
[`TOOL_VALIDATION.md`](TOOL_VALIDATION.md); the ATT&CK coverage table is
[`docs/detection-coverage.md`](../detection-coverage.md).

## Security checks

| Check | Tool | Result |
|---|---|---|
| Python dependencies (frozen backend set) | pip-audit | no known vulnerabilities |
| npm dependencies | `npm audit --audit-level=high` | 0 vulnerabilities |
| Secrets in git history | gitleaks (whole history of `main`) | clean |
| Images | Trivy on the api and worker images (gate: fixable CRITICAL in language packages) | passes in CI; OS findings listed in `var/scan/trivy-*.txt` |
| SBOM | CycloneDX for the Python environment, npm and both images | generated by `scripts/scan.sh` |
| Python static security | bandit | clean (reviewed exceptions annotated in code) |
| Sandbox proof | `phase10-smoke.py` | no network, read-only root and evidence, no capabilities, separate uid for parsers |

## Known gaps

* No browser end-to-end tests (Playwright); UI behaviour is covered by component tests and the
  live API smokes.
* No live-model AI evaluation in this report.
* Coverage of the Celery wrappers and the Linux-only sandbox paths is proven by live smokes rather
  than counted by coverage.
* Performance numbers come from one laptop; see the notes in [`BENCHMARK.md`](BENCHMARK.md).
