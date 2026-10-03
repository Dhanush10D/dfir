# Third-party software and data

dfirbench itself is released under the [MIT License](LICENSE). It depends on, bundles, or runs next
to the third-party components below, each under its own licence. Versions are the pinned ones in
`backend/pyproject.toml`, `frontend/package-lock.json`, `infra/compose.yaml` and
`infra/docker/*.Dockerfile` as of v0.1.0 (October 2026). Licence names come from each package's
metadata; the package's own licence text is authoritative.

This file is information, not legal advice. Check the licences again before any commercial
redistribution.

## Licences that need attention

| Component | Licence | What it means here |
|---|---|---|
| MinIO server (`pgsty/minio` community image) | AGPL-3.0 | Runs unmodified as a separate service (the evidence vault). If you modify MinIO and offer it over a network, you must publish your changes. dfirbench talks to it over the S3 API only. |
| Redis 7.4 (`redis:7.4-alpine`) | RSALv2 or SSPLv1 (source-available) | Fine for running it yourself inside your own deployment. Offering Redis itself as a managed service to third parties is restricted. Valkey (BSD-3-Clause) is a drop-in alternative. |
| psycopg / psycopg-binary 3.3.6 | LGPL-3.0-only | Used as an unmodified library (dynamically loaded). Replacing it with your own build is allowed by the LGPL. |
| Sleuth Kit 4.11.1 (worker image, Debian package) | IPL-1.0, CPL-1.0, GPL-2.0+ (parts) | Run as separate programs (`mmls`, `fls`); never linked into dfirbench. Debian's `libewf` (LGPL-3.0) comes with it. |
| Volatility 3 2.28.2 (worker image, own virtualenv) | Volatility Software License 1.0 | Run as a separate program (`vol --offline`); never imported. Read the VSL before redistributing images that contain it. |
| certifi | MPL-2.0 | Unmodified CA bundle used by HTTP clients. |

## Backend: Python runtime dependencies

Direct dependencies (pinned in `backend/pyproject.toml`) and everything they pull in at runtime:

| Package | Version | Licence |
|---|---|---|
| alembic | 1.20.0 | MIT |
| amqp | 5.4.0 | BSD |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anthropic | 1.9.0 | MIT |
| anyio | 4.15.1 | MIT |
| argon2-cffi | 25.1.0 | MIT |
| argon2-cffi-bindings | 26.1.0 | MIT |
| billiard | 4.3.0 | BSD |
| celery | 5.6.3 | BSD-3-Clause |
| certifi | 2026.7.22 | MPL-2.0 |
| cffi | 2.1.1 | MIT-0 |
| charset-normalizer | 3.5.2 | MIT |
| click | 8.5.0 | BSD-3-Clause |
| click-didyoumean | 0.3.1 | MIT |
| click-plugins | 1.1.1.2 | BSD |
| click-repl | 0.4.0 | MIT |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause |
| defusedxml | 0.7.1 | PSF-2.0 |
| docstring_parser | 0.18.0 | MIT |
| dpkt | 1.9.8 | BSD-3-Clause |
| fastapi | 0.141.1 | MIT |
| google-re2 | 1.1.20251105 | BSD-3-Clause (bundles RE2, BSD-3-Clause) |
| h11 | 0.16.0 | MIT |
| hexdump | 3.3 | Public domain |
| httpcore2 | 2.13.1 | BSD-3-Clause |
| httptools | 0.8.0 | MIT |
| httpx2 | 2.13.1 | BSD-3-Clause |
| idna | 3.20 | BSD-3-Clause |
| Jinja2 | 3.1.6 | BSD-3-Clause |
| jiter | 0.17.0 | MIT |
| kombu | 5.6.2 | BSD-3-Clause |
| LnkParse3 | 1.6.0 | MIT |
| Mako | 1.4.3 | MIT |
| markdown-it-py | 4.2.0 | MIT |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| minio (Python client) | 7.2.20 | Apache-2.0 |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| pefile | 2024.8.26 | MIT |
| pgvector (Python) | 0.5.0 | MIT |
| pillow | 12.3.0 | MIT-CMU |
| prompt_toolkit | 3.0.53 | BSD-3-Clause |
| psycopg, psycopg-binary | 3.3.6 | LGPL-3.0-only |
| pycparser | 3.0 | BSD-3-Clause |
| pycryptodome | 3.23.0 | BSD-2-Clause and public domain |
| pydantic | 2.13.5 | MIT |
| pydantic-core | 2.46.5 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| PyJWT | 2.15.0 | MIT |
| PyOTP | 2.10.0 | MIT |
| python-dateutil | 2.9.0.post0 | Apache-2.0 / BSD-3-Clause |
| python-dotenv | 1.2.3 | BSD-3-Clause |
| python-evtx | 0.8.1 | Apache-2.0 |
| PyYAML | 6.0.3 | MIT |
| redis (Python client) | 8.1.0 | MIT |
| reportlab | 5.0.1 | BSD-3-Clause |
| six | 1.17.0 | MIT |
| sniffio | 1.3.1 | MIT OR Apache-2.0 |
| SQLAlchemy | 2.1.1 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| structlog | 26.1.0 | MIT OR Apache-2.0 |
| truststore | 0.10.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| typing-inspection | 0.4.4 | MIT |
| tzdata | 2026.4 | Apache-2.0 (IANA tz data: public domain) |
| tzlocal | 5.4.4 | MIT |
| urllib3 | 2.8.0 | MIT |
| uvicorn | 0.54.0 | BSD-3-Clause |
| uvloop (Linux images only) | per uvicorn[standard] | MIT OR Apache-2.0 |
| vine | 5.1.0 | BSD-3-Clause |
| watchfiles | 1.3.0 | MIT |
| wcwidth | 0.9.1 | MIT |
| websockets | 17.1 | BSD-3-Clause |
| yara-python | 4.5.4 | Apache-2.0 (bundles libyara, BSD-3-Clause) |

Development and test tools (not shipped in the images): pytest, pytest-cov, hypothesis, ruff, mypy,
bandit, celery-types, stix2 (BSD-3-Clause), type stubs. All MIT, BSD, Apache-2.0 or MPL-2.0.
The security scan (`scripts/scan.sh`) downloads gitleaks (MIT), pip-audit (Apache-2.0), Trivy
(Apache-2.0) and CycloneDX tools (Apache-2.0) into `var/scan/` when it runs; they are not part of
the product.

## Frontend

Shipped in the browser bundle:

| Package | Version | Licence |
|---|---|---|
| react | 19.3.0 | MIT |
| react-dom | 19.3.0 | MIT |
| scheduler (React dependency) | 0.28.0 | MIT |
| @tanstack/react-query | 5.104.0 | MIT |
| @tanstack/query-core | 5.104.0 | MIT |
| Tailwind CSS (generated stylesheet) | 4.3.3 | MIT |

Build and test tools only (not shipped): Vite, TypeScript, ESLint and plugins, Vitest, jsdom,
Testing Library, `@tailwindcss/vite`, `@vitejs/plugin-react`, type packages. All MIT, Apache-2.0
or BSD. `npm audit --audit-level=high` reports no vulnerabilities (see
[`docs/validation/TEST_REPORT.md`](docs/validation/TEST_REPORT.md)).

## Container images and system software

All images are pinned by tag and multi-arch digest in `infra/compose.yaml` and the Dockerfiles.

| Image / software | Used for | Licence |
|---|---|---|
| `pgvector/pgvector:0.8.6-pg16-bookworm` | PostgreSQL 16 with the pgvector extension | PostgreSQL License (both) |
| `redis:7.4-alpine` | Celery broker, rate limits | RSALv2 / SSPLv1 (see above) |
| `pgsty/minio:RELEASE.2026-08-04T00-00-00Z` | S3 evidence vault with Object Lock | AGPL-3.0 (see above) |
| `python:3.12-slim-bookworm` | Base of the api, worker and parser-sandbox images | PSF-2.0 (Python); Debian packages under their own free licences |
| `nginxinc/nginx-unprivileged:1.28-alpine` | Web server and reverse proxy for the UI | BSD-2-Clause (nginx) |
| `node:24-alpine` | Build stage of the web image only | MIT (Node.js) |
| Sleuth Kit `4.11.1+dfsg-1+b1` (Debian apt) | `tsk_fs` parser | IPL-1.0 / CPL-1.0 / GPL-2.0+ |
| Volatility 3 2.28.2 (hash-pinned pip install) | `volatility` parser | Volatility Software License 1.0 |
| Zeek (optional, **not** in the images) | `zeek` parser if an operator installs it | BSD-3-Clause |

## Data and content

| Item | Source | Licence / terms |
|---|---|---|
| MITRE ATT&CK technique ids and tactic names (`backend/app/detection/attack.py`, rule metadata, UI heatmap) | [MITRE ATT&CK](https://attack.mitre.org/) | ATT&CK Terms of Use: © The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. |
| Test fixtures `backend/tests/fixtures/evtx/new_user_security.evtx` and `security_short_selected.evtx` | Byte-identical copies of samples in [omerbenamram/evtx](https://github.com/omerbenamram/evtx) | MIT / Apache-2.0 |
| EICAR test string in the YARA starter rule `EICAR_Test_File` | [EICAR](https://www.eicar.org/download-anti-malware-testfile/) | Freely usable test string |
| All other fixtures, the demo evidence (`data/demo/`) and the AI evaluation datasets | Generated by scripts in this repository | MIT (part of dfirbench); synthetic, no real personal data |
| Common-password list (`backend/app/core/data/common-passwords.txt`) | Written for this project as a stand-in for a breached-password API | MIT (part of dfirbench) |
| Detection rules (`backend/app/detection/builtin/`), YARA starter rules, playbooks | Written for this project | MIT (part of dfirbench). Sigma *format* support only; no Sigma rules are copied. |

## Services you may connect (optional)

None of these are contacted unless an administrator configures them; each has its own terms:
Anthropic API (or another OpenAI-compatible / Ollama model server) for AI features, VirusTotal
and MISP for indicator enrichment, Slack, Microsoft Teams and SMTP for notifications, and any
SIEM/EDR that sends signed webhooks.
