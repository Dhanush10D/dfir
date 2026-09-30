# PHASE 8: Reporting

## Goal
Turn a case into defensible, reproducible deliverables (guide 18, 8.4): technical, executive,
custody and IOC reports built from an immutable data snapshot, edited as Markdown sections and
evidence-cited findings, checked by a deterministic QA gate, approved by a second person (four
eyes), rendered to HTML and PDF plus STIX 2.1, CSV and JSON exports, and sealed with an Ed25519
signature over a manifest of artifact hashes. A signed report is frozen: it re-renders byte for
byte from its snapshot, its signature verifies against trust anchors outside the database, and
any change needs a new version. AI can draft a section (A4) through the Phase 7 pipeline; the
draft enters the report only after a person accepts it and is labelled "AI-drafted, approved by
<name>". Evidence items get a signed export package (manifest, custody chain, signature).

## In scope / Out of scope
In scope:
* `app/reports/`: snapshot builder, document model, HTML renderer (Jinja2, autoescape, safe
  Markdown), PDF renderer (ReportLab, deterministic), STIX 2.1 / CSV / JSON exporters, QA checks,
  manifest + signature, offline verifier (`python -m app.reports.verify`), evidence export package.
* `services/reports.py` (lifecycle, edits with optimistic concurrency, QA, approval, sign, verify,
  versions, downloads, AI draft apply), migration 0010, API, AI feature `report_draft` (A4).
* Frontend: Reports case tab (create, edit sections and findings, QA, submit/return/approve/sign,
  sandboxed preview, downloads, verification, AI drafts) and "Export package" on evidence.
* Tests, `docs/reports.md`, live smoke, verify script.

Out of scope (see `docs/BACKLOG.md`): DOCX output, custom report templates per organisation,
charts/graph images in reports (PNG rendering), PDF/A and font embedding for non-Latin scripts,
RFC 3161 time stamps on report signatures, custody anchors (needs the scheduler), background
render jobs, original evidence bytes inside the export package, A14 AI report QA (the
deterministic QA gate is in scope), report comments/review threads.

## Standard-profile decisions (made without the owner; recorded here)
1. **Snapshot first.** Creating a report builds `reports.context` from the case at that moment
   (case, evidence inventory with hashes and acquisition data, custody chains with verification
   results, alerts, key events = bookmarked or alert-linked events, IOCs, ATT&CK counts, entities,
   notes, accepted AI outputs, processing runs with parser and tool versions), with caps (500 key
   events, 500 alerts, 1000 IOCs, 200 notes; truncation is recorded in the snapshot). Its SHA-256
   (`context_sha256`) is stored; the snapshot never changes. "Later case changes create a new
   version": `POST /reports/{id}/versions` takes a new snapshot and copies sections and findings.
2. **Deterministic rendering.** HTML via Jinja2 (autoescape, StrictUndefined) and PDF via ReportLab
   platypus with `invariant=1` (fixed dates and ids), both from one document model; timestamps
   come from the snapshot, never the clock. The verifier re-renders from the snapshot and must get
   the same bytes. PDF uses the built-in Helvetica/Courier fonts (no embedding): characters outside
   Latin-1 are replaced and the PDF says so; the HTML and JSON artifacts keep the exact text.
3. **Safe Markdown.** Analyst and AI text is Markdown rendered with markdown-it-py (CommonMark,
   raw HTML disabled, links limited to http/https/mailto) into autoescaped templates; evidence
   strings are always escaped. For PDF, Markdown is reduced to paragraphs, lists and code blocks
   with ReportLab markup escaped. The UI shows previews in `<iframe sandbox srcdoc>` (no scripts,
   opaque origin); preview/download responses carry `Content-Security-Policy: default-src 'none';
   style-src 'unsafe-inline'; img-src data:; sandbox`.
4. **Lifecycle** `draft -> in_review -> approved -> signed` (and `in_review|approved -> draft` to
   rework). Editing (sections, findings, title) only in `draft`, with `expected_revision`
   (optimistic concurrency, 409 on a stale edit) under a row lock. Submit requires a passing QA
   run. Approve needs `approve` (lead/admin) and must be done by someone other than the submitter.
   Sign needs `approve`; it renders every artifact, stores them in the artifacts bucket, and seals
   them. All transitions lock the report row and re-check its state after the lock; closed cases
   are read-only. A DB trigger keeps `case_id`, `kind`, `version`, `family_id`, `context`,
   `context_sha256`, `created_by`, `created_at` immutable and freezes a `signed` row completely;
   the app role has no DELETE.
5. **QA gate (deterministic, guide 18.3 step 4).** Errors: a finding without an evidence
   reference, a reference that no longer exists in the case, empty required sections, TODO/TBD/
   FIXME/XXX markers, evidence without SHA-256, a custody chain that does not verify (technical
   and custody reports), an IOC report without IOCs. Warnings: alerts still `new`, truncated
   snapshot, unverified evidence. Stored in `reports.qa` with the revision it checked; submit
   requires a passing run on the current revision.
6. **Findings carry their own evidence.** A finding has title, Markdown body, confidence
   (low/medium/high), ATT&CK ids, and references (`event`, `alert`, `evidence`). On save the server
   checks every reference exists in the case and stores its label/time/summary with the finding,
   so the rendered report never depends on live data.
7. **Seal = manifest + signature.** `manifest = {report_id, family_id, version, case_number, kind,
   context_sha256, sections_sha256, artifacts: [{format, name, sha256, size}], signed_at,
   key_id}`; `reports.sha256` = SHA-256 of its canonical JSON; `reports.signature` = Ed25519 over
   that hex digest with the server signing key (the custody key). Verification trusts only the
   running signer and `CUSTODY_TRUSTED_KEYS_PATH`, never the database. `GET /reports/{id}/verify`
   recomputes artifact hashes from storage, the manifest hash, the signature, and re-renders from
   the snapshot. Artifacts live at `reports/{case}/{family}/v{n}/{name}` in the artifacts bucket.
8. **Artifacts per kind.** technical: `report.html`, `report.pdf`, `report.json`, `iocs.stix.json`,
   `iocs.csv`, `timeline.csv`; executive: html, pdf, json; custody: html, pdf, json,
   `custody.json`; ioc: html, json, `iocs.stix.json`, `iocs.csv`. CSV cells that start with
   `= + - @` (or tab/CR) are prefixed with `'` (formula injection).
9. **STIX 2.1 is generated, then validated.** The bundle (identity, TLP 1.0 markings, one
   `indicator` per active IOC with a STIX pattern, `attack-pattern` per technique with MITRE
   references, one `report`) uses UUIDv5 ids and snapshot timestamps, so it is deterministic.
   Tests parse it with the `stix2` library (dev dependency) to validate objects and patterns.
10. **A4 AI drafts reuse Phase 7.** `POST /ai/reports/{id}/draft {section}` runs feature
    `report_draft` (strong model) over a pack built from the snapshot's alerts and key events;
    output `{text, claims[{statement, cites}], limitations}` with citation validation. After the
    interaction is accepted (Phase 7 review), `POST /reports/{id}/sections/{name}/apply-ai
    {interaction_id}` copies it into the draft with `origin=ai_approved`, the reviewer's identity
    and the cited records. Only accepted `report_draft` interactions of the same case, report and
    section can be applied.
11. **Evidence export package (guide 8.4).** `POST /evidence/{id}/export-package` returns a ZIP
    with `manifest.json` (evidence metadata, hashes, acquisition, parser runs and tool versions,
    exporter, time), `custody.json` (full chain + verification result) and `manifest.sig`
    (Ed25519 over `sha256(manifest.json) + "\n" + sha256(custody.json)`, key id and public key
    PEM for convenience; trust still comes from the recipient's copy of the key). Originals are
    not included (they can be multi-GB; `GET /evidence/{id}/download` exists and the manifest
    carries their hashes). The export appends a custody entry `exported` with the package hash.
    `python -m app.reports.verify` checks a package or a report manifest offline.
12. **Synchronous rendering** with the snapshot caps (seconds for the capped sizes); background
    render jobs are backlog.

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/reports/snapshot.py` | `build_snapshot(session, case_id, *, principal_label, custody, limits) -> dict` |
| `backend/app/reports/model.py` | `SECTIONS` per kind, `Block` types, `build_document(report) -> list[Block]` |
| `backend/app/reports/markdown.py` | `md_to_html(text) -> Markup`, `md_blocks(text) -> list[MdBlock]` |
| `backend/app/reports/render_html.py`, `render_pdf.py`, `templates/report.html.j2` | renderers |
| `backend/app/reports/exports.py` | `stix_bundle(ctx, report_id)`, `iocs_csv`, `timeline_csv`, `report_json`, `csv_cell` |
| `backend/app/reports/qa.py` | `run_qa(kind, context, sections, findings, ref_check) -> QaResult` |
| `backend/app/reports/seal.py` | `canonical_json`, `build_manifest`, `manifest_sha256`, `verify_manifest_signature` |
| `backend/app/reports/package.py` | `build_evidence_package(...) -> bytes`, `verify_package(bytes, keys)` |
| `backend/app/reports/verify.py` | CLI: offline verification of a package ZIP or report manifest |
| `backend/app/services/reports.py` | `ReportService` |
| `backend/app/api/v1/reports.py`, `backend/app/schemas/reports.py` | API |
| `backend/app/ai/*` | feature `report_draft` (prompt, schema, spec) |
| `backend/alembic/versions/0010_reporting.py`, `backend/app/db/models/reports.py` | schema |
| `frontend/src/features/reports/*` | Reports tab; evidence "Export package" |
| `docs/reports.md` | report kinds, workflow, verification, exports |

## Data model changes (migration 0010)
`reports` + `title`, `family_id` (NOT NULL; the first version's id), `supersedes_id` (FK reports),
`revision` (int, edit counter), `sections` JSONB, `findings` JSONB, `context_sha256`, `qa` JSONB,
`updated_at`, `updated_by`, `submitted_by/at`, `approved_at`, `signed_by`, `signed_at`, `key_id`,
`manifest` JSONB; UNIQUE (`family_id`, `version`); CHECK kind in
(technical, executive, custody, ioc) and status in (draft, in_review, approved, signed); index
(`case_id`, `created_at`); trigger `reports_guard` (immutable columns, signed rows frozen, sections
and findings change only in draft). App role: SELECT, INSERT, UPDATE; no DELETE/TRUNCATE.

## API changes
| Method | Path | Access |
|---|---|---|
| POST/GET | `/cases/{id}/reports` | create: `investigate`; list: case read |
| GET | `/reports/{rid}` (`?include_context=true`) | case read |
| PATCH | `/reports/{rid}` `{expected_revision, title?, sections?, findings?}` | `investigate`, draft |
| POST | `/reports/{rid}/qa`, `/submit`, `/return`, `/approve`, `/sign`, `/versions` | as decision 4 |
| GET | `/reports/{rid}/preview` (text/html), `/download?format=`, `/verify` | case read |
| POST | `/reports/{rid}/sections/{name}/apply-ai` `{interaction_id}` | `investigate`, draft |
| POST | `/ai/reports/{rid}/draft` `{section}` | `ai:use` |
| POST | `/evidence/{id}/export-package` | `custody:view` (and case read) |

## Settings (new)
`REPORT_MAX_KEY_EVENTS=500`, `REPORT_MAX_ALERTS=500`, `REPORT_MAX_IOCS=1000`,
`REPORT_MAX_NOTES=200`, `REPORT_MAX_CONTEXT_MB=8`, `REPORT_ORG_NAME=dfirbench` (STIX identity
and report cover).

## Test plan
* Unit: snapshot shaping helpers; Markdown safety (raw HTML, `javascript:` links, images);
  HTML autoescape with hostile evidence strings; PDF determinism (same bytes twice, text
  extractable, non-Latin-1 replaced); STIX bundle validates with `stix2.parse` and is
  deterministic; CSV formula injection; QA rules each positive/negative; manifest canonical JSON
  and signature verify / tamper detection; package build + offline verify + tamper; verify CLI.
* Integration (compose Postgres, fake vault, fake AI provider): full lifecycle technical report
  (create -> edit -> QA fail -> fix -> submit -> self-approval refused -> approve -> sign ->
  verify ok -> download each artifact -> tamper an artifact in storage -> verify fails), stale
  edit 409, signed row frozen (trigger), new version, RBAC (viewer read-only, analyst cannot
  approve, outsider 404), closed case read-only, AI draft -> accept -> apply (labelled), reject
  path cannot be applied, custody and IOC kinds, evidence export package + custody `exported`
  entry, app-role grants, migration round trip.
* Live: `scripts/phase8-smoke.py` (API + MinIO artifacts bucket).

## Acceptance criteria (executable)
1. `pytest tests/unit/test_reports_*.py tests/integration/test_reports.py`
2. A signed report's `/verify` is ok: artifact hashes, manifest hash, Ed25519 signature (trusted
   keys only) and byte-identical re-render from the snapshot; tampering any artifact fails it.
3. QA blocks submission until every finding cites evidence and required sections are filled.
4. STIX bundle validates with `stix2`; CSV exports neutralize formulas.
5. Live: `scripts/phase8-smoke.py` prints `PHASE 8 SMOKE PASSED`.
6. Earlier phases: Phase 1-7 smokes, app-role denials, migration round trip, backend
   lint/format/type/bandit/tests, AI eval, frontend checks.

## Verification command
```bash
bash scripts/verify-phase8.sh
```
