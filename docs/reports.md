# Reports and evidence export packages (Phase 8)

Reports are forensic work products. dfirbench builds them from a frozen data snapshot, has them
checked by a deterministic QA gate and approved by a second person, then signs them. A signed report
re-renders byte for byte from its snapshot, and anyone holding the custody public key can verify it
offline. This page covers the report kinds, the workflow, what gets recorded, how to verify a
report, and the evidence export package.

## Report kinds and artifacts

| Kind | Audience | Artifacts |
|---|---|---|
| `technical` | IR team, engineers | `report.html`, `report.pdf`, `report.json`, `iocs.stix.json`, `iocs.csv`, `timeline.csv` |
| `executive` | Management | `report.html`, `report.pdf`, `report.json` |
| `custody` | Legal, auditors | `report.html`, `report.pdf`, `report.json`, `custody.json` |
| `ioc` | Other teams, partners | `report.html`, `report.json`, `iocs.stix.json`, `iocs.csv` |

Each kind has its own editable sections (Markdown). The required ones are marked in the UI and
enforced by QA. The technical report follows guide 18.2. It contains the executive summary, scope,
methodology (pre-filled, editable), tools and processing runs, the evidence inventory, the timeline
of key events, findings, affected assets, IOCs, ATT&CK techniques, root cause, impact, actions,
lessons learned, limitations, and appendices for the custody summary, alerts, and report provenance.

## Workflow

```
create (snapshot) -> edit -> QA -> submit -> approve (another person) -> sign -> verify
                         ^           |            |
                         +-- return to draft -----+
```

1. **Create** (`investigate`): `POST /cases/{id}/reports {kind, title?}` takes the snapshot. The
   snapshot holds the case, the evidence inventory with hashes and acquisition data, each custody
   chain with its verification result, alerts, key events (bookmarked or alert-linked), active IOCs,
   ATT&CK counts, processing runs with parser and tool versions, and accepted AI outputs. The
   snapshot is capped (`REPORT_MAX_*`), and any truncation is recorded. It stores
   `input_hashes` (the SHA-256 of each included part) and its own hash, `context_sha256`. The
   snapshot never changes; a later state of the case needs a new version
   (`POST /reports/{id}/versions`). Case notes are not copied: they are internal working material,
   and findings carry the analyst's statements.
2. **Edit** (`investigate`, draft only): `PATCH /reports/{id}` with `expected_revision`. A stale
   revision returns 409. Findings carry a title, a Markdown body, a confidence level, ATT&CK ids,
   and references (`event`, `alert`, `evidence`). The server checks that every reference exists
   *in this case* and stores its label, time and summary with the finding.
3. **QA** (`POST /reports/{id}/qa`, re-run automatically on submit). QA fails on any of these
   errors:
   - an empty required section
   - `TODO`, `TBD`, `FIXME` or `XXX` markers
   - a finding without evidence, or with a reference that no longer exists
   - evidence without a SHA-256, or a custody chain that does not verify (technical and custody
     reports)
   - an IOC report without IOCs

   Warnings (untriaged alerts, a truncated snapshot, evidence not verified, AI-drafted content)
   are shown but do not block submission.
4. **Submit** (`investigate`) -> **approve** (`approve`: lead or admin). The approver must be a
   different person from the submitter (four eyes). A database trigger enforces this too.
   **Return to draft** needs `approve`; the submitter can also withdraw while the report is in
   review.
5. **Sign** (`approve`) renders every artifact from the snapshot and stores it under
   `reports/{case}/{family}/v{n}/` in the artifacts bucket. It then builds the manifest (below),
   stores its SHA-256, and signs that with the custody Ed25519 key. The signed row is frozen by a
   database trigger.

Closed cases are read-only: create, edit, QA, transitions and new versions all return 409.
Reading, previewing, downloading and verifying still work. Sign reports before closing a case.
The evidence export package also works on a closed case (like `GET /evidence/{id}/download`):
handing evidence over after closure is a normal step, and it is recorded in custody.

### Manifest and signature

```json
{"schema": "dfirbench.report-manifest/1", "report_id": "...", "family_id": "...", "version": 1,
 "case_id": "...", "case_number": "IR-2026-0001", "kind": "technical",
 "context_sha256": "...", "content_sha256": "...", "render_meta": {"...": "cover data"},
 "artifacts": [{"name": "report.pdf", "format": "pdf", "content_type": "application/pdf",
                "sha256": "...", "size": 12345}],
 "signed_at": "2026-09-30T11:05:00Z", "key_id": "ed25519-..."}
```

- `reports.sha256` is the SHA-256 of the canonical JSON of the manifest (sorted keys, no
  whitespace, UTF-8).
- `reports.signature` is an Ed25519 signature over that hex digest (ASCII).
- `content_sha256` is the hash of the edited title, sections and findings.
- `render_meta` freezes the cover data (author, approver, signer, times), so re-rendering does not
  depend on live user names.

The audit log records `report.create` (with the snapshot hash and input hashes), every edit
(`report.update` with the content hash), `report.qa`, `report.submit`, `report.return`,
`report.approve`, `report.sign` (manifest hash and every artifact hash), `report.download` (hash of
the bytes served, also for draft previews), `report.verify` and `report.apply_ai`. Report
generation never reads or changes evidence bytes.

## Verification

`GET /reports/{id}/verify` (case read access) checks the following:

- the manifest hash and the Ed25519 signature. Only the running signer and the keys in
  `CUSTODY_TRUSTED_KEYS_PATH` are trusted; keys stored in the database are never trusted.
- that the stored snapshot and content still match `context_sha256` and `content_sha256`.
- that every stored artifact still has the SHA-256 listed in the manifest.
- that re-rendering every artifact from the snapshot gives identical bytes.

A download of a signed artifact whose stored bytes no longer match the manifest is refused
(409 `artifact_tampered`).

### Offline verification

Download `seal.json` (`?format=seal`) and the artifacts into one directory, then run:

```bash
cd backend
python -m app.reports.verify report ./out/seal.json --dir ./out --keys trusted.json
# or with a single public key PEM:
python -m app.reports.verify report ./out/seal.json --public-key custody.pub.pem --key-id ed25519-...
```

`trusted.json` has the format of `CUSTODY_TRUSTED_KEYS_PATH` (`{"key_id": "PEM"}`). The public key
PEM inside `seal.json` is only there for convenience and is never trusted by itself. The command
exits with 0 when the report verifies, 1 when it does not, and 2 on a usage error. Every artifact
listed in the manifest must be in the directory (`artifact_missing` otherwise); `--partial` checks
only the files present. The output lists `artifacts_checked` and `artifacts_total`. A seal or
package whose JSON is not the expected object fails as `malformed`.

## Output safety

All evidence-derived text is treated as hostile in every output format.

- **HTML**: Jinja2 with autoescape and StrictUndefined. Markdown goes through markdown-it-py
  (CommonMark) with raw HTML disabled, images disabled, and links limited to `http`, `https` and
  `mailto` (`rel="noopener noreferrer nofollow"`). The page uses inline CSS only and loads nothing
  external. It carries its own CSP meta tag, and the API sends
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; ...;
  sandbox`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. The UI shows previews
  only in `<iframe sandbox srcdoc>` (no scripts, opaque origin) and never uses
  `dangerouslySetInnerHTML`.
- **PDF**: ReportLab platypus (pinned), with every value XML-escaped before it reaches paragraph
  markup. There are no links, images, JavaScript, forms or embedded files. ReportLab's
  `trustedSchemes` and `trustedHosts` are emptied, so the renderer cannot fetch a URL or read a
  local file named by evidence text. The PDF uses the built-in Helvetica and Courier fonts, and
  `invariant=1` makes it deterministic. Characters outside Windows-1252 are replaced with `?`, and
  the PDF says how many were replaced; the HTML and JSON keep the exact text. Table cells and long
  unbroken tokens are shortened or broken, so hostile values cannot break the layout.
- **CSV**: every cell goes through `app/core/csvsafe.py` (the same guard as the timeline export).
  A leading `= + - @`, tab, CR or LF, or their full-width forms, gets a `'` prefix.
- **STIX 2.1**: pattern literals are escaped (backslash and single quote). Ids are UUIDv5 values
  scoped to the report, and timestamps come from the snapshot. Tests validate each bundle with the
  OASIS `stix2` library. TLP 2.0 values map to the TLP 1.0 markings STIX defines; `AMBER+STRICT`
  maps to the stricter RED.
- **JSON**: `json.dumps` with sorted keys; no evaluation.

Size and time limits: the snapshot caps (`REPORT_MAX_KEY_EVENTS=500`, `REPORT_MAX_ALERTS=500`,
`REPORT_MAX_IOCS=1000`, `REPORT_MAX_CONTEXT_MB=8`), 50 000 characters per section, 200 findings with
up to 50 references each, and 20 000 characters per finding body. Rendering runs in the request.
A typical report renders in a few seconds. A report at every cap (500 alerts, 500 key events and
1000 IOCs as PDF tables plus the maximum text) takes about a minute on a small host, so the PDF
renderer has two more limits: at most 2000 pages, and `REPORT_RENDER_TIMEOUT_S` (default 120 s,
checked on every new page; kept below the web proxy's 300 s read timeout). Exceeding either
returns 413 `report_too_large` for sign and draft downloads (the report stays in its state).
`GET /reports/{id}/verify` shares one budget across all its re-renders and reports
`rerender_limit` for the artifacts it could not re-render in time. The check never changes the output, so a render that
finishes is still byte-for-byte reproducible.

## AI-drafted sections (A4)

`POST /ai/reports/{id}/draft {section}` (`ai:use`, draft reports, only sections marked
`ai_draft`) runs the Phase 7 pipeline with the feature `report_draft` (strong model). The pack is
built from the report snapshot's alerts and key events. The output `{text, claims[{statement,
cites}], limitations}` must pass schema and citation validation, and every cited record must exist
in the case.

The draft does nothing until a person accepts it (`POST /ai/interactions/{id}/review`). Then
`POST /reports/{id}/sections/{section}/apply-ai {interaction_id, expected_revision}` copies it into
the section. Only an accepted, valid `report_draft` interaction of the same case, report and
section can be applied. The section then records `origin: ai_approved` with the interaction id,
reviewer, review time, model, prompt version and output hash. The rendered report labels it
"AI-drafted, approved by <name> ...", and the provenance appendix lists every AI contribution. If
an analyst later edits the text, the label says so (`ai_edited`).

## Evidence export package (guide 8.4)

`POST /evidence/{id}/export-package` (`custody:view` on the case) returns
`<label>_package.zip`:

| Member | Content |
|---|---|
| `manifest.json` | evidence metadata, hashes (SHA-256, MD5, expected), acquisition data, vault version id, processing runs with their run manifests (parser and tool versions), custody head, exporter and time |
| `custody.json` | the full custody chain (every field needed to recompute entry hashes and check signatures) and its verification result |
| `manifest.sig` | Ed25519 over `sha256(manifest.json) + "\n" + sha256(custody.json)`, the key id, and the public key PEM for convenience |

Original bytes are not included: images can be many GB, and `GET /evidence/{id}/download`
provides them with its own custody entry, while the manifest carries their hashes. Each export
appends an `exported` custody entry with the package SHA-256 and writes an audit record. The ZIP is
deterministic (fixed member order and timestamps). To check a package offline:

```bash
python -m app.reports.verify package EV-001_package.zip --keys trusted.json
```

This checks the member hashes, the signature (trusted keys only) and the custody chain inside the
package (hash links and every entry signature). The verifier reads only the three fixed member
names and caps their size.

## Database

Migration `0011_reporting` extends `reports` with these columns: `title`, `family_id`,
`supersedes_id`, `revision`, `sections`, `findings`, `context_sha256`, `qa`,
`updated_*`/`submitted_*`/`approved_at`/`signed_*`, `key_id` and `manifest`.

- The app role has SELECT, INSERT, and UPDATE of the workflow columns only. It cannot UPDATE the
  identity or snapshot columns, and it has no DELETE.
- The `reports_guard` trigger (BEFORE INSERT OR UPDATE) enforces these rules:
  - new rows are unreviewed drafts
  - identity and snapshot columns are immutable
  - sections, findings and title change only in draft
  - only the lifecycle transitions shown above are allowed
  - the approver differs from the recorded submitter; the submitter columns change only on submit
    or return, the approver columns only on approve or return, and the signer and seal columns
    only on sign, which needs a four-eyes approval and a named signer
  - signed rows are frozen
- CHECKs `submitted` (a non-draft report names its submitter) and `four_eyes` (an approved or
  signed report names an approver other than the submitter) hold even with triggers bypassed.
- CHECK `signed_sealed` requires a signed row to carry its hash, signature, manifest, key id and
  time.
- Downgrading 0011 drops the review trail and the seal columns, so it returns every report to an
  unreviewed, unsealed draft (status, approver, storage URI, hash and signature cleared). The
  snapshot, sections and findings are kept. After a later upgrade, a report has to go through QA,
  review and signing again. The downgrade leaves artifacts in the bucket alone, but signing again
  writes the same `v{n}/` prefix and replaces them; the `report.sign` audit record keeps the old
  hashes (write-once artifact keys are in the backlog).

## Deliberate deviations from the guide

- **PDF**: ReportLab instead of WeasyPrint. ReportLab is pure Python, needs no system libraries,
  is deterministic with `invariant=1`, and has no HTML fetcher that evidence content could steer.
  The PDF is built from the same document model as the HTML.
- **Out of scope for now**: charts in reports, DOCX, PDF/A with embedded fonts, per-organisation
  templates, RFC 3161 time stamps, and background render jobs. See `docs/BACKLOG.md`.
