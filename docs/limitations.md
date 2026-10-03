# Limitations and future work

dfirbench v0.1.0 is built to the **Standard profile** of the build guide: a single-host deployment
for a small team, run with Docker Compose. This page states plainly what it does not do, what is
only partly done, and what would come next. The item-by-item record, with the reason each item
was deferred, is [`docs/BACKLOG.md`](BACKLOG.md).

## What dfirbench is not

* **Not a court-certified tool.** It follows forensic practice (hashing, write-once storage,
  signed custody chains, tool validation in the spirit of NIST CFTT), but it has not been
  independently certified. Treat its output as one tool's result and cross-check important
  findings with a second tool, as with any forensic software.
* **Not an EDR or agent platform.** It has no endpoint agent. Response playbooks are guided
  checklists: actions such as "isolate host" or "disable account" are recorded as **not executed**
  and must be carried out and confirmed by a person.
* **Not a SIEM.** It analyses evidence for a case. It can receive signed webhooks from a SIEM or
  EDR, but it does not do continuous log collection or real-time monitoring.
* **Not a disk or memory acquisition tool.** The triage collectors gather files and live data;
  full disk and memory images are made with established tools (procedures in
  [`docs/collection.md`](collection.md)) and then uploaded.

## Current limitations

### Scale and operations

* **One host, one parse at a time.** All services run on one machine. The parser sandbox handles
  one job at a time (a deliberate isolation choice). Benchmarks on the 7.8 GB development laptop:
  about 24,000 log lines per second parsed, 3,200 events per second stored
  ([`validation/BENCHMARK.md`](validation/BENCHMARK.md)). Large disk images take hours, not minutes.
* **No scheduler.** There is no Celery beat service, so nothing runs on a timer: no automatic
  nightly re-verification, no periodic signed custody anchors, no reaper for stuck jobs or
  half-finished uploads. The integrity check is a command you can run from cron
  (`python -m app.cli integrity-check`), and stuck jobs can be cancelled and retried by hand.
* **Backups are full dumps** taken in a short maintenance window. There is no point-in-time
  recovery (WAL archiving) and no MinIO replication.
* **No built-in TLS.** The stack listens on `127.0.0.1` only. For use over a network, put a TLS
  reverse proxy in front ([`admin-guide.md`](admin-guide.md#8-tls-and-network-access)).
* **Secrets live in files and environment variables** (custody key, JWT secret, KEK). There is no
  integration with a secret manager, KMS or HSM.
* **Single-key rotation.** Rotating the JWT secret signs everyone out, and rotating the TOTP
  encryption key means users must enrol MFA again. Custody and integration keys can be rotated
  without losing data.

### Evidence and parsing

* **Supported formats** are listed in [`docs/parsers.md`](parsers.md): Windows event logs, Linux
  auth/syslog, journald JSON, wtmp/btmp, shell history, registry hives, Amcache, Prefetch, LNK,
  browser history, PE files, pcap/pcapng, raw/E01 disk images (file-system timeline), memory images
  (Volatility 3), YARA scans. Not yet: Jump Lists, ShellBags, SRUM, `$MFT` and `$UsnJrnl`, macOS
  artifacts, mobile and cloud logs, Sysmon-specific and DNS-log parsing.
* **Large forensic suites are not in the image** (Plaso, Hayabusa, Suricata, tshark, Zeek) because
  of image size and memory on the development host. Zeek works if an operator installs it.
* **Volatility needs symbol packs** for the memory image's operating system; they are not shipped
  (hundreds of MB).
* **Multi-segment images** (`.E01` + `.E02`, split raw) cannot be uploaded as one item.
* **Triage bundles are ZIP only**, and one oversized member rejects the whole bundle.
* **No file browser** for disk images (the file-system timeline is available; browsing and
  extracting single files is not).
* **The Windows collector cannot read locked files** (`$MFT`, a loaded `Amcache.hve` or
  `SRUDB.dat`, other users' loaded hives); collect those from a disk image.
* **Bundle unpacking runs in the worker**, not in the sandbox (bounded by size, count and ratio
  limits, but not isolated like parsing).

### Detection

* **25 built-in rules** (Linux SSH and account changes, Windows logons, services, tasks, log
  clearing, shadow-copy deletion, encoded PowerShell, anti-forensics detectors, IOC matching).
  Coverage: 14 ATT&CK techniques ([`detection-coverage.md`](detection-coverage.md)). Many guide
  rules wait for data sources that are not parsed yet (Sysmon, PowerShell script-block logs, DNS).
* **No statistical analytics** (beaconing, rare parent-child processes, DGA scoring,
  IsolationForest); detection is rule-based.
* **Every detection run rescans the whole case.** Correct and bounded, but slower on big cases.
* **No alert suppression or incident grouping** yet; alerts are deduplicated per rule and entity.
* **Sigma import is a strict subset** of the Sigma specification (documented modifiers only).

### AI features

* **The AI assists; it never decides.** Answers must cite the case's own records and are only
  "accepted" after a person reviews them. Even so, a model can misread evidence; read the cited
  records.
* **No live-model evaluation is included.** The offline evaluation measures dfirbench's
  validation pipeline with hand-written reference answers, not a specific model's quality.
  Running `python -m app.ai.eval --provider live` needs an API key.
* **Case chat search is lexical** (local hashing embeddings, no neural model), so it finds records
  by shared words, not by meaning. A neural embedding server can be configured.
* **Redaction is best effort** (regular expressions for e-mail addresses, secrets and optionally
  IPs, users and hosts); names inside free text are not recognised. Use `AI_LOCAL_ONLY=true` with a
  local model when data must not leave the host.
* **Single-question chat**: no conversation memory, no streamed answers.
* **The daily AI budget can be exceeded by a few calls** under concurrency (rate limits bound it).

### User interface

* **Some administration is API-only**: creating users, case membership, MFA enrolment, IOC import,
  API keys, detection rule management and on-demand detection runs. The interactive API docs at
  `/api/v1/docs` cover these ([`admin-guide.md`](admin-guide.md)).
* **No browser end-to-end tests** (Playwright); components are unit-tested and the API is tested
  live.
* **Simple charts and graph**: hand-written SVG histogram, ATT&CK heatmap and entity graph; no
  zoomable graph library, no virtualised event table (results load page by page).
* The in-app report preview is unstyled (the downloaded HTML and PDF are styled).

### Reports

* **No charts in reports** (tables carry the same data), no DOCX, no per-organisation templates.
* **PDFs use the built-in Helvetica and Courier fonts**: characters outside Windows-1252 are
  replaced (the PDF says how many); the HTML and JSON versions keep the exact text. Not PDF/A.
* **No RFC 3161 time stamps**: signatures prove integrity and the signer, not the time from an
  independent authority.
* Rendering is synchronous: a typical report takes seconds, a report at every size cap about a
  minute.

### Security model

* The sandbox shares the host kernel; a kernel exploit from a parser could escape it (gVisor or
  Kata Containers are a deployment option).
* Signed report artifacts are stored in a normal bucket: tampering is **detected** (hashes and
  signature) but not **prevented** like the WORM evidence bucket.
* API keys can be created without an expiry date.
* No container image signing (cosign) or build provenance yet.
* No single sign-on (OIDC/SAML) or WebAuthn; passwords with optional TOTP MFA only.

## Future work

In rough order of value:

1. **Scheduler service** (Celery beat): nightly integrity checks with notifications, signed custody
   anchors between backups, job and upload reapers.
2. **More data sources and rules**: Sysmon and PowerShell logs, DNS, `$MFT`/`$UsnJrnl`, Jump Lists,
   SRUM, with the ATT&CK rules that need them; Hayabusa and Plaso as optional engines.
3. **Admin screens**: users and membership, IOC import, rule management, MFA enrolment.
4. **Analytics**: beaconing, rare parent-child, DGA and anomaly scoring with scikit-learn.
5. **Live-model AI evaluation** with stored reports per prompt version, and AI-assisted report QA.
6. **Deployment hardening**: TLS proxy in compose, secret manager or KMS for keys, image signing,
   WAL archiving, a gVisor runtime for the sandbox.
7. **Scale-out**: several sandbox replicas, incremental detection, background report rendering,
   OpenSearch for very large cases (the guide's Full profile).
8. **Collaboration**: alert suppression and incident grouping, report review comments, SSO.
