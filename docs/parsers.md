# Parsers and forensic engines

Every parser implements `app/parsers/base.py` (guide 10.2): pure (no DB, no network, writes only in
the job scratch dir), streaming or size-bounded, hostile-input safe, UTC timestamps with the raw
value kept in `ts_original`, stable `record_key`s (idempotent reprocessing), and exact record
accounting (`records_read == events_emitted + skipped + errors`, checked by the runner). The run
manifest of every job records parser and engine versions, limits, assumptions and counts.

## Catalogue

| Parser | Input | Auto | Engine | Events (`source_type`) |
|---|---|---|---|---|
| `evtx` | `.evtx` | yes | python-evtx | Windows event records (`evtx`) |
| `linux_auth` | auth.log, secure, syslog | yes | own | SSH, sudo, account changes (`auth_log`, `syslog`) |
| `journal_json` | `journalctl -o json` | yes | own | journal entries, auth-classified (`journal`) |
| `wtmp` | wtmp / btmp / utmp | yes (by name) | own | boot, logon, logoff, failed logon (`wtmp`, `btmp`) |
| `shell_history` | `.bash_history`, `.zsh_history`, PSReadLine | yes (by name) | own | commands (`shell_history`) |
| `registry_hive` | SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat | yes | own regf reader | services, USB, ShimCache, BAM, Run keys, Winlogon, IFEO, Uninstall, UserAssist, RunMRU, TypedPaths/URLs (`registry`) |
| `amcache` | Amcache.hve | yes | own regf reader | files with SHA-1, programs, drivers (`amcache`) |
| `prefetch` | `.pf` v17-31, MAM | yes | own + LZXPRESS decoder | program runs (`prefetch`) |
| `lnk` | `.lnk` | yes | LnkParse3 | target created/modified/accessed (`lnk`) |
| `browser` | Chromium `History`, Firefox `places.sqlite` | yes | sqlite3 | visits, downloads, searches (`browser`) |
| `pe_static` | PE files | yes | pefile | one triage summary (`pe`) |
| `pcap` | pcap / pcapng | yes | dpkt | flows, DNS, HTTP requests, TLS SNI (`pcap`) |
| `tsk_fs` | raw / E01 disk images | yes | Sleuth Kit `mmls` + `fls` | MACB file-system timeline (`filesystem`) |
| `volatility` | memory images | yes (weak) | Volatility 3 `vol` | processes, command lines, connections (`memory`) |
| `yara_scan` | any file | **explicit** | yara-python | one event per matching rule (`yara`) |
| `zeek` | pcap / pcapng | **explicit** | Zeek (optional, not in the image) | conn/dns/http/ssl/notice (`zeek`) |

"Explicit" parsers are never auto-selected: `POST /evidence/{id}/process {"parsers": ["yara_scan"]}`.
Triage bundles (Phase 5) derive every verified member that an auto parser recognizes; after a
parser is added, `POST /jobs/{bundle_job}/reprocess` derives the newly recognized members and
reuses the ones derived before.

## Job parameters

| Parser | Parameter | Values |
|---|---|---|
| `linux_auth` | `timezone`, `year` | IANA zone; 1970-2100 |
| `tsk_fs` | `timezone` | IANA zone, passed to `fls -z` (FAT stores local time); default UTC |
| `volatility` | `os` | `windows` (default) or `linux` |
| `volatility` | `plugins` | windows: `info pslist psscan pstree cmdline netscan netstat dlllist svcscan malfind`; linux: `pslist pstree bash lsmod sockstat malfind`. Default windows `info pslist cmdline netscan`, linux `pslist bash` |

## Time handling

| Source | Epoch | `ts_original` |
|---|---|---|
| Registry, LNK, Prefetch, ShimCache, BAM | FILETIME (100 ns since 1601) | `filetime:<int>` |
| Chromium | WebKit microseconds since 1601 | `webkit:<int>` |
| Firefox | PRTime microseconds since 1970 | `prtime:<int>` |
| wtmp, shell history, pcap, Zeek, body files | Unix seconds | `unix:<value>` / `pcap_ts:` / `zeek_ts:` |
| journald | `__REALTIME_TIMESTAMP` microseconds | `unix_us:<int>` |
| Volatility | ISO 8601 from the JSON renderer | the string as rendered |
| PE | `TimeDateStamp` (Unix), when plausible | `pe_timedatestamp:<int>` |

A zero value means "not set" (the record is skipped); impossible values are errors. Records with
no intrinsic time (YARA matches, undated shell history, PE with an implausible compile time,
Volatility rows without a time column) use the evidence reference time (acquisition time, else
upload time) with `raw.ts_source = "reference:..."` and the tag `time_inferred`. MRU-style registry
lists only know the key's last-write time (true for the most recent entry): the other entries carry
`time_inferred` too.

## Limits (settings, `.env.example`)

| Setting | Default | Applies to |
|---|---|---|
| `PARSER_MAX_STRUCTURED_MB` | 1024 | hives, SQLite, PE (random-access formats are refused above it) |
| `PARSER_MAX_RECORDS` | 5 000 000 | every parser (run becomes `partial`) |
| `PARSER_SQLITE_TIMEOUT_S` | 600 | browser DB queries (progress handler) |
| `TOOL_TIMEOUT_S` / `TOOL_MAX_OUTPUT_MB` | 3600 / 1024 | each engine run (wall clock / stdout+stderr+log dir) |
| `YARA_TIMEOUT_S` / `YARA_MAX_FILE_MB` | 600 / 2048 | YARA scans |
| fixed | 16 MiB | Prefetch (compressed and declared decompressed), LNK |
| fixed | depth 64, 5 M keys, 16 MiB per value | registry reader |
| fixed | 200 000 flows | pcap flow table (`partial` beyond) |
| fixed | 256 MiB | Volatility JSON loaded per plugin |

## External engines

Engines run through `app/parsers/tools.py`: the binary is found by fixed name on
`TOOL_SEARCH_PATH` (else `PATH`); argv is a fixed list (`shell=False`); stdin is closed; the child
gets a clean environment (`PATH`, `HOME`/`TMPDIR` = job work dir, `LANG`, `TZ=UTC`; no database,
object-store or JWT secrets); it runs in its own process group inside the job's scratch work dir;
output size and wall clock are polled every 0.5 s and the job's cancel check runs at the same
time; the group is killed on timeout, overflow or cancel. The evidence is a read-only (0400)
scratch copy verified against the signed custody hash before parsing.

A missing engine fails the job with `unusable input: '<name>' is not installed in this worker
image (...)`.

| Engine | In the worker image | Version | Licence | How it is used |
|---|---|---|---|---|
| Sleuth Kit (`mmls`, `fls`) | yes (Debian bookworm apt) | 4.11.1+dfsg-1+b1 | IPL-1.0 / CPL-1.0 / GPL-2+ (parts) | separate program |
| Volatility 3 (`vol`) | yes (`/opt/dfir/vol3` venv) | 2.28.2 | Volatility Software License 1.0 | separate program, never imported; `--offline`; symbols via `VOLATILITY_SYMBOLS_DIR` |
| Zeek (`zeek`) | **no** (optional) | - | BSD-3-Clause | separate program if an operator installs it |

Installed versions are recorded at build time in `/opt/dfir/tool-versions.txt`
(`DFIR_TOOL_VERSIONS`) and copied into run manifests.

Volatility needs symbol tables (ISF) that match the image's kernel. They are not in the image
(hundreds of MB). Mount a symbol pack read-only and set `VOLATILITY_SYMBOLS_DIR`; without one,
Windows/Linux plugins fail with Volatility's "Unsatisfied requirement" message, which appears in
the job error / run manifest (`assumptions.plugins_failed`).

To add Zeek: build a derived worker image with Zeek on `PATH` (or mount it and set
`TOOL_SEARCH_PATH`), then request `{"parsers": ["zeek"]}`.

## Python libraries (licences)

| Library | Version | Licence | Used by |
|---|---|---|---|
| pefile | 2024.8.26 | MIT | `pe_static` |
| yara-python (bundles libyara) | 4.5.4 | Apache-2.0 (libyara BSD-3) | `yara_scan` |
| dpkt | 1.9.8 | BSD-3-Clause | `pcap` |
| LnkParse3 | 1.6.0 | MIT | `lnk` |
| python-evtx | 0.8.1 | Apache-2.0 | `evtx` |
| sqlite3 | stdlib | public domain (SQLite) | `browser` |

Evaluated and not used: regipy (MIT; reads whole hives into memory and loops forever on a crafted
big-data segment offset, so dfirbench has its own bounded regf reader), libscca/pyscca (LGPL, C)
and dissect.util (AGPL) for Prefetch decompression (own LZXPRESS Huffman decoder), Scapy (GPL-2).

## YARA rules

The packaged starter pack is `backend/app/detection/yara/*.yar` (reviewed, low-noise: EICAR,
Mimikatz strings, encoded PowerShell / download cradles, PHP webshell patterns, UPX). Operators add
rules through `YARA_RULES_DIR` (a read-only mount, `*.yar`/`*.yara`, non-recursive, symlinks
ignored). Rules are compiled with `include` disabled; the pack SHA-256 (namespaces + bytes) is in
every run manifest (`assumptions.rule_pack_sha256`). Rule text is never accepted through the API.

## Adding a parser

1. Implement the `Parser` protocol in `backend/app/parsers/<name>.py`, register it with
   `@register` and list the module in `registry.BUILTIN_MODULES`.
2. Account for every record (`ctx.stats.read/skip/error`), bound everything, convert times with
   `timeconv`, keep the raw value in `ts_original`.
3. Add a synthetic fixture (`backend/tests/fixtures/deep/make_fixtures.py`), a golden case in
   `tests/unit/test_parsers_deep_golden.py` (`DFIR_UPDATE_GOLDEN=1` regenerates), and a fuzz case in
   `tests/unit/test_parsers_deep_hostile.py`.
4. Parameters: add them to `PARSER_PARAMS` and `validate_params` in `app/services/jobs.py` and to
   `ProcessParams`.
