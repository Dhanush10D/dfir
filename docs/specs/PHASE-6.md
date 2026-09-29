# PHASE 6: Deep parsers

## Goal
Turn the Windows and Linux artifacts that the Phase 5 collectors already gather, plus disk images,
memory images, packet captures and suspicious files, into normalized timeline events (guide 10,
10.3 catalogue, 11.4). Every new parser follows the Phase 2 contract (`app/parsers/base.py`): pure,
streaming or bounded, hostile-input safe, UTC timestamps with the original value kept, stable
record keys, and `records_read == events_emitted + skipped + errors`. External engines run through
one wrapper with a fixed argv, a timeout, an output cap, a clean environment and outputs only in
the job scratch dir. A bundle reprocess derives the members these parsers now recognize.

## In scope / Out of scope
In scope (parser name -> input):
* `browser` -> Chrome/Edge/Chromium `History`, Firefox `places.sqlite` (visits, downloads, searches)
* `registry_hive` -> SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat (curated artifacts, see below)
* `amcache` -> `Amcache.hve` (InventoryApplicationFile / InventoryApplication /
  InventoryDriverBinary, legacy `Root\File`)
* `prefetch` -> `.pf` versions 17/23/26/30/31, including Win10+ MAM (LZXPRESS Huffman) compression
* `lnk` -> Windows shortcut files (`.lnk`)
* `pe_static` -> PE triage (headers, sections + entropy, imports, imphash, suspicious APIs, signature
  presence, overlay)
* `yara_scan` -> YARA scan of any evidence item with the trusted rule pack
* `pcap` -> pcap/pcapng flows, DNS, HTTP requests and TLS SNI (pure Python, `dpkt`)
* `zeek` -> Zeek wrapper for pcaps (optional engine)
* `tsk_fs` -> Sleuth Kit file system timeline (`mmls` + `fls -r -m`) for raw/E01 disk images
* `volatility` -> Volatility 3 wrapper (JSON renderer; allowlisted plugins)
* `wtmp` -> wtmp/btmp/utmp login records; `shell_history` -> bash/zsh/sh/PSReadLine history;
  `journal_json` -> `journalctl -o json` exports (the Linux items from the Phase 2/5 backlog)
* Worker image: Sleuth Kit (apt, pinned), Volatility 3 (own venv, pinned), tool version file;
  `app/parsers/tools.py` (external tool runner); `docs/parsers.md`; tests; live smoke.

Out of scope (see `docs/BACKLOG.md`): Plaso, Hayabusa, tshark, Suricata, capa/FLOSS,
MFT/UsnJrnl, SRUM (ESE), Jump Lists (OLE CFB), ShellBags, Firefox WAL replay, user-uploaded YARA
rules, YARA over files extracted from disk images / memory regions, TSK file browser UI and file
extraction (`icat`), multi-segment E01 sets, Volatility symbol packs in the image, the volatile
JSON listings from the collectors (process/network snapshots), per-job sandbox containers
(Phase 10), split worker images.

## Standard-profile decisions (made without the owner; recorded here)
1. **Own bounded regf reader instead of regipy.** regipy 6.4.0 (MIT) was evaluated: it copies the
   whole hive into memory, and its big-data (`db`) reader loops forever when a crafted segment
   offset points past the end of the file (`while value_size > 0` with an empty read). The
   registry and Amcache parsers therefore use `app/parsers/regf.py`: mmap (read-only), every
   cell/list/offset bounds-checked, key recursion depth <= 64, visited-cell set against cycles,
   caps on keys visited, values per key, value size and big-data segments. The golden tests use
   synthetic hives from a small test-side hive writer.
2. **Curated registry artifacts, not a full key dump.** A SOFTWARE hive has hundreds of thousands
   of keys; a key-per-event timeline would swamp the events table. `registry_hive` emits: one
   `hive_info` event (base block last-written time) per hive; SYSTEM: services, USBSTOR devices,
   ShimCache/AppCompatCache (Win7 x64 / Win8 / Win10+ formats), BAM/DAM; SOFTWARE: Run/RunOnce
   (+Wow6432Node), Winlogon Shell/Userinit, IFEO `Debugger`, Uninstall entries; NTUSER.DAT:
   Run/RunOnce, UserAssist (ROT13, v5 data), RunMRU, TypedPaths, TypedURLs. Only the current
   control set (`Select\Current`) is read. Dirty hives (sequence numbers differ) are parsed as-is
   with a `hive_dirty` warning (transaction logs are not replayed).
3. **Prefetch MAM decompression is our own LZXPRESS Huffman decoder** (MS-XCA 2.2.4). libscca /
   pyscca (LGPL, C) and dissect.util (AGPL) were rejected for licensing. The decoder is bounded:
   declared size <= 16 MiB, output never exceeds the declared size, invalid tables/offsets raise.
4. **LNK via LnkParse3 1.6.0 (MIT)** for link info, string data and tracker blocks; the header
   FILETIMEs are read directly (LnkParse3 is only asked for structures); any exception from the
   library is one counted error, files > 16 MiB are refused.
5. **YARA rules are trusted configuration, never evidence or request data.** Rules are compiled
   from the packaged pack `app/detection/yara/*.yar` plus an optional operator directory
   `YARA_RULES_DIR` (read-only mount), with `includes=False`; the rule pack SHA-256 goes into the
   run manifest. Scans use `timeout` (`YARA_TIMEOUT_S`) and a size cap (`YARA_MAX_FILE_MB`).
   Uploading rule text through the API is **not supported** in this phase (no validation surface
   to get wrong); it is in the backlog. YARA is never auto-selected: request `parsers:
   ["yara_scan"]`.
6. **Zeek is optional and not in the image.** Zeek packages come from a third-party OBS repo and
   add hundreds of MB; the host has 7.6 GB RAM. `zeek` is a wrapper that finds the binary on
   `TOOL_SEARCH_PATH`/`PATH` and otherwise fails the job with `unusable input: 'zeek' is not
   installed in this worker image (optional engine, see docs/parsers.md)`. It is unit-tested with a
   fake binary. The default pcap path is the pure-Python `pcap` parser (dpkt, BSD-3), which is
   auto-selected for pcap/pcapng; `zeek` must be requested explicitly.
7. **Volatility 3 runs as a separate program from its own venv** (`/opt/dfir/vol3`, `vol` on PATH).
   Its licence (Volatility Software License 1.0) is copyleft-style, so dfirbench never imports
   it; invoking the CLI keeps it an aggregated separate work. The wrapper passes `--offline` (no
   symbol downloads) and `-s VOLATILITY_SYMBOLS_DIR` when configured; symbol packs are not baked
   into the image (hundreds of MB), so Windows/Linux plugins without matching symbols fail with
   Volatility's message in the job error. Plugins come from a fixed allowlist per OS.
8. **Sleuth Kit from Debian bookworm apt, pinned** (`sleuthkit`, CPL/IPL/GPL mix, executed as a
   separate program, never linked). E01 support comes from Debian's libewf build.
9. **External tools get a clean environment**: `PATH` (the tool search path), `HOME`/`TMPDIR` =
   job work dir, `LANG=C.UTF-8`, `TZ=UTC`, nothing else (no DB/S3 credentials reach a process that
   reads hostile input). Fixed argv lists, `shell=False`, stdin closed, new session (killed as a
   process group on timeout/cancel), stdout/stderr to files in scratch, output size polled against
   `TOOL_MAX_OUTPUT_MB`, wall clock against `TOOL_TIMEOUT_S`, cancellation checked every 0.5 s.
10. **Events without an intrinsic time** (YARA matches, PE triage without a sane compile time,
    shell history lines without `#epoch` stamps, Volatility rows without a time column) use the
    evidence reference time (acquisition time, else upload time) and say so:
    `raw.ts_source = "reference:<acquired_at|uploaded_at>"`, tag `time_inferred`, and
    `ts_original` = null. They are never silently given "now".
11. **Timestamp conversion** lives in `app/parsers/timeconv.py`: FILETIME, WebKit/Chrome, PRTime
    (Firefox), Unix s/ms/us, DOS; zero means "not set" (skipped), values outside
    1601-01-01..9999 are errors; `ts_original` records the raw value as `filetime:<int>`,
    `webkit:<int>`, `prtime:<int>`, `unix:<value>` so nothing is lost.
12. **SQLite evidence** is opened on the read-only scratch copy with
    `file:...?mode=ro&immutable=1` (no journal/WAL/SHM files), `PRAGMA trusted_schema=OFF`,
    `cell_size_check=ON`, `query_only=ON`, `mmap_size=0`; the tables used must be real tables
    (not views); text columns are truncated in SQL (`substr`); a progress handler enforces
    `PARSER_SQLITE_TIMEOUT_S`.
13. **Accounting for aggregating parsers**: `pcap` counts a record per flow, per decoded
    DNS/HTTP/TLS-SNI message, per undecodable packet (error) and per non-IP frame (skipped);
    `tsk_fs` counts a record per distinct timestamp of a body-file line (lines without any time are
    one skipped record); `prefetch` counts one record per last-run slot; `registry_hive`/`amcache`
    count one record per artifact entry examined.
14. **No new tables, no migration.** Everything lands in `events`; tool/engine versions and rule
    pack hashes go into run manifests. Grants are unchanged (verify script re-runs the denial list).

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/parsers/base.py` | `ParseContext.work_dir` (scratch subdir for tool output), `ParseContext.tools: ToolConfig`, `ParseLimits.max_structured_bytes` / `max_records` / `max_depth`; `reference_ts(ctx)` helper |
| `backend/app/parsers/timeconv.py` | `filetime()`, `webkit()`, `prtime()`, `unix_seconds()`, `dos_datetime()` -> `Converted(ts, original)` or `None`; `TimestampError` |
| `backend/app/parsers/tools.py` | `ToolConfig`, `find_tool(name, cfg)`, `run_tool(argv, *, cwd, stdout, cfg, heartbeat, watch=())` -> `ToolResult`; `ToolMissingError(ParserInputError)`, `ToolTimeoutError`, `ToolOutputLimitError`; `image_tool_versions()` reads `DFIR_TOOL_VERSIONS` |
| `backend/app/parsers/regf.py` | `Hive(path, limits)`, `Key` (`name`, `last_written`, `subkeys()`, `values()`, `value(name)`, `subkey(path)`), `Value` (`name`, `type`, `data`, `as_str()`, `as_int()`, `as_multi_sz()`), `RegfError` |
| `backend/app/parsers/xpress.py` | `decompress_huffman(data, out_size)` (MS-XCA LZXPRESS Huffman), `XpressError` |
| `backend/app/parsers/browser.py`, `registry_hive.py`, `amcache.py`, `prefetch.py`, `lnk.py`, `pe_static.py`, `yara_scan.py`, `pcap.py`, `zeek.py`, `tsk_fs.py`, `volatility.py`, `wtmp.py`, `shell_history.py`, `journal_json.py` | the parsers (registered in `registry.BUILTIN_MODULES`) |
| `backend/app/detection/yara/*.yar` | reviewed starter rule pack (EICAR, webshell, credential-tool strings, encoded PowerShell, UPX) |
| `backend/app/services/processing.py` | builds `ToolConfig` + `work_dir` for the context; manifest `limits` extended |
| `backend/app/services/jobs.py`, `app/schemas/jobs.py` | `PARSER_PARAMS` for new parsers; `ProcessParams.os`/`plugins`; validation of `os`/`plugins` (volatility) and `timezone` (tsk_fs) |
| `backend/app/services/bundles.py` | `DERIVED_KIND` for the new log-like parsers (`log`) and `pcap` |
| `scripts/phase5-smoke.py` | expects the collected `.bash_history` to be derived too (Phase 6 behaviour change) |
| `backend/app/config.py`, `.env.example` | settings below |
| `infra/docker/worker.Dockerfile` | `tools` stage: `sleuthkit` + `tzdata` (pinned apt), Volatility 3 venv, `/opt/dfir/tool-versions.txt` |
| `backend/tests/fixtures/deep/make_fixtures.py` + committed outputs | synthetic hive (SYSTEM/SOFTWARE/NTUSER/Amcache), Prefetch v17/v30 + MAM, LNK, Chrome History, Firefox places, pcap, pcapng, PE, YARA sample, wtmp, histories, journal JSON, tiny FAT12 image |
| `backend/tests/unit/test_parsers_deep_golden.py`, `test_parsers_deep_hostile.py` (also timeconv, xpress, regf), `test_tool_wrappers.py`, `deep_helpers.py`; `tests/fixtures/deep/fake_tools/fake_engines.py`, `regwriter.py` | unit tests (no Docker) |
| `backend/tests/integration/test_deep_parsers.py` | bundle reprocess derives the new artifacts; parse jobs through the pipeline |
| `docs/parsers.md` | catalogue, inputs, event mapping, limits, engines, licences |
| `scripts/phase6-smoke.py`, `scripts/verify-phase6.sh` | live smoke and verification |

## Settings (new, `.env.example`)
`TOOL_SEARCH_PATH` (unset = PATH), `TOOL_TIMEOUT_S=3600`, `TOOL_MAX_OUTPUT_MB=1024`,
`PARSER_MAX_STRUCTURED_MB=1024` (hives, SQLite, PE, disk-image metadata), `PARSER_MAX_RECORDS=5000000`
(per job), `PARSER_SQLITE_TIMEOUT_S=600`, `YARA_RULES_DIR` (unset), `YARA_TIMEOUT_S=600`,
`YARA_MAX_FILE_MB=2048`, `VOLATILITY_SYMBOLS_DIR` (unset).

## Job parameters
| Parser | Params |
|---|---|
| `tsk_fs` | `timezone` (IANA, default UTC; passed as `fls -z` for FAT local times) |
| `volatility` | `os`: `windows` (default) or `linux`; `plugins`: subset of the OS allowlist (default set: windows `info, pslist, cmdline, netscan`; linux `pslist, bash`) |
| others | none (422 on unknown keys, as before) |

## Detection (auto)
| Parser | Signal | Score |
|---|---|---|
| `prefetch` | `SCCA` at 4 with a known version; `MAM\x04`/`MAM\x84` + `.pf` name | 0.95 (MAM without `.pf`: 0.7) |
| `lnk` | header size 0x4C + LinkCLSID | 0.95 |
| `amcache` | `regf` + base-block file name or file name `amcache.hve` | 0.95 |
| `registry_hive` | `regf` | 0.8 |
| `browser` | SQLite header + `urls`/`visits` or `moz_places` in page 1, or name `History`/`places.sqlite` | 0.9 |
| `pcap` | pcap (4 magics) / pcapng magic | 0.9 |
| `journal_json` | first line JSON with `__REALTIME_TIMESTAMP` | 0.9 |
| `wtmp` | name `wtmp*`/`btmp*`/`utmp*` and 384-byte records with valid `ut_type` | 0.9 |
| `shell_history` | name `.bash_history`, `.zsh_history`, `.sh_history`, `.history`, `.ash_history`, `ConsoleHost_history.txt` | 0.7 |
| `pe_static` | `MZ` + `PE\0\0` at `e_lfanew` | 0.7 |
| `tsk_fs` | MBR/GPT/NTFS/FAT/ext/E01 signatures | 0.6 |
| `volatility` | LiME `EMiL`, crash dump `PAGEDU`, hiberfil, or name `.mem/.vmem/.lime/.raw` with no other match | 0.55-0.6 |
| `yara_scan`, `zeek` | never auto (explicit request) | 0 |

## Event mapping (summary; full table in `docs/parsers.md`)
* `browser`: `source_type=browser`, `event_category=web`, `action` visit/download/search, raw url,
  title, transition, browser, profile file; `file_path` for downloads.
* `registry_hive`: `source_type=registry`, `registry_key` full path, `event_code` artifact
  (`service`, `usb_device`, `shimcache`, `bam`, `run_key`, `winlogon`, `ifeo_debugger`,
  `installed_program`, `userassist`, `runmru`, `typed_path`, `typed_url`, `hive_info`), tags
  `persistence` / `execution` where applicable.
* `amcache`: `source_type=amcache`, `file_path`, `file_hash` = SHA-1, `event_code`
  `amcache_file`/`amcache_program`/`amcache_driver`.
* `prefetch`: `source_type=prefetch`, `event_code=prefetch_run`, `action=process_start`,
  `process_name`, raw run count, hash, volumes, loaded files (first 256).
* `lnk`: `source_type=lnk`, one event per target timestamp (`target_created/modified/accessed`),
  `file_path` target, raw volume, machine id, droids, arguments.
* `pe_static`: `source_type=pe`, one summary event; tags `packed`, `suspicious_imports`, `signed`.
* `yara_scan`: `source_type=yara`, one event per matching rule, `event_code` rule name, raw
  namespace, meta, tags, first 16 string instances (offset, identifier, hex of <= 64 bytes).
* `pcap`/`zeek`: `source_type=pcap`/`zeek`, `event_category=network`, `src/dst_ip`, ports,
  `protocol`; `action` connection/dns_query/dns_response/http_request/tls_client_hello.
* `tsk_fs`: `source_type=filesystem`, `event_code` MACB string, `file_path`, tag `deleted`.
* `volatility`: `source_type=memory`, `event_code` plugin name, pid/ppid/process/cmdline/IPs.
* `wtmp`: `source_type=wtmp` (or `btmp`), `event_category=authentication`, logon/logoff/boot.
* `shell_history`: `source_type=shell_history`, `cmdline`, `user` from the path when known.
* `journal_json`: `source_type=journal`; messages run through the `linux_auth` classifier.

## Test plan
* Unit (no Docker): golden output per fixture (`DFIR_UPDATE_GOLDEN=1` regenerates); timestamp
  conversions incl. zero / out of range; regf reader on the synthetic hive plus cycle, bad offset,
  huge counts, truncated file, big-data segment past EOF (terminates); xpress round trip
  (test-side encoder) plus corrupt tables/offsets; Prefetch MAM; hostile fuzz (hypothesis byte
  flips) for regf, prefetch, lnk, pcap, wtmp, browser never raise and stay balanced; SQLite view
  instead of table refused; oversized inputs refused; tool runner: missing binary -> clear error,
  timeout kills the process, output cap, clean environment, no shell; fake `fls`/`mmls`, `vol`,
  `zeek` binaries drive the wrappers to golden events; YARA: rule pack compiles, EICAR sample
  matches, timeout/size cap, `includes` disabled; detection scores on every fixture.
* Integration (compose Postgres, fake vault): a Windows-style triage bundle (hives, Amcache,
  Prefetch, LNK, Chrome History, Firefox places) ingested -> derived evidence + parse jobs for each
  -> events; a Phase 5 bundle ingested before the parsers existed and reprocessed now derives the
  newly recognized members and reuses the old ones; `volatility` param validation (422).
* Live: `scripts/phase6-smoke.py` uploads the fixtures, runs each parser in the worker image
  (including real Sleuth Kit on the FAT12 image and YARA on the sample), checks counts,
  `zeek` fails with the "not installed" error, `vol` exists in the image and a garbage memory
  image fails cleanly, and a bundle reprocess derives the new artifacts.

## Acceptance criteria (executable)
1. `pytest tests/unit/test_parsers_deep_golden.py tests/unit/test_parsers_deep_hostile.py
   tests/unit/test_tool_wrappers.py`
2. `pytest tests/integration/test_deep_parsers.py`
3. Worker image: `fls -V`, `mmls -V`, `vol --help`, `python -c "import yara, pefile, dpkt,
   LnkParse3"`, `/opt/dfir/tool-versions.txt` lists sleuthkit and volatility3.
4. Live: `scripts/phase6-smoke.py` prints `PHASE 6 SMOKE PASSED`.
5. Earlier phases: collector checks, Phase 1-5 smokes, app-role denial list, migrations round
   trip, backend lint/format/type/bandit/tests, frontend checks.

## Verification command
```bash
bash scripts/verify-phase6.sh
```
