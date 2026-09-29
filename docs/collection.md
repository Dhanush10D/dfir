# Collection: triage collectors, bundle ingest, memory and disk acquisition

This is the field guide for getting evidence into dfirbench (build guide section 9, Phase 5).
Everything under `collector/` runs on the endpoint or on forensic media. Nothing there downloads
tools or talks to the platform. You carry the output to an analyst workstation and upload it.

## 1. Order of volatility

Collect the most volatile data first (guide 9.1):

1. Memory, if policy allows and you trust the tool (section 5).
2. Network state: connections, listening ports, ARP, routes, DNS cache.
3. Processes: command lines, parents, executables.
4. Logged-on users and sessions.
5. Persistence: services, scheduled tasks, run keys, cron, systemd, WMI subscriptions.
6. Disk artifacts: event logs, registry hives, Prefetch, shell history, browser history.
7. A full disk image if needed, write-blocked where possible (section 6).
8. Remote and cloud logs.

The triage collectors cover steps 2 to 6 in one run. Run memory acquisition **before** the
triage collector: the collector itself changes memory, as any program does.

## 2. Triage collectors

Both collectors produce `triage_<HOST>_<YYYYMMDDTHHMMSSZ>.zip` plus `<zip>.sha256` in the output
directory. Use external media or a network share for the output, never the disk you are
investigating.

### Windows (`collector/collect-windows.ps1`, Windows PowerShell 5.1)

Run it from an elevated prompt. Without elevation you still get a bundle, but event logs such as
Security, the hives, Prefetch and Tasks are recorded as access errors.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File E:\collector\collect-windows.ps1 `
    -OutputDir E:\triage -CaseRef IR-2026-001
```

| Parameter | Meaning |
|---|---|
| `-OutputDir` (required) | Output folder. It is created if missing. |
| `-CaseRef`, `-Operator` | Recorded in the manifest. The operator defaults to the current account. |
| `-NoVolatile`, `-NoEventLogs`, `-NoFiles` | Skip a section. |
| `-EventLogs` | Channels to export with `wevtutil epl`. |
| `-ExtraPaths` | Extra files or folders to copy into `files/extra/`. |
| `-MaxFileMB`, `-MaxTotalMB` | Size caps. Anything over them is listed in `skipped`. |
| `-NtpServer host` | Measures the clock offset with one `w32tm /stripchart` sample. This is the only network traffic the collector makes, and only when you ask for it. |
| `-KeepStaging` | Keep the unzipped staging folder next to the zip. |

With `-File`, PowerShell passes a list parameter as a single string. Separate the items with `|`,
for example `-EventLogs 'Security|System'`.

What it collects:

| Section | Items |
|---|---|
| `system/` | `os_info.json` (OS, build, boot time, time zone, domain), `time_sync.txt` (`w32tm /query /status`), `installed_software.json`, `hosts` |
| `volatile/` | `processes.json` (pid, ppid, path, command line, start time), `connections.json`, `netstat.txt`, `dns_cache.txt`, `ipconfig.txt`, `arp.txt`, `routes.txt`, `sessions.txt`, `users.json`, `services.json`, `drivers.json`, `shares.json` |
| `persistence/` | `run_keys.json` (Run, RunOnce and Winlogon), `scheduled_tasks.json`, `wmi_subscriptions.json`, `startup_commands.json`, the Tasks folder, Startup folders |
| `logs/` | EVTX exports: Security, System, Application, PowerShell, Sysmon, TaskScheduler, RDP, Defender, WMI and BITS |
| `files/` | the SYSTEM and SOFTWARE hives (`reg save`), per-user NTUSER.DAT and UsrClass.dat, Amcache, SRUM, Prefetch, LNK files, Jump Lists, `ConsoleHost_history.txt` |
| `browser/` | Chrome and Edge `History`, Firefox `places.sqlite` |

Never collected: the SAM and SECURITY hives, browser `Login Data` and `Cookies`, or anything else
that holds credentials (guide 9.2 rule 5).

The collector does not read raw NTFS or use shadow copies, so a locked file is recorded in
`errors`. This affects `$MFT`, `Amcache.hve` and `SRUDB.dat` while their services run, and the
unloaded hives of other users. Collect those from a disk image (section 6).

### Linux (`collector/collect_linux.py`, Python 3.6 or later, standard library only)

```bash
sudo python3 /mnt/usb/collector/collect_linux.py --output /mnt/usb/triage --case-ref IR-2026-001
# dead box: a mounted image, read-only mount recommended; no volatile section
python3 collect_linux.py --output /cases/ir1/triage --root /mnt/image
```

| Option | Meaning |
|---|---|
| `--output` (required) | Output directory. Must not be inside `--root`. |
| `--root` | Collect from a mounted image instead of `/`. The manifest records `mode: offline`. |
| `--case-ref`, `--operator` | Recorded in the manifest. The operator defaults to `$SUDO_USER` or the current user. |
| `--no-volatile`, `--no-logs`, `--no-files` | Skip a section. |
| `--max-file-mb`, `--max-total-mb` | Size caps (default 1024 and 8192). |
| `--journal-days N` | `journalctl -o json` export window (default 14; live mode only). |
| `--ntp-server host` | Measures the clock offset with one SNTP query. Off by default. |

What it collects:

| Section | Items |
|---|---|
| `volatile/` (live only) | `processes.json` and `connections.json` (from `/proc`), `ss`, `ip addr/route/neigh`, `who`, `w`, `last`, `lastb`, `lsmod`, `mount`, `lsof`, `/proc/net/arp`, `/proc/modules`. Also listings of `/tmp`, `/var/tmp` and `/dev/shm` (metadata only). |
| `logs/` | `auth.log*`, `secure*`, `syslog*`, `messages*`, `kern.log*`, `cron*`, `wtmp`, `btmp`, `lastlog`, `faillog`, package logs, `audit/audit.log*`, the journal export |
| `system/` | `os-release`, hostname, time zone, hosts, `resolv.conf`, `fstab`, `sshd_config`, `ld.so.preload`, `uname`, `timedatectl`, `chronyc tracking`, package lists |
| `persistence/` | crontabs and `/etc/cron.*`, the user cron spool, systemd units plus a listing that includes enable symlinks, `rc.local`, profile scripts, `sudoers.d`, XDG autostart, `modprobe.d`, `init.d` |
| `files/` | `passwd`, `group`, `sudoers`, and per user: shell histories, `authorized_keys`, `known_hosts`, `.ssh/config`, shell rc files |

Never collected: `/etc/shadow`, `/etc/gshadow`, and private SSH keys.

### Read-only guarantees (both collectors)

- Host files are only ever opened for reading. PowerShell uses .NET with `FileShare.ReadWrite|Delete`
  and passes every path with `-LiteralPath`. Python uses `O_RDONLY|O_NOFOLLOW|O_NONBLOCK`, adds
  `O_NOATIME` where the kernel permits it so access times stay unchanged, and requires a regular
  file after `fstat`.
- Symbolic links, junctions and reparse points are not followed. They are listed in `skipped`.
- Only fixed commands run, with no shell and each with a timeout. `wevtutil epl` and `reg save`
  write only into the output directory.
- Nothing on the host is modified, moved or deleted. The one deletion is the Windows collector's
  own staging folder inside `-OutputDir`, after the zip has been written and its entries counted.
- Unreadable or locked targets go to `errors` and the run continues.
- Both collectors are tested against these rules: `backend/tests/unit/test_collectors.py` checks
  that the source tree is unchanged after a run.

## 3. Manifest (`manifest.json`, schema `dfirbench.triage/1`)

```json
{
  "schema": "dfirbench.triage/1",
  "collector": {"name": "dfirbench-collect-linux", "version": "1.0.0", "sha256": "<own hash>", "runtime": "python 3.10.12"},
  "host": {"hostname": "web01", "fqdn": null, "os": "Ubuntu 22.04.4 LTS", "timezone": "Europe/Berlin",
           "utc_offset_minutes": 120, "boot_time": "2026-09-20T06:00:00Z"},
  "operator": "alice", "case_ref": "IR-2026-001", "mode": "live", "elevated": true,
  "started_at": "2026-09-29T10:00:00Z", "finished_at": "2026-09-29T10:03:12Z",
  "clock": {"source": "timedatectl", "synchronized": true, "ntp_offset_s": null},
  "files": [{"path": "logs/var/log/auth.log", "sha256": "<64 hex>", "size": 2231, "category": "logs",
             "source": "/var/log/auth.log", "collected_at": "2026-09-29T10:01:07Z"}],
  "errors": [{"target": "/etc/sudoers", "error": "PermissionError (EACCES)"}],
  "skipped": [{"target": "/var/log/journal", "reason": "symlink"}]
}
```

Every timestamp is UTC ISO-8601 with `Z`. Each `files[].path` is the member name in the zip; it
uses `/` separators and has no `..`, leading `/`, drive letter or backslash. The manifest does not
list itself. Unknown keys are ignored, so newer collectors stay readable.

## 4. Upload and ingest

1. In the UI (Evidence tab), upload the zip with kind **triage_bundle**. Over the API, create the
   evidence with `kind: "triage_bundle"` and `expected_sha256` set to the value from `<zip>.sha256`,
   then upload and finalize. Finalize fails if the stored bytes differ from `expected_sha256`.
2. Press **Process**, or call `POST /api/v1/evidence/{id}/process` with `{}`. This queues one
   `bundle` job, and the request is idempotent.
3. The worker re-verifies the stored bundle against its signed custody entry and checks the
   archive for hostile content. It then extracts every member into its scratch directory under
   fixed names and compares each one with the manifest (SHA-256 and size):
   - **ingested**: the member was verified and a parser recognizes it (EVTX, Linux auth/syslog).
     It becomes a *derived evidence* item with its own label, for example `EV-003.0001`. That
     item has `parent_evidence_id` set to the bundle and is stored WORM under
     `{case}/{bundle}/derived/...`. Its signed custody chain is `created` (with the bundle id,
     SHA-256, member path and manifest SHA-256), `ingested`, `hash_verified` and `locked`. A
     normal parse job then puts its events in the timeline.
   - **verified**: the member matched the manifest, but no parser handles it yet (registry,
     Prefetch, JSON listings: Phase 6). It stays inside the bundle.
   - **hash_mismatch**, **size_mismatch**, **unlisted**, **missing**, **corrupt**: the member is
     quarantined and never ingested. The job ends `partial` and admins are notified
     (`evidence.bundle_manifest_mismatch`).
4. A hostile archive is rejected whole and nothing is extracted. The job ends `failed`, the
   `processed` custody entry lists the reasons, and admins are notified
   (`evidence.bundle_rejected`). Hostile means any of:
   - a member name with a path traversal, an absolute path, a drive letter or a backslash
   - a symlink, hard link, device or reparse point
   - an encrypted member, or compression other than stored/deflate
   - duplicate names, including names that differ only in case
   - overlapping entries
   - more members, bytes or compression ratio than the limits allow
   - a missing or invalid manifest
   - a tar or other non-ZIP format
5. `GET /api/v1/evidence/{id}/bundle` shows the latest run: collector, collector trust, host,
   counts, the verdict for each member, and the derived items. To re-run, use
   `POST /jobs/{id}/reprocess`. Members already derived with the same path and hash are reused,
   not duplicated.

The uploaded bundle is never modified. Every conclusion can be re-checked from the original.

Limits (see `.env.example`):

| Setting | Default | Meaning |
|---|---|---|
| `BUNDLE_MAX_MEMBERS` | 10000 | Maximum members in the archive. |
| `BUNDLE_MAX_TOTAL_MB` | 4096 | Maximum total size, checked on the declared sizes and again while extracting. |
| `BUNDLE_MAX_MEMBER_MB` | 2048 | Maximum size of one member. |
| `BUNDLE_MAX_RATIO` | 200 | Maximum compression ratio, per member and for the whole archive, for anything over 1 MiB. |
| `BUNDLE_MAX_DERIVED` | 500 | Maximum derived items per run. |

### Collector trust

The manifest reports the SHA-256 of the collector script that produced it. The server compares it
with `backend/app/collection/trusted_collectors.json`, and optionally with an operator file at
`COLLECTOR_TRUSTED_HASHES_PATH` (same format, kept on a read-only mount). The trust list lives
outside the database. The result is `trusted`, `unknown`, `name_mismatch` or `no_hash`, and it is
shown in the run manifest and in the `processed` custody entry.

An unknown collector does not block ingest, because field teams adapt scripts. The analyst decides
how much weight to give a bundle from an unverified collector.

After changing a collector, run `python scripts/update-collector-hashes.py`. A unit test fails
until you do. The PowerShell script is listed in both its CRLF form (the git checkout) and its LF
form (a raw download).

## 5. Memory acquisition

The platform does not ship or download acquisition tools or kernel drivers. You bring trusted,
verified binaries on your collection media. Each wrapper:

- checks that its tool exists (exit code 2 if it does not)
- checks for root or Administrator (exit code 3)
- checks free space (exit code 4)
- refuses to overwrite existing output
- hashes the image and writes `<image>.sha256` and `<image>.acquisition.json`

The JSON records the tool path, tool hash, version or signature, host, operator and UTC start and
end times.

### Windows: WinPmem (`collector/acquire/acquire-memory-windows.ps1`)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File E:\collector\acquire\acquire-memory-windows.ps1 `
    -OutputDir E:\mem -WinPmemPath E:\tools\winpmem_mini_x64_rc2.exe -CaseRef IR-2026-001
```

The wrapper records the Authenticode status of the WinPmem binary and its signer. Check that the
status is `Valid` before you trust the image.

### Linux: AVML (`collector/acquire/acquire-memory-linux.sh`)

```bash
sudo /mnt/usb/collector/acquire/acquire-memory-linux.sh --output /mnt/usb/mem \
    --avml /mnt/usb/tools/avml --case-ref IR-2026-001 [--compress]
```

AVML is a static binary and needs no kernel module.

LiME is the alternative, but its module must be built for the exact running kernel, on an
identical system rather than on the suspect host:

```bash
insmod lime-$(uname -r).ko "path=/mnt/usb/mem.lime format=lime"
```

Then hash the result with `sha256sum`.

Memory images are uploaded as kind **memory**. Set `acquired_at`, `acquisition_tool` and
`expected_sha256` from the acquisition JSON. Sanity-check the size against the RAM figure in the
JSON. Analysis with Volatility 3 arrives in Phase 6.

## 6. Disk acquisition

- Use a hardware write blocker for physical media, and record the serial numbers. The wrapper
  records the model, serial and size from `lsblk`.
- Image the whole device, never a mounted file system you are still using.

### Linux (`collector/acquire/acquire-disk-linux.sh`)

The wrapper uses `ewfacquire` (E01) if it is present, otherwise `dc3dd`, otherwise `dd`.

```bash
sudo ./acquire-disk-linux.sh --source /dev/sdb --output /mnt/evidence/ir1 \
    --case-ref IR-2026-001 --evidence-number EV-004 --description "suspect laptop SSD"
```

The wrapper:

- refuses to write the image onto the source device or one of its partitions
- warns when the source is mounted
- never mounts or reconfigures the source; it does not run `blockdev --setro` either, so use a
  hardware write blocker
- records the tool, device model, serial and size, and the image hash

`dd` does not verify its copy, so for `dd` the wrapper hashes the source a second time (read-only)
and compares the two hashes. Read errors are zero-padded (`conv=noerror,sync`) and show up as a
hash difference.

`ewfacquire` splits large images into segments (`.E01`, `.E02`, ...). Run `ewfverify` before
upload. dfirbench stores each uploaded file as one evidence item, so either upload a single-segment
image or use `dc3dd`/`dd` for a raw image (multi-segment evidence sets are in the backlog).

### Windows

There is no wrapper for Windows disk imaging (Standard profile). Use one of these:

- FTK Imager: in the GUI, choose *Create Disk Image*, *Physical Drive*, *E01*, and check *Verify
  images after they are created*. Keep the `.txt` report it writes.
- `ewfacquire.exe` from a libewf build on your forensic media, with the same options as above.

Record the drive model and serial from the imaging report.

### Cloud VM disks

Snapshot the volume, then share or copy the snapshot to a separate forensic account. Record the
snapshot and volume IDs in the evidence `acquisition_notes`; they become part of the signed
`created` custody entry.

Upload disk images as kind **disk_image** with `expected_sha256`. File-system timelines (TSK)
arrive in Phase 6.
