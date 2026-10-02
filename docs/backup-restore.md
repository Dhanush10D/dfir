# Backup, restore and re-verification

Phase 10 (guide 7.6, 20.2, 21.6). Scripts: `scripts/backup.py`, `scripts/restore.py`; operator
commands: `python -m app.cli backup-manifest`, `python -m app.cli integrity-check`.

## What a backup contains

`BACKUP_PASSPHRASE=... BACKUP_KEYS_PASSPHRASE=... backend/.venv/Scripts/python scripts/backup.py
--out <new dir>` (on the Docker host, with the backend venv) writes:

| File | Content |
|---|---|
| `manifest.json` | Signed state manifest: Alembic revision, row counts of the forensic tables, every evidence item's SHA-256, size, vault version and status, every custody chain's length and head (`seq`, `entry_hash`), every signed report's hash and signature. Ed25519-signed with the custody key. |
| `integrity-at-backup.json` | `integrity-check` of the live stack at backup time (known findings, e.g. evidence a tamper demo damaged on purpose). |
| `db.dump.enc` | `pg_dump -Fc` of the database (no role passwords: roles are not dumped). |
| `objects.tar.enc` | The MinIO volume (evidence originals, report artifacts, object versions, Object Lock retention, bucket configuration). |
| `keys.tar.enc` | The custody key volume (the private signing key), encrypted with its own `BACKUP_KEYS_PASSPHRASE`. |
| `index.json` | Sizes and SHA-256 of every file above, plaintext SHA-256 of the encrypted parts. |

The script stops `web`, `api` and `worker` for the duration (a maintenance window, so the dump,
the manifest and the objects describe one state) and MinIO while its volume is copied (read-only
mount, so versions and retention are copied exactly; copying the volume is what keeps the
version ids that evidence rows and signed custody entries refer to). Everything it stopped is
started again, also after an error. Original evidence is only read.

**Encryption** (`app/ops/backupcrypt.py`): AES-256-GCM in 1 MiB chunks with the STREAM
construction (nonce = random prefix, chunk counter, last-chunk flag; the header is associated
data), key from the passphrase with scrypt (N=2^15, r=8, p=1). Truncation, reordering,
duplicated or appended chunks, a wrong passphrase or any flipped bit is detected. A file's header
cannot ask for a costly key derivation: only N up to 2^17 with r=8 (at most 128 MiB) is accepted.

**Two passphrases** (backup format 2), both at least 20 characters, read from the environment
only and never printed:

* `BACKUP_PASSPHRASE` encrypts the database dump and the object store.
* `BACKUP_KEYS_PASSPHRASE` encrypts `keys.tar.enc`, the private custody signing key, and must be
  different. Whoever holds a backup and the data passphrase can restore and read the data, but
  cannot sign custody records or manifests. Give the keys passphrase to fewer people and keep it
  apart from the data passphrase and from the backups (password manager / secret store).

Copy backups off the host; the backup directory holds no plaintext.

## Restore and verification

```bash
# the trust anchor comes from outside the backup: the public part of the signing key
docker compose -f infra/compose.yaml run --rm --no-deps -T api \
  python -m app.core.signing show /var/lib/dfirbench/keys/custody-dev.pem > pub.txt
# (or the operator's trust store); then build {key_id: PEM} with `python -m app.core.signing trust`
BACKUP_PASSPHRASE=... BACKUP_KEYS_PASSPHRASE=... backend/.venv/Scripts/python scripts/restore.py \
  --from <backup dir> --project dfirbench-restore --trusted-keys trusted.json [--keep]
```

1. Every file must match `index.json` (size and SHA-256) before anything is decrypted.
2. Every file is decrypted and authenticated completely, and the plaintext is thrown away as it
   is checked. A wrong passphrase (either one), truncation or any modification stops the restore
   here, before anything is created.
3. The target project's volumes must not exist (`--force` replaces them; restoring over the live
   project `dfirbench` always needs `--force` and is never torn down afterwards).
4. Each file is decrypted a second time straight into its consumer: the MinIO and key archives
   into `tar` in `--network none` containers, the dump into `pg_restore --exit-on-error`
   (postgres and MinIO start on their own ports, default 55432 and 59000, and subnet; the
   least-privilege role is created first). Every record is authenticated again and the plaintext
   SHA-256 must match the index. **No plaintext is ever written to the host's disk**, so the
   private signing key never sits in a temporary directory, on Windows or anywhere else.
5. `integrity-check --manifest manifest.json --trusted-keys <file> --no-signer` runs against the
   restored project, read-only: the manifest signature under the trusted key, schema revision,
   row counts, every evidence item, every custody chain (signatures, links, hashes) and its head
   (truncation or extension relative to the backup is visible), every original's bytes at the
   recorded version against the signed ingest SHA-256 and size, and Object Lock retention.
6. The restore is **verified** only if no manifest comparison failed and the integrity findings
   are exactly those recorded in `integrity-at-backup.json`. Then, unless `--keep`, the restore
   project is removed (`down -v`): that is the restore drill `verify-phase10.sh` runs.

Result and exit code:

| Exit | Last line | Meaning |
|---|---|---|
| 0 | `RESTORE VERIFIED: ... no integrity findings` | The restored state equals the backup, and the backup was clean. |
| 3 | `RESTORE VERIFIED WITH KNOWN FINDINGS: ...`, then one `known finding:` line each | The restored state equals the backup, but the backup already held these findings when it was taken. The restore reproduced them and did not cause them, but they still need investigating. |
| 1 | `RESTORE NOT VERIFIED: ...` or `restore failed: ...` | The restored state differs from the backup, or the restore failed. |
| 2 | `error: ...` | Configuration (a passphrase missing, too short, or both the same). |

To return a restored project to service, first run the drill above with the same backup, then
restore with `--project dfirbench --force` while the live stack is stopped, then
`docker compose up -d`; the migrate job re-provisions the app login. Before the live volumes are
replaced, each is copied to `<volume>-pre-restore-<time>` (this needs free disk space for one
copy of the live data). If the restore fails or is not verified, the script names those copies:
to roll back, stop the project and copy each one back into its volume (for example
`docker run --rm -v dfirbench_pgdata-pre-restore-<time>:/from:ro -v dfirbench_pgdata:/to
--entrypoint sh dfirbench/api:dev -c "cd /from && tar -cpf - . | tar -xpf - -C /to"`). Delete
the copies with `docker volume rm` once the restored project is back in service.

## Re-verification without a backup

`python -m app.cli integrity-check` (in the api container) is the same read-only check without a
manifest: run it from cron (`docker compose exec -T api python -m app.cli integrity-check`) to get
the guide's "nightly re-verify". It never appends custody entries; the per-item `POST
/evidence/{id}/verify` remains the way to record a `hash_verified` entry. Exit code 1 means a
finding (JSON on stdout), 2 an error.

## Limits (Standard profile)

* No WAL archiving or point-in-time recovery: backups are full logical dumps taken in a short
  maintenance window. Production with a recovery-point objective below a day should add WAL
  archiving and MinIO bucket/site replication (guide 21.6); both are post-v1.
* The restore needs the same MinIO root credentials as the backed-up stack (MinIO encrypts its
  configuration with them) and the same `POSTGRES_PASSWORD` for the owner login of the new
  cluster.
* Periodic signed custody anchors (between backups) need a scheduler and are post-v1; until then
  a backup manifest is the anchor that makes later tail truncation visible.
