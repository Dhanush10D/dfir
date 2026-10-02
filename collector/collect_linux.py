#!/usr/bin/env python3
"""dfirbench Linux triage collector (guide 9.2, docs/collection.md). Stdlib only, Python >= 3.6.

    sudo python3 collect_linux.py --output /mnt/usb/triage [--case-ref IR-1] [--operator alice]
    python3 collect_linux.py --output ./out --root /mnt/image      # dead box / mounted image

Writes ``triage_<host>_<YYYYMMDDTHHMMSSZ>.zip`` (with ``manifest.json``, schema
``dfirbench.triage/1``) and ``<zip>.sha256`` into the output directory, and nothing anywhere else.

Read-only toward the host:
* files are opened with O_RDONLY|O_NOFOLLOW|O_NONBLOCK (+O_NOATIME when permitted, so access
  times are not touched), must be regular files after fstat, and are streamed straight into the
  zip; symbolic links are never followed (recorded in ``skipped``);
* only fixed, read-only commands run (``ss``, ``ip``, ``who``, ``journalctl``, ...), never through
  a shell, each with a timeout; nothing is installed, changed, moved or deleted;
* no network traffic unless ``--ntp-server`` is given (one SNTP query to measure clock offset);
* no credential material: /etc/shadow, /etc/gshadow, private keys and browser secrets are never
  collected.
Unreadable or vanished targets are recorded in ``errors`` and collection continues.
"""

import argparse
import datetime
import errno
import fnmatch
import getpass
import hashlib
import json
import os
import platform
import re
import socket
import stat
import struct
import subprocess
import sys
import time
import zipfile

NAME = "dfirbench-collect-linux"
VERSION = "1.0.0"
SCHEMA = "dfirbench.triage/1"
CHUNK = 1024 * 1024
MAX_LISTING = 20000
MAX_PROBLEMS = 5000
COMMAND_TIMEOUT = 60

LOG_PATTERNS = (
    "auth.log*", "secure*", "syslog*", "messages*", "kern.log*", "cron*", "wtmp*", "btmp*",
    "lastlog", "faillog", "dpkg.log*", "yum.log*", "dnf.log*", "dnf.rpm.log*", "boot.log*",
    "sudo.log*",
)
LOG_SUBDIRS = {"audit": ("audit.log*",), "apt": ("history.log*", "term.log*")}
SYSTEM_FILES = (
    "/etc/os-release", "/etc/hostname", "/etc/timezone", "/etc/hosts", "/etc/resolv.conf",
    "/etc/fstab", "/etc/ssh/sshd_config", "/etc/modules", "/etc/ld.so.preload",
)
ACCOUNT_FILES = ("/etc/passwd", "/etc/group", "/etc/sudoers")
PERSISTENCE_FILES = (
    "/etc/crontab", "/etc/anacrontab", "/etc/rc.local", "/etc/profile", "/etc/bash.bashrc",
    "/etc/environment",
)
PERSISTENCE_DIRS = (
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
    "/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/profile.d",
    "/etc/sudoers.d", "/etc/xdg/autostart", "/etc/modprobe.d", "/etc/update-motd.d",
    "/etc/init.d",
)
SYSTEMD_DIRS = ("/etc/systemd/system", "/etc/systemd/user", "/run/systemd/system")
LISTING_DIRS = ("/tmp", "/var/tmp", "/dev/shm")
USER_FILES = (
    ".bash_history", ".zsh_history", ".sh_history", ".history", ".ash_history",
    ".python_history", ".mysql_history", ".psql_history", ".lesshst", ".viminfo",
    ".bashrc", ".bash_profile", ".bash_logout", ".profile", ".zshrc",
    ".ssh/authorized_keys", ".ssh/authorized_keys2", ".ssh/known_hosts", ".ssh/config",
    ".config/autostart",
)
NEVER = ("/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/security/opasswd")
COMMANDS = (
    ("volatile/ss.txt", ["ss", "-tunapeo"]),
    ("volatile/ip_addr.txt", ["ip", "-d", "addr"]),
    ("volatile/ip_route.txt", ["ip", "route", "show", "table", "all"]),
    ("volatile/ip_neigh.txt", ["ip", "neigh"]),
    ("volatile/who.txt", ["who", "-a"]),
    ("volatile/w.txt", ["w"]),
    ("volatile/last.txt", ["last", "-F", "-n", "500"]),
    ("volatile/lastb.txt", ["lastb", "-F", "-n", "500"]),
    ("volatile/lsmod.txt", ["lsmod"]),
    ("volatile/mount.txt", ["mount"]),
    ("volatile/lsof.txt", ["lsof", "-nP"]),
    ("system/uname.txt", ["uname", "-a"]),
    ("system/timedatectl.txt", ["timedatectl"]),
    ("system/chrony_tracking.txt", ["chronyc", "tracking"]),
    ("persistence/systemctl_units.txt", ["systemctl", "list-units", "--all", "--no-pager"]),
    ("persistence/systemctl_unit_files.txt", ["systemctl", "list-unit-files", "--no-pager"]),
    ("persistence/systemctl_timers.txt", ["systemctl", "list-timers", "--all", "--no-pager"]),
    ("system/packages_dpkg.txt", ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]),
    ("system/packages_rpm.txt", ["rpm", "-qa", "--last"]),
)
UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(value):
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_epoch(seconds):
    try:
        return iso(datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc))
    except (OverflowError, OSError, ValueError):
        return None


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_component(part):
    part = UNSAFE_CHARS.sub("_", part)
    if part in ("", ".", ".."):
        part = "_" + part
    return part[:200]


class Collector:
    def __init__(self, args):
        self.args = args
        self.root = os.path.abspath(args.root)
        self.live = args.root == "/" and sys.platform.startswith("linux")
        self.out_dir = os.path.abspath(args.output)
        self.max_file = args.max_file_mb * 1024 * 1024
        self.max_total = args.max_total_mb * 1024 * 1024
        self.total = 0
        self.files = []
        self.errors = []
        self.skipped = []
        self.names = set()
        self.started = utcnow()
        self.stamp = self.started.strftime("%Y%m%dT%H%M%SZ")
        self.hostname = self._hostname()
        base = "triage_%s_%s" % (safe_component(self.hostname)[:64] or "host", self.stamp)
        self.zip_path = os.path.join(self.out_dir, base + ".zip")
        self.partial_path = self.zip_path + ".partial"
        self.zip = None

    # -------------------------------------------------------------- bookkeeping

    def host(self, path):
        """Absolute path of a host path under --root (never outside it)."""
        return os.path.join(self.root, path.lstrip("/"))

    def error(self, target, exc):
        if len(self.errors) < MAX_PROBLEMS:
            code = getattr(exc, "errno", None)
            text = type(exc).__name__ + (" (%s)" % errno.errorcode.get(code, code) if code else "")
            self.errors.append({"target": target, "error": text})

    def skip(self, target, reason):
        if len(self.skipped) < MAX_PROBLEMS:
            self.skipped.append({"target": target, "reason": reason})

    def arcname(self, category, host_path):
        parts = [safe_component(p) for p in host_path.strip("/").split("/") if p]
        name = "/".join([category] + parts)[:480]
        candidate, n = name, 1
        while candidate.lower() in self.names:
            n += 1
            candidate = "%s~%d" % (name, n)
        self.names.add(candidate.lower())
        return candidate

    def _zipinfo(self, arcname):
        info = zipfile.ZipInfo(arcname, date_time=utcnow().timetuple()[:6])
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (stat.S_IFREG | 0o444) << 16
        info.create_system = 3
        return info

    # -------------------------------------------------------------- writers

    def add_bytes(self, arcname, data, category, source):
        digest = hashlib.sha256(data).hexdigest()
        with self.zip.open(self._zipinfo(arcname), "w", force_zip64=True) as dst:
            dst.write(data)
        self.total += len(data)
        self.files.append(
            {
                "path": arcname,
                "sha256": digest,
                "size": len(data),
                "category": category,
                "source": source,
                "collected_at": iso(utcnow()),
            }
        )

    def add_json(self, arcname, value, category, source):
        data = json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
        self.add_bytes(arcname, data, category, source)

    def _open_readonly(self, path):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        noatime = getattr(os, "O_NOATIME", 0)
        if noatime:
            try:
                return os.open(path, flags | noatime)
            except PermissionError:
                pass  # O_NOATIME needs file ownership or CAP_FOWNER; fall back
        return os.open(path, flags)

    def add_file(self, host_path, category, quiet_missing=False):
        if host_path in NEVER:
            return
        src = self.host(host_path)
        try:
            st = os.lstat(src)
        except FileNotFoundError:
            if not quiet_missing:
                self.skip(host_path, "not_found")
            return
        except OSError as exc:
            self.error(host_path, exc)
            return
        if stat.S_ISLNK(st.st_mode):
            self.skip(host_path, "symlink")
            return
        if not stat.S_ISREG(st.st_mode):
            self.skip(host_path, "not_regular_file")
            return
        if st.st_size > self.max_file:
            self.skip(host_path, "larger_than_max_file_mb")
            return
        if self.total + st.st_size > self.max_total:
            self.skip(host_path, "total_cap_reached")
            return
        try:
            fd = self._open_readonly(src)
        except OSError as exc:
            self.error(host_path, exc)
            return
        with os.fdopen(fd, "rb") as fh:
            try:
                fst = os.fstat(fh.fileno())
            except OSError as exc:
                self.error(host_path, exc)
                return
            if not stat.S_ISREG(fst.st_mode):
                self.skip(host_path, "not_regular_file")
                return
            arcname = self.arcname(category, host_path)
            digest = hashlib.sha256()
            size = 0
            truncated = False
            failure = None
            with self.zip.open(self._zipinfo(arcname), "w", force_zip64=True) as dst:
                while True:
                    try:
                        chunk = fh.read(CHUNK)
                    except OSError as exc:  # e.g. EIO on a failing disk: keep what was read
                        failure = exc
                        break
                    if not chunk:
                        break
                    if size + len(chunk) > self.max_file:  # file grew while being read
                        chunk = chunk[: self.max_file - size]
                        truncated = True
                    digest.update(chunk)
                    dst.write(chunk)
                    size += len(chunk)
                    if truncated:
                        break
        self.total += size
        entry = {
            "path": arcname,
            "sha256": digest.hexdigest(),
            "size": size,
            "category": category,
            "source": host_path,
            "collected_at": iso(utcnow()),
            "mtime": iso_epoch(fst.st_mtime),
            "mode": oct(stat.S_IMODE(fst.st_mode)),
            "uid": getattr(fst, "st_uid", None),
        }
        if truncated:
            entry["truncated"] = True
        if failure is not None:
            entry["partial"] = True
            self.error(host_path, failure)
        self.files.append(entry)

    def entries(self, host_dir, patterns=None, recursive=False, depth=0):
        """Regular files and symlinks under host_dir (never following links)."""
        src = self.host(host_dir)
        try:
            with os.scandir(src) as it:
                items = sorted(it, key=lambda e: e.name)
        except FileNotFoundError:
            return []
        except OSError as exc:
            self.error(host_dir, exc)
            return []
        found = []
        for item in items:
            path = host_dir.rstrip("/") + "/" + item.name
            try:
                if item.is_dir(follow_symlinks=False):
                    if recursive and depth < 6:
                        found.extend(self.entries(path, patterns, True, depth + 1))
                    continue
            except OSError as exc:
                self.error(path, exc)
                continue
            if patterns and not any(fnmatch.fnmatch(item.name, p) for p in patterns):
                continue
            found.append(path)
        return found

    # -------------------------------------------------------------- host facts

    def read_text(self, host_path, limit=1024 * 1024):
        try:
            fd = self._open_readonly(self.host(host_path))
        except OSError:
            return None
        with os.fdopen(fd, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")

    def _hostname(self):
        if self.live:
            return socket.gethostname()
        text = self.read_text("/etc/hostname") or ""
        return text.strip().splitlines()[0][:255] if text.strip() else "unknown"

    def _timezone(self):
        text = (self.read_text("/etc/timezone") or "").strip()
        if text:
            return text.splitlines()[0][:64]
        try:
            target = os.readlink(self.host("/etc/localtime"))
        except OSError:
            return None
        marker = "zoneinfo/"
        return target.split(marker, 1)[1][:64] if marker in target else None

    def _os_name(self):
        for line in (self.read_text("/etc/os-release") or "").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')[:256]
        return platform.platform() if self.live else None

    def users(self):
        """(name, home) from the collected root's /etc/passwd (not the collector's host)."""
        out = []
        for line in (self.read_text("/etc/passwd") or "").splitlines():
            parts = line.split(":")
            if len(parts) >= 7 and parts[5].startswith("/"):
                out.append((parts[0], os.path.normpath(parts[5]).replace("\\", "/")))
        return out

    # -------------------------------------------------------------- volatile (live only)

    def run(self, argv, arcname, category):
        try:
            proc = subprocess.Popen(  # fixed argv, no shell
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except OSError as exc:
            self.skip(" ".join(argv), "command_unavailable:" + type(exc).__name__)
            return
        try:
            out, _err = proc.communicate(timeout=COMMAND_TIMEOUT)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _err = proc.communicate()
            self.error(" ".join(argv), TimeoutError("timeout"))
        if proc.returncode not in (0, None) and not out:
            self.skip(" ".join(argv), "exit_%s" % proc.returncode)
            return
        out = out[: self.max_file]
        self.add_bytes(arcname, out, category, "command: " + " ".join(argv))

    def journal(self):
        argv = ["journalctl", "-o", "json", "--no-pager", "--utc",
                "--since", "-%dd" % self.args.journal_days]
        try:
            proc = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        except OSError:
            self.skip("journalctl", "command_unavailable")
            return
        arcname = self.arcname("logs", "/journal/journal_%dd.json" % self.args.journal_days)
        digest, size, truncated = hashlib.sha256(), 0, False
        deadline = time.time() + 30 * COMMAND_TIMEOUT
        with self.zip.open(self._zipinfo(arcname), "w", force_zip64=True) as dst:
            while True:
                chunk = proc.stdout.read(CHUNK)
                if not chunk:
                    break
                if size + len(chunk) > self.max_file or time.time() > deadline:
                    truncated = True
                    break
                digest.update(chunk)
                dst.write(chunk)
                size += len(chunk)
        if truncated:
            proc.kill()
        proc.wait()
        self.total += size
        entry = {"path": arcname, "sha256": digest.hexdigest(), "size": size,
                 "category": "logs", "source": "command: " + " ".join(argv),
                 "collected_at": iso(utcnow())}
        if truncated:
            entry["truncated"] = True
        self.files.append(entry)

    def processes(self):
        procs = []
        try:
            clk = os.sysconf("SC_CLK_TCK")
        except (ValueError, OSError, AttributeError):
            clk = 100
        boot = self.boot_time()
        for name in sorted(os.listdir("/proc"), key=lambda n: (len(n), n)):
            if not name.isdigit():
                continue
            base = "/proc/" + name
            item = {"pid": int(name)}
            try:
                with open(base + "/stat", "rb") as fh:
                    raw = fh.read().decode("utf-8", "replace")
                comm_end = raw.rfind(")")
                item["name"] = raw[raw.find("(") + 1: comm_end]
                fields = raw[comm_end + 2:].split()
                item["state"] = fields[0]
                item["ppid"] = int(fields[1])
                if boot is not None:
                    item["start_time"] = iso_epoch(boot + int(fields[19]) / clk)
                with open(base + "/cmdline", "rb") as fh:
                    item["cmdline"] = fh.read(65536).replace(b"\x00", b" ").decode(
                        "utf-8", "replace").strip()
                with open(base + "/status", "rb") as fh:
                    for line in fh.read().decode("utf-8", "replace").splitlines():
                        if line.startswith("Uid:"):
                            item["uid"] = int(line.split()[1])
            except (OSError, ValueError, IndexError):
                pass  # the process exited while being read
            try:
                item["exe"] = os.readlink(base + "/exe")
            except OSError:
                pass
            try:
                item["cwd"] = os.readlink(base + "/cwd")
            except OSError:
                pass
            procs.append(item)
        return procs

    def boot_time(self):
        for line in (self.read_text("/proc/stat") or "").splitlines():
            if line.startswith("btime "):
                return int(line.split()[1])
        return None

    def sockets(self):
        owners = {}
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            fd_dir = "/proc/%s/fd" % name
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    link = os.readlink(fd_dir + "/" + fd)
                except OSError:
                    continue
                if link.startswith("socket:["):
                    owners[link[8:-1]] = int(name)
        rows = []
        states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
                  "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
                  "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            text = self.read_text("/proc/net/" + proto) or ""
            for line in text.splitlines()[1:]:
                cols = line.split()
                if len(cols) < 10:
                    continue
                local, remote = decode_addr(cols[1]), decode_addr(cols[2])
                rows.append({
                    "proto": proto, "local": local, "remote": remote,
                    "state": states.get(cols[3], cols[3]) if proto.startswith("tcp") else None,
                    "uid": int(cols[7]) if cols[7].isdigit() else None,
                    "inode": cols[9], "pid": owners.get(cols[9]),
                })
        return rows

    def listing(self, host_dir):
        out = []
        stack = [host_dir]
        while stack and len(out) < MAX_LISTING:
            current = stack.pop()
            try:
                with os.scandir(self.host(current)) as it:
                    items = list(it)
            except FileNotFoundError:
                continue
            except OSError as exc:
                self.error(current, exc)
                continue
            for item in items:
                path = current.rstrip("/") + "/" + item.name
                try:
                    st = item.stat(follow_symlinks=False)
                except OSError:
                    continue
                kind = ("dir" if stat.S_ISDIR(st.st_mode) else "symlink"
                        if stat.S_ISLNK(st.st_mode) else "file"
                        if stat.S_ISREG(st.st_mode) else "other")
                row = {"path": path, "type": kind, "size": st.st_size,
                       "mode": oct(stat.S_IMODE(st.st_mode)), "uid": getattr(st, "st_uid", None),
                       "mtime": iso_epoch(st.st_mtime), "ctime": iso_epoch(st.st_ctime)}
                if kind == "symlink":
                    try:
                        row["target"] = os.readlink(item.path)[:4096]
                    except OSError:
                        pass
                out.append(row)
                if kind == "dir" and path.count("/") < 12:
                    stack.append(path)
        return out

    # -------------------------------------------------------------- phases

    def collect(self):
        os.makedirs(self.out_dir, exist_ok=True)
        if os.path.lexists(self.zip_path):
            raise OSError(errno.EEXIST, "bundle already exists", self.zip_path)
        self.zip = zipfile.ZipFile(self.partial_path, "x", zipfile.ZIP_DEFLATED, allowZip64=True)
        try:
            if self.live and not self.args.no_volatile:
                self.collect_volatile()
            if not self.args.no_logs:
                self.collect_logs()
            if not self.args.no_files:
                self.collect_files()
            self.write_manifest()
        finally:
            self.zip.close()
        # Publish only after the archive is complete so interrupted collection leaves a partial
        # artifact instead of a file that could be mistaken for finalized evidence.
        os.rename(self.partial_path, self.zip_path)
        digest = file_sha256(self.zip_path)
        with open(self.zip_path + ".sha256", "x") as fh:
            fh.write("%s  %s\n" % (digest, os.path.basename(self.zip_path)))
        return digest

    def collect_volatile(self):
        steps = (
            ("volatile/processes.json", self.processes),
            ("volatile/connections.json", self.sockets),
        )
        for arcname, fn in steps:
            try:
                self.add_json(arcname, fn(), "volatile", "/proc")
            except Exception as exc:  # noqa: BLE001 - never abort the collection
                self.error(arcname, exc)
        for arcname, argv in COMMANDS:
            self.run(argv, arcname, arcname.split("/")[0])
        for proc_file in ("/proc/net/arp", "/proc/net/route", "/proc/modules", "/proc/mounts",
                          "/proc/cmdline", "/proc/uptime"):
            text = self.read_text(proc_file)
            if text is not None:
                self.add_bytes(self.arcname("volatile", proc_file), text.encode("utf-8"),
                               "volatile", proc_file)

    def collect_logs(self):
        for path in self.entries("/var/log", LOG_PATTERNS):
            self.add_file(path, "logs")
        for sub, patterns in sorted(LOG_SUBDIRS.items()):
            for path in self.entries("/var/log/" + sub, patterns):
                self.add_file(path, "logs")
        if self.live and self.args.journal_days > 0:
            self.journal()

    def collect_files(self):
        for path in SYSTEM_FILES:
            self.add_file(path, "system", quiet_missing=True)
        for path in ACCOUNT_FILES:
            self.add_file(path, "files")
        for path in PERSISTENCE_FILES:
            self.add_file(path, "persistence", quiet_missing=True)
        for directory in PERSISTENCE_DIRS:
            for path in self.entries(directory):
                self.add_file(path, "persistence")
        systemd = []
        for directory in SYSTEMD_DIRS:
            systemd.extend(self.listing(directory))
            for path in self.entries(directory, recursive=True):
                self.add_file(path, "persistence")
        self.add_json("persistence/systemd_listing.json", systemd, "persistence",
                      "listing of " + ", ".join(SYSTEMD_DIRS))
        for directory in LISTING_DIRS:
            if not os.path.isdir(self.host(directory)):
                continue
            rows = self.listing(directory)
            self.add_json(self.arcname("volatile", directory + "_listing.json"), rows,
                          "volatile", "listing of " + directory)
        seen = set()
        for _user, home in self.users() + [("root", "/root")]:
            if home in seen or home in ("/", "/nonexistent") or home.startswith("/proc"):
                continue
            seen.add(home)
            for rel in USER_FILES:
                path = home.rstrip("/") + "/" + rel
                if rel == ".config/autostart":
                    for item in self.entries(path):
                        self.add_file(item, "files")
                else:
                    self.add_file(path, "files", quiet_missing=True)

    def clock(self):
        info = {"source": None, "synchronized": None, "ntp_offset_s": None}
        if self.live:
            try:
                proc = subprocess.Popen(
                    ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                    env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                )
                try:
                    raw = proc.communicate(timeout=10)[0]
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    raw = b""
                out = raw.decode("ascii", "replace").strip()
                info["source"] = "timedatectl"
                info["synchronized"] = {"yes": True, "no": False}.get(out)
            except OSError:
                pass
        if self.args.ntp_server:
            offset = sntp_offset(self.args.ntp_server)
            info["ntp_offset_s"] = offset
            info["ntp_server"] = self.args.ntp_server
        return info

    def write_manifest(self):
        finished = utcnow()
        offset = None
        if self.live:
            offset = int(time.localtime().tm_gmtoff // 60)
        elevated = None
        if hasattr(os, "geteuid"):
            elevated = os.geteuid() == 0
        manifest = {
            "schema": SCHEMA,
            "collector": {
                "name": NAME,
                "version": VERSION,
                "sha256": file_sha256(os.path.realpath(__file__)),
                "runtime": "python %s" % platform.python_version(),
            },
            "host": {
                "hostname": self.hostname,
                "fqdn": None,
                "os": self._os_name(),
                "timezone": self._timezone(),
                "utc_offset_minutes": offset,
                "boot_time": iso_epoch(self.boot_time()) if self.live and self.boot_time()
                else None,
            },
            "operator": self.args.operator or os.environ.get("SUDO_USER") or getpass.getuser(),
            "case_ref": self.args.case_ref,
            "mode": "live" if self.live else "offline",
            "root": self.root,
            "elevated": elevated,
            "started_at": iso(self.started),
            "finished_at": iso(finished),
            "clock": self.clock(),
            "limits": {"max_file_mb": self.args.max_file_mb,
                       "max_total_mb": self.args.max_total_mb},
            "files": self.files,
            "errors": self.errors,
            "skipped": self.skipped,
        }
        data = json.dumps(manifest, indent=1, ensure_ascii=False).encode("utf-8")
        with self.zip.open(self._zipinfo("manifest.json"), "w") as dst:
            dst.write(data)


def decode_addr(value):
    try:
        host, port = value.split(":")
        raw = bytes.fromhex(host)
        if len(raw) == 4:
            addr = socket.inet_ntop(socket.AF_INET, raw[::-1])
        else:
            words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            addr = socket.inet_ntop(socket.AF_INET6, words)
        return "%s:%d" % (addr, int(port, 16))
    except (ValueError, OSError):
        return value


def sntp_offset(server, timeout=3.0):
    """One SNTP (RFC 4330) query; only with --ntp-server. Returns seconds or None."""
    packet = b"\x1b" + 47 * b"\0"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            t0 = time.time()
            sock.sendto(packet, (server, 123))
            data, _ = sock.recvfrom(48)
            t3 = time.time()
    except OSError:
        return None
    if len(data) < 48:
        return None
    epoch = 2208988800
    secs, frac = struct.unpack("!II", data[32:40])
    t1 = secs - epoch + frac / 2 ** 32
    secs, frac = struct.unpack("!II", data[40:48])
    t2 = secs - epoch + frac / 2 ** 32
    return round(((t1 - t0) + (t2 - t3)) / 2, 6)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="dfirbench Linux triage collector (read-only).")
    p.add_argument("--output", required=True, help="output directory (use external media)")
    p.add_argument("--root", default="/", help="collect from a mounted image instead of /")
    p.add_argument("--case-ref", default=None)
    p.add_argument("--operator", default=None)
    p.add_argument("--no-volatile", action="store_true")
    p.add_argument("--no-logs", action="store_true")
    p.add_argument("--no-files", action="store_true")
    p.add_argument("--max-file-mb", type=int, default=1024)
    p.add_argument("--max-total-mb", type=int, default=8192)
    p.add_argument("--journal-days", type=int, default=14)
    p.add_argument("--ntp-server", default=None, help="measure clock offset (one UDP query)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.max_file_mb < 1 or args.max_total_mb < 1:
        print("error: size limits must be positive", file=sys.stderr)
        return 2
    root = os.path.abspath(args.root)
    out = os.path.abspath(args.output)
    if not os.path.isdir(root):
        print("error: --root is not a directory", file=sys.stderr)
        return 2
    if args.root != "/" and (out + os.sep).startswith(root.rstrip(os.sep) + os.sep):
        print("error: --output must not be inside --root (the source stays untouched)",
              file=sys.stderr)
        return 2
    collector = Collector(args)
    digest = collector.collect()
    print("bundle:  %s" % collector.zip_path)
    print("sha256:  %s" % digest)
    print("files:   %d collected, %d errors, %d skipped"
          % (len(collector.files), len(collector.errors), len(collector.skipped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
