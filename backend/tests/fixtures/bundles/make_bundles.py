"""Build the triage bundle fixtures (good + malicious) in this directory.

    backend/.venv/Scripts/python backend/tests/fixtures/bundles/make_bundles.py

The zips are committed; tests read them. Every archive is small: the "bomb" fixture is a 50 MiB
run of zeros that deflates to ~50 KiB (ratio ~1000, over the 200 limit).
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import struct
import zipfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
EVTX = (FIXTURES / "evtx" / "new_user_security.evtx").read_bytes()
WHEN = (2026, 1, 3, 0, 0, 0)
COLLECTED = "2026-01-03T00:00:00Z"
PROCESSES = json.dumps([{"pid": 1, "ppid": 0, "name": "init", "cmdline": "/sbin/init"}]).encode()


def entry(path: str, data: bytes, category: str = "logs", **extra: Any) -> dict[str, Any]:
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "category": category,
        "source": "/" + path.split("/", 1)[-1],
        "collected_at": COLLECTED,
        **extra,
    }


def manifest(files: list[dict[str, Any]], **extra: Any) -> bytes:
    body: dict[str, Any] = {
        "schema": "dfirbench.triage/1",
        "collector": {
            "name": "dfirbench-collect-linux",
            "version": "1.0.0",
            "sha256": "0" * 64,
            "runtime": "python 3.12",
        },
        "host": {"hostname": "web01", "os": "Test Linux", "timezone": "UTC"},
        "operator": "fixture",
        "case_ref": "IR-FIXTURE",
        "mode": "offline",
        "elevated": True,
        "started_at": "2026-01-03T00:00:00Z",
        "finished_at": "2026-01-03T00:01:00Z",
        "files": files,
        "errors": [{"target": "/etc/sudoers", "error": "PermissionError"}],
        "skipped": [],
    }
    body.update(extra)
    return json.dumps(body, indent=1).encode()


def info(name: str, mode: int = stat.S_IFREG | 0o444) -> zipfile.ZipInfo:
    zi = zipfile.ZipInfo("placeholder", date_time=WHEN)
    zi.filename = zi.orig_filename = name  # set after __init__: keeps backslashes verbatim
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3
    zi.external_attr = mode << 16
    return zi


def write(name: str, members: list[tuple[str, bytes]], **modes: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for member, data in members:
            zf.writestr(info(member, modes.get(member, stat.S_IFREG | 0o444)), data)
    raw = buf.getvalue()
    (HERE / name).write_bytes(raw)
    return raw


GOOD_FILES = [
    ("logs/var/log/auth.log", AUTH_LOG, "logs"),
    ("logs/Security.evtx", EVTX, "logs"),
    ("volatile/processes.json", PROCESSES, "volatile"),
]


def good() -> None:
    files = [entry(p, d, c) for p, d, c in GOOD_FILES]
    write("good.zip", [(p, d) for p, d, _ in GOOD_FILES] + [("manifest.json", manifest(files))])


def mismatch() -> None:
    """One good member, one with a wrong manifest hash, one unlisted, one listed but missing."""
    evtx_entry = entry("logs/Security.evtx", EVTX)
    evtx_entry["sha256"] = "f" * 64
    files = [
        entry("logs/var/log/auth.log", AUTH_LOG),
        evtx_entry,
        entry("logs/var/log/missing.log", b"never collected\n"),
    ]
    write(
        "mismatch.zip",
        [
            ("logs/var/log/auth.log", AUTH_LOG),
            ("logs/Security.evtx", EVTX),
            ("files/unlisted.txt", b"not in the manifest\n"),
            ("manifest.json", manifest(files)),
        ],
    )


def traversal() -> None:
    for name, member in (
        ("traversal_dotdot.zip", "../evil.txt"),
        ("traversal_nested.zip", "logs/../../evil.txt"),
        ("traversal_absolute.zip", "/etc/cron.d/evil"),
        ("traversal_drive.zip", "C:/Windows/System32/evil.dll"),
        ("traversal_backslash.zip", "logs\\..\\..\\evil.txt"),
    ):
        files = [entry("logs/var/log/auth.log", AUTH_LOG)]
        write(
            name,
            [
                ("logs/var/log/auth.log", AUTH_LOG),
                (member, b"* * * * * root /tmp/x\n"),
                ("manifest.json", manifest(files)),
            ],
        )


def symlink() -> None:
    target = b"../../../../etc/passwd"
    files = [entry("logs/var/log/auth.log", AUTH_LOG), entry("logs/link", target)]
    write(
        "symlink.zip",
        [
            ("logs/var/log/auth.log", AUTH_LOG),
            ("logs/link", target),
            ("manifest.json", manifest(files)),
        ],
        **{"logs/link": stat.S_IFLNK | 0o777},
    )


def bomb() -> None:
    zeros = b"\0" * (50 * 1024 * 1024)
    files = [entry("logs/zeros.bin", zeros)]
    write("bomb_ratio.zip", [("logs/zeros.bin", zeros), ("manifest.json", manifest(files))])
    many = [(f"logs/f{i:03d}.txt", f"{i}\n".encode()) for i in range(60)]
    files = [entry(p, d) for p, d in many]
    write("bomb_count.zip", [*many, ("manifest.json", manifest(files))])


def duplicates() -> None:
    files = [entry("logs/a.log", b"one\n")]
    with_dup = [("logs/a.log", b"one\n"), ("logs/a.log", b"two\n")]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # "Duplicate name" is the point of this fixture
            for member, data in [*with_dup, ("manifest.json", manifest(files))]:
                zf.writestr(info(member), data)
    (HERE / "duplicate.zip").write_bytes(buf.getvalue())
    write(
        "duplicate_case.zip",
        [("logs/A.log", b"one\n"), ("logs/a.log", b"two\n"), ("manifest.json", manifest(files))],
    )


def _central_entries(raw: bytes) -> list[int]:
    out, pos = [], raw.find(b"PK\x01\x02")
    while pos >= 0:
        out.append(pos)
        pos = raw.find(b"PK\x01\x02", pos + 4)
    return out


def encrypted_and_overlap() -> None:
    files = [entry("logs/var/log/auth.log", AUTH_LOG)]
    raw = bytearray(
        write(
            "encrypted.zip",
            [("logs/var/log/auth.log", AUTH_LOG), ("manifest.json", manifest(files))],
        )
    )
    first = _central_entries(bytes(raw))[0]
    flags = struct.unpack_from("<H", raw, first + 8)[0]
    struct.pack_into("<H", raw, first + 8, flags | 0x1)  # "encrypted" in the central directory
    (HERE / "encrypted.zip").write_bytes(bytes(raw))

    raw = bytearray(
        write(
            "overlap.zip",
            [
                ("logs/a.log", b"A" * 200),
                ("logs/b.log", b"B" * 200),
                ("manifest.json", manifest([entry("logs/a.log", b"A" * 200)])),
            ],
        )
    )
    second = _central_entries(bytes(raw))[1]
    struct.pack_into("<I", raw, second + 42, 0)  # b's local header offset -> a's header
    (HERE / "overlap.zip").write_bytes(bytes(raw))


def manifest_problems() -> None:
    write("no_manifest.zip", [("logs/var/log/auth.log", AUTH_LOG)])
    write(
        "bad_manifest.zip",
        [
            ("logs/var/log/auth.log", AUTH_LOG),
            (
                "manifest.json",
                manifest([{"path": "../../etc/passwd", "sha256": "0" * 64, "size": 1}]),
            ),
        ],
    )


def main() -> None:
    good()
    mismatch()
    traversal()
    symlink()
    bomb()
    duplicates()
    encrypted_and_overlap()
    manifest_problems()
    for path in sorted(HERE.glob("*.zip")):
        print(f"{path.name:28} {path.stat().st_size:>9} bytes")


if __name__ == "__main__":
    main()
