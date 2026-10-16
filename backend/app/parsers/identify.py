"""Evidence kind identification from a file's name, head and tail (pure; no I/O).

The upload form calls this before the upload so the analyst does not have to pick the kind. It uses
the same parser detection as automatic parser selection (``registry.detect``), so the kind it
suggests and the parser that later runs agree. A triage bundle is a ZIP whose central directory
(at the end of the file, hence the tail) lists ``manifest.json``.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.parsers.registry import detect

HEAD_BYTES = 8192  # same window as automatic parser selection (services/jobs.py)
TAIL_BYTES = 65536

# parser name -> (evidence kind, what the file is)
PARSER_KINDS: dict[str, tuple[str, str]] = {
    "evtx": ("evtx", "Windows event log"),
    "pcap": ("pcap", "Packet capture"),
    "zeek": ("pcap", "Packet capture"),
    "linux_auth": ("log", "Linux auth / syslog log"),
    "journal_json": ("log", "systemd journal export (JSON)"),
    "wtmp": ("log", "Linux login records (wtmp/btmp/utmp)"),
    "shell_history": ("log", "Shell history"),
    "web_access": ("log", "Web server access log (Apache/Nginx)"),
    "w3c": ("log", "W3C extended log (Windows Firewall / IIS)"),
    "csv_events": ("log", "CSV export with a timestamp column"),
    "registry_hive": ("file", "Windows registry hive"),
    "amcache": ("file", "Windows Amcache hive"),
    "prefetch": ("file", "Windows Prefetch file"),
    "lnk": ("file", "Windows shortcut (LNK)"),
    "browser": ("file", "Browser history database"),
    "pe_static": ("file", "Windows executable (PE)"),
    "tsk_fs": ("disk_image", "Disk image"),
    "volatility": ("memory", "Memory image"),
}
ZIP_MAGIC = b"PK\x03\x04"
BUNDLE_MANIFEST = b"manifest.json"


@dataclass(frozen=True)
class Identification:
    kind: str
    parser: str | None  # the parser that Process will run; None: no automatic parser
    confidence: float
    description: str


def _is_bundle(head: bytes, tail: bytes) -> bool:
    if not head.startswith(ZIP_MAGIC):
        return False
    # Central directory entries ("PK\x01\x02" + 42 fixed bytes + name) list every member.
    data = head + tail
    start = 0
    while (pos := data.find(b"PK\x01\x02", start)) != -1:
        name_len = int.from_bytes(data[pos + 28 : pos + 30], "little")
        if data[pos + 46 : pos + 46 + name_len] == BUNDLE_MANIFEST:
            return True
        start = pos + 4
    return False


def identify(filename: str, head: bytes, tail: bytes = b"") -> Identification:
    head, tail = head[:HEAD_BYTES], tail[-TAIL_BYTES:]
    if _is_bundle(head, tail):
        return Identification("triage_bundle", None, 0.9, "Triage bundle (ZIP with manifest.json)")
    for name, score in detect(head, filename):
        if name in PARSER_KINDS:
            kind, description = PARSER_KINDS[name]
            return Identification(kind, name, round(score, 2), description)
    if head.startswith(ZIP_MAGIC):
        return Identification("file", None, 0.0, "ZIP archive (not a dfirbench triage bundle)")
    return Identification(
        "file", None, 0.0, "Not recognised: stored as a file, no automatic parser"
    )
