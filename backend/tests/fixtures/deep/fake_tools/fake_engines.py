"""Stand-ins for mmls / fls / vol / zeek / misbehaving tools (unit tests only).

Invoked as ``python fake_engines.py <tool> <argv...>`` through the launchers built by
``tests/unit/deep_helpers.py``. Output is fixed so golden files are deterministic. Every fake
first checks that the wrapper passed a clean environment (no DATABASE_URL / S3 secrets).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

SECRETS = ("DATABASE_URL", "S3_SECRET_KEY", "JWT_SECRET", "DFIR_FAKE_SECRET")


def check_env() -> None:
    leaked = [k for k in SECRETS if k in os.environ]
    if leaked:
        sys.stderr.write(f"environment leaked: {leaked}\n")
        sys.exit(97)


BODY_P0 = [
    "0|/p00/Windows/System32/cmd.exe|128-128-1|r/rrwxrwxrwx|0|0|289792|1767340800|1767340800|1767340800|1767340800",
    "0|/p00/Users/Public/evil.exe|200-128-1|r/rrwxrwxrwx|0|0|73728|1767348060|1767348030|1767348030|1767347990",
    "0|/p00/Users/Public/gone.txt (deleted)|201-128-1|r/rrwxrwxrwx|0|0|5|0|0|0|0",
    "d41d8cd98f00b204e9800998ecf8427e|/p00/odd|name.txt|202-128-1|r/rrwxrwxrwx|0|0|1|1767348100|1767348100|1767348100|1767348100",
    "garbage line without fields",
]
MMLS = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0000208895   0000002048   Linux Swap (0x82)
"""

VOL = {
    "windows.info": [
        {"Variable": "Kernel Base", "Value": "0xf80000000000", "__children": []},
        {"Variable": "SystemTime", "Value": "2026-01-02 10:30:00+00:00", "__children": []},
    ],
    "windows.pslist": [
        {
            "PID": 4,
            "PPID": 0,
            "ImageFileName": "System",
            "CreateTime": "2026-01-02T08:00:00+00:00",
            "ExitTime": None,
            "__children": [
                {
                    "PID": 666,
                    "PPID": 4,
                    "ImageFileName": "evil.exe",
                    "CreateTime": "2026-01-02T10:00:30+00:00",
                    "ExitTime": None,
                    "__children": [],
                }
            ],
        }
    ],
    "windows.cmdline": [
        {"PID": 666, "Process": "evil.exe", "Args": "evil.exe -k -c 203.0.113.50", "__children": []}
    ],
    "windows.netscan": [
        {
            "Offset": 1,
            "Proto": "TCPv4",
            "LocalAddr": "192.0.2.10",
            "LocalPort": 49160,
            "ForeignAddr": "203.0.113.50",
            "ForeignPort": 443,
            "State": "ESTABLISHED",
            "PID": 666,
            "Owner": "evil.exe",
            "Created": "2026-01-02T10:00:40+00:00",
            "__children": [],
        }
    ],
}

ZEEK = {
    "conn.log": [
        {
            "ts": 1767348000.25,
            "uid": "CAbc1",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 49152,
            "id.resp_h": "203.0.113.10",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "conn_state": "SF",
        }
    ],
    "dns.log": [
        {
            "ts": 1767348001.0,
            "uid": "CDef2",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 53000,
            "id.resp_h": "198.51.100.53",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "evil.example",
            "answers": ["203.0.113.10"],
        }
    ],
    "ssl.log": [
        {
            "ts": 1767348002.0,
            "uid": "CGhi3",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 49153,
            "id.resp_h": "203.0.113.20",
            "id.resp_p": 443,
            "server_name": "c2.example",
        },
        {"ts": "not-a-number", "uid": "CBad4"},
    ],
}


def main() -> int:
    tool, args = sys.argv[1], sys.argv[2:]
    check_env()
    if tool == "mmls":
        if args and args[0] == "-V":
            print("The Sleuth Kit ver 4.11.1")
            return 0
        sys.stdout.write(MMLS)
        return 0
    if tool == "mmls_none":
        sys.stderr.write("Cannot determine partition type\n")
        return 1
    if tool == "fls":
        if (
            "-o" in args
            and args[args.index("-o") + 1] != "2048"
            and args[args.index("-o") + 1] != "0"
        ):
            sys.stderr.write("Cannot determine file system type\n")
            return 1
        sys.stdout.write("\n".join(BODY_P0) + "\n")
        return 0
    if tool == "vol":
        if "--offline" not in args or "-r" not in args:
            sys.stderr.write("wrapper must run offline with a renderer\n")
            return 2
        plugin = args[-1]
        if plugin not in VOL:
            sys.stderr.write("Unsatisfied requirement plugins.Malfind.kernel.symbol_table_name\n")
            return 1
        sys.stdout.write(json.dumps(VOL[plugin], indent=2))
        return 0
    if tool == "zeek":
        for name, rows in ZEEK.items():
            Path(name).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return 0
    if tool == "sleep":
        time.sleep(30)
        return 0
    if tool == "flood":
        chunk = "x" * 65536
        for _ in range(64):
            sys.stdout.write(chunk)
            sys.stdout.flush()
            time.sleep(0.02)
        time.sleep(10)
        return 0
    if tool == "envdump":
        print(json.dumps(sorted(os.environ)))
        return 0
    return 3


if __name__ == "__main__":
    sys.exit(main())
