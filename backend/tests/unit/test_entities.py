"""Entity normalization and resolution (guide 12.3): deterministic, order independent, capped."""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.analysis.entities import (
    EntityAccumulator,
    Resolution,
    normalize_hash,
    normalize_host,
    normalize_ip,
    normalize_process,
    normalize_sid,
    normalize_user,
)

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "golden"
T0 = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)


def test_normalizers() -> None:
    assert normalize_host("WS-042") == ("ws-042", [("hostname", "ws-042")])
    assert normalize_host("WS-042.Corp.Local.") == (
        "ws-042",
        [("hostname", "ws-042.corp.local"), ("fqdn", "ws-042.corp.local")],
    )
    for bad in (None, "", "-", "10.0.0.1", "a b", "localhost", "x" * 600, "a\\b"):
        assert normalize_host(bad) is None, bad
    assert normalize_ip("10.0.4.17") == ("10.0.4.17", "private")
    assert normalize_ip("2001:DB8::0:1") == ("2001:db8::1", "private")
    assert normalize_ip("::ffff:8.8.8.8") == ("8.8.8.8", "public")
    assert normalize_ip("127.0.0.1")[1] == "loopback"  # type: ignore[index]
    assert normalize_ip("999.1.1.1") is None
    assert normalize_user("CORP\\Alice") == ("corp\\alice", [("name", "corp\\alice")])
    assert normalize_user("Alice@Corp.Local") == (
        "corp\\alice",
        [("name", "alice@corp.local"), ("upn", "alice@corp.local")],
    )
    assert normalize_user("alice", "CORP") == ("corp\\alice", [("name", "alice")])
    assert normalize_user("deploy") == ("deploy", [("name", "deploy")])
    for bad in (None, "", "-", "NULL SID", "S-1-5-18", "CORP\\-", "N/A"):
        assert normalize_user(bad) is None, bad
    assert normalize_sid("s-1-5-21-1-2-3-1104") == "S-1-5-21-1-2-3-1104"
    assert normalize_sid("S-1-0-0") is None and normalize_sid("alice") is None
    assert normalize_hash("A" * 64) == ("a" * 64, "sha256")
    assert normalize_hash("b" * 32) == ("b" * 32, "md5")
    assert normalize_hash("0" * 40) is None and normalize_hash("xyz") is None
    assert normalize_process("ws-042", "C:\\Windows\\System32\\CMD.EXE") == "ws-042/cmd.exe"
    assert normalize_process(None, "/usr/sbin/sshd") == "sshd"


def _events() -> list[dict[str, Any]]:
    ed = "raw.event_data."
    return [
        {"id": 1, "ts": T0, "host": "WS-042", "user": "CORP\\alice", "event_category":
         "authentication", "outcome": "success", "src_ip": "1.1.1.1"},
        {"id": 2, "ts": T0 + timedelta(minutes=1), "host": "ws-042.corp.local",
         "user": "alice@corp.local", "event_category": "process", "process_name":
         "C:\\Windows\\System32\\cmd.exe", "file_hash": "A" * 64},
        # EVTX-style: the subject SID and name are stated together -> strong merge
        {"id": 3, "ts": T0 + timedelta(minutes=2), "host": "DC01", "user": "CORP\\bob",
         ed + "SubjectUserSid": "S-1-5-21-1-2-3-1104", ed + "SubjectUserName": "bob",
         ed + "SubjectDomainName": "CORP", "event_category": "authentication",
         "outcome": "failure"},
        # SID only (e.g. a group membership event): resolves to the same user
        {"id": 4, "ts": T0 + timedelta(minutes=3), "host": "DC01", "user": "S-1-5-21-1-2-3-1104"},
        {"id": 5, "ts": T0 + timedelta(minutes=4), "host": "WS-042", "dst_ip": "10.0.0.5",
         "user": "-"},
    ]  # fmt: skip


def _resolve(events: list[dict[str, Any]], **kw: Any) -> Resolution:
    acc = EntityAccumulator(**kw)
    for ev in events:
        acc.feed(ev)
    return acc.result()


def test_resolution_merges_strong_identifiers() -> None:
    res = _resolve(_events())
    keys = set(res.entities)
    assert ("host", "ws-042") in keys and ("host", "dc01") in keys
    assert ("user", "corp\\alice") in keys and ("user", "corp\\bob") in keys
    assert not any(k[0] == "sid" or k[1].startswith("S-1-") for k in keys)
    bob = res.entities[("user", "corp\\bob")]
    assert ("sid", "S-1-5-21-1-2-3-1104") in bob.aliases
    assert bob.first_seen == T0 + timedelta(minutes=2) and bob.last_seen == T0 + timedelta(
        minutes=3
    )
    host = res.entities[("host", "ws-042")]
    assert ("fqdn", "ws-042.corp.local") in host.aliases and host.event_count == 3
    assert ("ip", "1.1.1.1") in keys and res.entities[("ip", "1.1.1.1")].attributes == {
        "scope": "public"
    }
    rel = {(l.src, l.dst, l.relation) for l in res.links}  # noqa: E741
    assert (("user", "corp\\alice"), ("host", "ws-042"), "logged_on") in rel
    assert (("user", "corp\\bob"), ("host", "dc01"), "failed_logon") in rel
    assert (("user", "corp\\bob"), ("host", "dc01"), "seen_on") in rel  # sid-only event
    assert (("ip", "1.1.1.1"), ("host", "ws-042"), "connected_to") in rel
    assert (("host", "ws-042"), ("ip", "10.0.0.5"), "connected_to") in rel
    assert (("user", "corp\\alice"), ("process", "ws-042/cmd.exe"), "executed") in rel
    assert (("process", "ws-042/cmd.exe"), ("hash", "a" * 64), "has_hash") in rel


def test_resolution_is_order_independent() -> None:
    events = _events()
    expected = _resolve(events)
    for seed in range(5):
        shuffled = events[:]
        random.Random(seed).shuffle(shuffled)
        got = _resolve(shuffled)
        assert list(got.entities) == list(expected.entities)
        assert [(l.src, l.dst, l.relation, l.weight) for l in got.links] == [  # noqa: E741
            (l.src, l.dst, l.relation, l.weight)
            for l in expected.links  # noqa: E741
        ]
        for key, ent in expected.entities.items():
            assert got.entities[key].aliases == ent.aliases
            assert (got.entities[key].first_seen, got.entities[key].last_seen) == (
                ent.first_seen,
                ent.last_seen,
            )


def test_caps_are_reported() -> None:
    events = [{"id": i, "ts": T0, "host": f"h{i}", "user": f"u{i}"} for i in range(20)]
    res = _resolve(events, max_entities=10, max_links=3)
    assert res.capped and len(res.entities) <= 10 and len(res.links) <= 3


@pytest.mark.parametrize("golden", ["evtx_new_user_security", "linux_auth_utc"])
def test_real_parser_output(golden: str) -> None:
    data = json.loads((GOLDEN / f"{golden}.json").read_text(encoding="utf-8"))
    acc = EntityAccumulator()
    for ev in data["events"]:
        row = {k: v for k, v in ev.items() if k != "raw"}
        row["ts"] = datetime.fromisoformat(ev["ts"])
        for key, value in (ev.get("raw") or {}).get("event_data", {}).items():
            row[f"raw.event_data.{key}"] = value
        acc.feed(row)
    res = acc.result()
    types = {k[0] for k in res.entities}
    if golden.startswith("evtx"):
        assert ("host", "ie8win7") in res.entities
        machine = res.entities[("user", "workgroup\\win-qala5q3kj43$")]
        # S-1-5-18 (SYSTEM) is well known: it stays its own node instead of merging hosts.
        assert ("sid", "S-1-5-18") not in machine.aliases
        assert ("user", "S-1-5-18") in res.entities
        admins = res.entities[("user", "builtin\\administrators")]
        assert ("sid", "S-1-5-32-544") in admins.aliases  # one group everywhere: still merged
    else:
        assert {"host", "user", "ip", "process"} <= types
        assert ("user", "deploy") in res.entities and ("process", "web01/sshd") in res.entities


def test_well_known_sids_do_not_merge_machine_accounts_across_hosts() -> None:
    # EVTX 4624/4688 put SubjectUserSid=S-1-5-18 next to SubjectUserName=<HOST>$ on every host.
    events = [
        {
            "id": i,
            "ts": T0,
            "host": host,
            "event_category": "process",
            "raw.event_data.SubjectUserSid": "S-1-5-18",
            "raw.event_data.SubjectUserName": f"{host}$",
            "raw.event_data.SubjectDomainName": "CORP",
        }
        for i, host in enumerate(["ws01", "ws02", "dc01"])
    ]
    res = _resolve(events)
    users = [e for e in res.entities.values() if e.type == "user"]
    assert len(users) >= 3, [(u.canonical, u.aliases) for u in users]


def test_sysmon_prefixed_hashes_normalize() -> None:
    assert normalize_hash("sha256:" + "ab" * 32) == ("ab" * 32, "sha256")
    assert normalize_hash("SHA256:" + "AB" * 32) == ("ab" * 32, "sha256")
