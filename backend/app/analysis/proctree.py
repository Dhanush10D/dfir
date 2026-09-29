"""Process tree builder (guide 12.6). Pure, bounded, cycle-safe.

Nodes come from process-create events (Sysmon 1, Security 4688: ``kind="created"``) and from other
events that carry a pid (``kind="observed"``: one node per (pid, name) not explained by a create).
Parent resolution, in order:

1. ``parent_guid`` equals another node's ``guid`` (Sysmon ProcessGuid/ParentProcessGuid);
2. the latest node with ``pid == ppid`` that started at or before the child (PID reuse safe);
3. a synthetic parent node for the ppid (named from ``parent_name`` when known).

A parent link that would close a cycle (hostile or clock-skewed data) is refused and counted;
nodes deeper than ``max_depth`` are dropped and counted; at most ``max_nodes`` nodes are built.
Output is a DFS pre-order list with depth, so a UI can render it without recursion.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

MAX_NODES = 5000
MAX_DEPTH = 128

# Suspicious parent -> child pairs (lowercase image basenames).
OFFICE_LIKE = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
        "mspub.exe",
        "acrord32.exe",
        "mshta.exe",
        "wmiprvse.exe",
    }
)
SHELLS_AND_LOLBINS = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
    }
)
GUID_RE = re.compile(r"^\{?([0-9a-fA-F-]{32,36})\}?$")


def basename(value: str | None) -> str | None:
    if not value:
        return None
    return re.split(r"[\\/]", value)[-1].strip().lower() or None


def norm_guid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    m = GUID_RE.match(value.strip())
    if not m:
        return None
    guid = m.group(1).lower()
    return None if set(guid) <= {"0", "-"} else guid


@dataclass(frozen=True)
class ProcEvent:
    event_id: str
    ts: datetime
    pid: int
    ppid: int | None = None
    name: str | None = None
    image: str | None = None
    cmdline: str | None = None
    user: str | None = None
    guid: str | None = None
    parent_guid: str | None = None
    parent_name: str | None = None
    created: bool = False


@dataclass
class ProcNode:
    key: str
    pid: int | None
    name: str | None
    kind: str  # created | observed | synthetic
    ts: datetime | None = None
    ppid: int | None = None
    image: str | None = None
    cmdline: str | None = None
    user: str | None = None
    event_id: str | None = None
    guid: str | None = None
    parent: str | None = None
    depth: int = 0
    children: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class ProcessTree:
    nodes: list[ProcNode]
    roots: list[str]
    truncated: bool
    cycles_broken: int
    depth_capped: int


def build_tree(
    events: list[ProcEvent], *, max_nodes: int = MAX_NODES, max_depth: int = MAX_DEPTH
) -> ProcessTree:
    nodes: dict[str, ProcNode] = {}
    by_guid: dict[str, str] = {}
    by_pid: dict[int, list[tuple[datetime, str]]] = {}
    observed: dict[tuple[int, str | None], str] = {}
    truncated = False

    def add(node: ProcNode) -> bool:
        nonlocal truncated
        if len(nodes) >= max_nodes:
            truncated = True
            return False
        nodes[node.key] = node
        return True

    ordered = sorted(events, key=lambda e: (e.ts, not e.created, e.event_id))
    pending: list[tuple[str, ProcEvent]] = []
    for ev in ordered:
        name = basename(ev.name) or basename(ev.image)
        guid = norm_guid(ev.guid)
        if ev.created:
            if guid and guid in by_guid:
                continue  # the same process logged twice
            key = f"g:{guid}" if guid else f"e:{ev.event_id}"
        else:
            # An observed event belongs to the latest created node with that pid and name.
            starts = by_pid.get(ev.pid, [])
            i = bisect.bisect_right(starts, (ev.ts, "￿")) - 1
            if i >= 0 and nodes[starts[i][1]].name == name:
                continue
            if (ev.pid, name) in observed:
                continue
            key = f"o:{ev.pid}:{name or '?'}"
        node = ProcNode(
            key=key,
            pid=ev.pid,
            name=name,
            kind="created" if ev.created else "observed",
            ts=ev.ts,
            ppid=ev.ppid,
            image=ev.image,
            cmdline=ev.cmdline,
            user=ev.user,
            event_id=ev.event_id,
            guid=guid,
        )
        if not add(node):
            break
        if guid:
            by_guid[guid] = key
        if ev.created:
            bisect.insort(by_pid.setdefault(ev.pid, []), (ev.ts, key))
        else:
            observed[(ev.pid, name)] = key
        pending.append((key, ev))

    cycles = 0

    def creates_cycle(child: str, parent: str) -> bool:
        seen = 0
        cur: str | None = parent
        while cur is not None:
            if cur == child:
                return True
            seen += 1
            if seen > len(nodes):  # defensive: an existing loop
                return True
            cur = nodes[cur].parent
        return False

    for key, ev in pending:
        node = nodes[key]
        parent_key: str | None = None
        pguid = norm_guid(ev.parent_guid)
        if pguid and pguid in by_guid and by_guid[pguid] != key:
            parent_key = by_guid[pguid]
        elif ev.ppid is not None and ev.ppid != ev.pid:
            starts = by_pid.get(ev.ppid, [])
            i = bisect.bisect_right(starts, (ev.ts, "￿")) - 1
            while i >= 0 and starts[i][1] == key:
                i -= 1
            if i >= 0:
                parent_key = starts[i][1]
            else:
                pname = basename(ev.parent_name)
                parent_key = f"s:{ev.ppid}:{pname or '?'}"
                if parent_key not in nodes and not add(
                    ProcNode(key=parent_key, pid=ev.ppid, name=pname, kind="synthetic")
                ):
                    parent_key = None
        if parent_key is None:
            continue
        if creates_cycle(key, parent_key):
            cycles += 1
            node.flags.append("cycle_broken")
            continue
        node.parent = parent_key
        nodes[parent_key].children.append(key)
        pname = nodes[parent_key].name
        if pname in OFFICE_LIKE and node.name in SHELLS_AND_LOLBINS:
            node.flags.append("suspicious_parent")

    # DFS pre-order from the roots (iterative), depth-capped.
    def order(k: str) -> tuple[bool, float, str]:
        ts = nodes[k].ts
        return (ts is None, ts.timestamp() if ts else 0.0, k)

    roots = sorted((k for k, n in nodes.items() if n.parent is None), key=order)
    out: list[ProcNode] = []
    depth_capped = 0
    stack: list[tuple[str, int]] = [(k, 0) for k in reversed(roots)]
    visited: set[str] = set()
    while stack:
        key, depth = stack.pop()
        if key in visited:
            continue
        visited.add(key)
        node = nodes[key]
        if depth > max_depth:  # drop the whole subtree below the cap, counting it
            depth_capped += 1
            stack.extend((k, depth + 1) for k in node.children)
            continue
        node.depth = depth
        out.append(node)
        kids = sorted(node.children, key=order)
        stack.extend((k, depth + 1) for k in reversed(kids))
    keep = {n.key for n in out}
    for n in out:
        n.children = [c for c in n.children if c in keep]
    return ProcessTree(out, roots, truncated, cycles, depth_capped)
