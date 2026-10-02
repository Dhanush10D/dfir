"""Entity extraction, normalization and resolution (guide 12.3). Pure and deterministic.

Normalization (identifiers -> canonical keys):

* host: lowercase, trailing dot removed; canonical = first DNS label (short name); the observed
  name and the FQDN are aliases. A "host" that is an IP address becomes an ip entity.
* user: ``DOMAIN\\name`` -> ``domain\\name``; ``name@corp.local`` (UPN) -> ``corp\\name`` (first
  domain label); bare ``name`` stays ``name``. SIDs are aliases. Placeholders (``-``, ``NULL SID``,
  ``S-1-0-0``, empty) are ignored.
* ip: canonical text from :mod:`ipaddress`; attribute ``scope``.
* process: ``host/image-basename`` (lowercase): an executable on a host.
* hash: lowercase hex of length 32/40/64 (``algo`` md5/sha1/sha256); anything else is ignored.

Resolution: identifiers that one event states together (an EVTX SID next to its account name) are
merged with union-find; the group canonical is chosen deterministically (smallest ``domain\\name``,
else smallest bare name, else smallest SID), so the result does not depend on event order.
Weak evidence (same IP at different times) never merges.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

MAX_ENTITIES = 50_000
MAX_LINKS = 200_000
MAX_ALIASES = 20
MAX_IDENT = 512

SID_RE = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)
HEX_RE = re.compile(r"^[0-9a-f]+$")
HASH_ALGOS = {32: "md5", 40: "sha1", 64: "sha256"}
USER_PLACEHOLDERS = frozenset({"", "-", "n/a", "null sid", "none", "s-1-0-0", "(null)", "unknown"})
HOST_PLACEHOLDERS = frozenset({"", "-", "localhost", "unknown", "(null)"})
# EVTX Subject*/Target* triples: (sid field, user field, domain field)
_ED = "raw.event_data."
SID_TRIPLES = (
    (_ED + "SubjectUserSid", _ED + "SubjectUserName", _ED + "SubjectDomainName"),
    (_ED + "TargetUserSid", _ED + "TargetUserName", _ED + "TargetDomainName"),
    (_ED + "TargetSid", _ED + "TargetUserName", _ED + "TargetDomainName"),
)
RAW_PATHS = tuple(sorted({p for triple in SID_TRIPLES for p in triple}))
AUTH_CATEGORIES = frozenset({"authentication", "session"})


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or len(text) > MAX_IDENT or "\x00" in text:
        return None
    return text


def normalize_ip(value: Any) -> tuple[str, str] | None:
    """-> (canonical, scope) or None."""
    text = _clean(value)
    if text is None:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        scope = "loopback"
    elif ip.is_link_local:
        scope = "link_local"
    elif ip.is_private:
        scope = "private"
    elif ip.is_multicast:
        scope = "multicast"
    else:
        scope = "public"
    return ip.compressed, scope


def normalize_host(value: Any) -> tuple[str, list[tuple[str, str]]] | None:
    """-> (canonical short name, aliases) or None (placeholders, IPs)."""
    text = _clean(value)
    if text is None:
        return None
    name = text.lower().rstrip(".")
    if name in HOST_PLACEHOLDERS or normalize_ip(name) is not None:
        return None
    if any(c.isspace() for c in name) or "\\" in name or "/" in name:
        return None
    short = name.split(".", 1)[0]
    if not short:
        return None
    aliases = [("hostname", name)]
    if "." in name:
        aliases.append(("fqdn", name))
    return short, aliases


def normalize_sid(value: Any) -> str | None:
    text = _clean(value)
    if text is None or not SID_RE.match(text):
        return None
    sid = "S" + text[1:]
    return None if sid.lower() in USER_PLACEHOLDERS else sid.upper()


def well_known_sid(sid: str) -> bool:
    """SIDs that are not one account's own (SYSTEM, LOCAL SERVICE, BUILTIN groups, Everyone...).

    Only domain/local account SIDs (S-1-5-21-...) and Entra ID SIDs (S-1-12-1-...) identify one
    account. EVTX names S-1-5-18 after the machine account (``HOST$``) on every host, so a
    well-known SID next to a ``$`` name must not merge those hosts' accounts.
    """
    return not sid.startswith(("S-1-5-21-", "S-1-12-1-"))


def normalize_user(value: Any, domain: Any = None) -> tuple[str, list[tuple[str, str]]] | None:
    """-> (canonical, aliases) or None. ``domain`` is used when ``value`` has none."""
    text = _clean(value)
    if text is None or text.lower() in USER_PLACEHOLDERS:
        return None
    if normalize_sid(text) is not None:
        return None  # SIDs are aliases, resolved by the accumulator
    lowered = text.lower()
    dom: str | None = None
    name = lowered
    if "\\" in lowered:
        dom, _, name = lowered.partition("\\")
    elif "@" in lowered:
        name, _, fqdn = lowered.partition("@")
        dom = fqdn.split(".", 1)[0] if fqdn else None
    elif domain is not None:
        d = _clean(domain)
        dom = d.lower() if d and d.lower() not in USER_PLACEHOLDERS else None
    name = name.strip()
    if not name or name in USER_PLACEHOLDERS:
        return None
    canonical = f"{dom}\\{name}" if dom else name
    aliases = [("name", lowered)]
    if "@" in lowered:
        aliases.append(("upn", lowered))
    return canonical, aliases


def normalize_hash(value: Any) -> tuple[str, str] | None:
    text = _clean(value)
    if text is None:
        return None
    h = text.lower()
    if ":" in h:  # Sysmon's "sha256:<hex>"; the length still decides the algorithm
        h = h.rpartition(":")[2]
    algo = HASH_ALGOS.get(len(h))
    if algo is None or not HEX_RE.match(h) or set(h) == {"0"}:
        return None
    return h, algo


def normalize_process(host: str | None, value: Any) -> str | None:
    text = _clean(value)
    if text is None:
        return None
    base = re.split(r"[\\/]", text)[-1].strip().lower()
    if not base or base in {"-", "?"}:
        return None
    return f"{host}/{base}" if host else base


# ---------------------------------------------------------------------------------- resolution

Key = tuple[str, str]  # (type, canonical-or-identifier)


@dataclass
class EntityOut:
    type: str
    canonical: str
    aliases: set[tuple[str, str]] = field(default_factory=set)
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    event_count: int = 0


@dataclass
class LinkOut:
    src: Key
    dst: Key
    relation: str
    weight: int
    first_seen: datetime | None
    last_seen: datetime | None
    event_id: Any


@dataclass
class Resolution:
    entities: dict[Key, EntityOut]
    links: list[LinkOut]
    capped: bool
    events: int


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[Key, Key] = {}

    def find(self, key: Key) -> Key:
        self.parent.setdefault(key, key)
        root = key
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[key] != root:  # path compression
            self.parent[key], key = root, self.parent[key]
        return root

    def union(self, a: Key, b: Key) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _user_rank(key: Key) -> tuple[int, str]:
    kind, value = key
    if kind == "user" and "\\" in value:
        return (0, value)
    if kind == "user":
        return (1, value)
    return (2, value)  # ("sid", S-1-...)


class EntityAccumulator:
    """Feed normalized event rows (dicts with Appendix A columns + ``raw.*`` paths)."""

    def __init__(self, max_entities: int = MAX_ENTITIES, max_links: int = MAX_LINKS) -> None:
        self.max_entities = max_entities
        self.max_links = max_links
        self.nodes: dict[Key, EntityOut] = {}
        self.links: dict[tuple[Key, Key, str], LinkOut] = {}
        self.uf = _UnionFind()
        self.capped = False
        self.events = 0
        self._touched: set[Key] = set()

    # -- helpers
    def _node(
        self,
        key: Key,
        ts: datetime | None,
        aliases: Iterable[tuple[str, str]] = (),
        **attrs: Any,
    ) -> Key | None:
        node = self.nodes.get(key)
        if node is None:
            if len(self.nodes) >= self.max_entities:
                self.capped = True
                return None
            node = self.nodes[key] = EntityOut(type=key[0], canonical=key[1])
        for alias in aliases:
            if len(node.aliases) < MAX_ALIASES:
                node.aliases.add(alias)
        node.attributes.update({k: v for k, v in attrs.items() if v is not None})
        if key not in self._touched:  # count each event once per entity
            self._touched.add(key)
            node.event_count += 1
        if ts is not None:
            node.first_seen = ts if node.first_seen is None else min(node.first_seen, ts)
            node.last_seen = ts if node.last_seen is None else max(node.last_seen, ts)
        return key

    def _link(
        self, src: Key | None, dst: Key | None, relation: str, ts: datetime | None, event_id: Any
    ) -> None:
        if src is None or dst is None or src == dst:
            return
        k = (src, dst, relation)
        link = self.links.get(k)
        if link is None:
            if len(self.links) >= self.max_links:
                self.capped = True
                return
            self.links[k] = LinkOut(src, dst, relation, 1, ts, ts, event_id)
            return
        link.weight += 1
        if ts is not None:
            if link.first_seen is None or ts < link.first_seen:
                link.first_seen, link.event_id = ts, event_id
            if link.last_seen is None or ts > link.last_seen:
                link.last_seen = ts

    def _user(self, value: Any, domain: Any, sid: Any, ts: datetime | None) -> Key | None:
        norm = normalize_user(value, domain)
        sid_n = normalize_sid(sid) or normalize_sid(value)
        key: Key | None = None
        if norm is not None:
            key = self._node(("user", norm[0]), ts, norm[1])
        if sid_n is not None:
            sid_key = self._node(("sid", sid_n), ts, [("sid", sid_n)])
            machine = norm is not None and norm[0].endswith("$")
            if key is not None and sid_key is not None and not (machine and well_known_sid(sid_n)):
                self.uf.union(key, sid_key)  # strong evidence: stated together in one event
            key = key or sid_key
        return key

    # -- entry point
    def feed(self, event: dict[str, Any]) -> None:
        self.events += 1
        self._touched = set()
        ts = event.get("ts")
        eid = event.get("id")
        host_key: Key | None = None
        host_raw = event.get("host")
        host = normalize_host(host_raw)
        if host is not None:
            host_key = self._node(("host", host[0]), ts, host[1])
        elif (hip := normalize_ip(host_raw)) is not None:
            host_key = self._node(("ip", hip[0]), ts, scope=hip[1])
        user_key = self._user(event.get("user"), None, None, ts)
        for sid_f, name_f, dom_f in SID_TRIPLES:
            if event.get(sid_f) or event.get(name_f):
                self._user(event.get(name_f), event.get(dom_f), event.get(sid_f), ts)
        category = (event.get("event_category") or "").lower()
        outcome = (event.get("outcome") or "").lower()
        if user_key and host_key:
            if category in AUTH_CATEGORIES and outcome == "failure":
                relation = "failed_logon"
            elif category in AUTH_CATEGORIES and outcome == "success":
                relation = "logged_on"
            else:
                relation = "seen_on"
            self._link(user_key, host_key, relation, ts, eid)
        if (src := normalize_ip(event.get("src_ip"))) is not None:
            src_key = self._node(("ip", src[0]), ts, scope=src[1])
            self._link(src_key, host_key, "connected_to", ts, eid)
        if (dst := normalize_ip(event.get("dst_ip"))) is not None:
            dst_key = self._node(("ip", dst[0]), ts, scope=dst[1])
            self._link(host_key, dst_key, "connected_to", ts, eid)
        proc_name = normalize_process(host[0] if host else None, event.get("process_name"))
        proc_key: Key | None = None
        if proc_name is not None:
            proc_key = self._node(("process", proc_name), ts)
            self._link(proc_key, host_key, "ran_on", ts, eid)
            self._link(user_key, proc_key, "executed", ts, eid)
        if (hsh := normalize_hash(event.get("file_hash"))) is not None:
            hash_key = self._node(("hash", hsh[0]), ts, algo=hsh[1])
            self._link(proc_key, hash_key, "has_hash", ts, eid)

    def result(self) -> Resolution:
        """Merge union-find groups into user entities; deterministic output."""
        groups: dict[Key, list[Key]] = defaultdict(list)
        for key in self.nodes:
            if key[0] in ("user", "sid"):
                groups[self.uf.find(key)].append(key)
        mapping: dict[Key, Key] = {}
        merged: dict[Key, EntityOut] = {}
        for key, node in self.nodes.items():
            if key[0] not in ("user", "sid"):
                mapping[key] = key
                merged[key] = node
        for members in groups.values():
            best = min(members, key=_user_rank)
            target: Key = ("user", best[1])
            out = EntityOut(type="user", canonical=best[1])
            for member in sorted(members):
                mapping[member] = target
                node = self.nodes[member]
                out.aliases |= node.aliases
                out.attributes.update(node.attributes)
                out.event_count = max(out.event_count, node.event_count)
                for ts in (node.first_seen, node.last_seen):
                    if ts is not None:
                        out.first_seen = ts if out.first_seen is None else min(out.first_seen, ts)
                        out.last_seen = ts if out.last_seen is None else max(out.last_seen, ts)
            if best[0] == "user" and "\\" in best[1]:
                out.aliases.add(("domain_user", best[1]))
            out.aliases = set(sorted(out.aliases)[:MAX_ALIASES])
            merged[target] = out
        links: dict[tuple[Key, Key, str], LinkOut] = {}
        for (src, dst, rel), link in sorted(self.links.items(), key=lambda kv: repr(kv[0])):
            s, d = mapping[src], mapping[dst]
            if s == d:
                continue
            k = (s, d, rel)
            if k not in links:
                links[k] = LinkOut(s, d, rel, 0, None, None, link.event_id)
            out_link = links[k]
            out_link.weight += link.weight
            for ts in (link.first_seen, link.last_seen):
                if ts is not None:
                    if out_link.first_seen is None or ts < out_link.first_seen:
                        out_link.first_seen, out_link.event_id = ts, link.event_id
                    if out_link.last_seen is None or ts > out_link.last_seen:
                        out_link.last_seen = ts
        ordered = dict(sorted(merged.items()))
        edges = sorted(links.values(), key=lambda e: (e.src, e.dst, e.relation))
        return Resolution(ordered, edges, self.capped, self.events)
