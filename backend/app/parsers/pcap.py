"""Packet captures (pcap / pcapng) -> flows, DNS, HTTP requests and TLS SNI, in pure Python with
dpkt 1.9.8 (BSD-3). The default pcap parser; ``zeek`` is the optional deeper engine (spec
decision 6).

Accounting (spec decision 13): a record is a flow (one event at its first packet time), a decoded
DNS message, HTTP request or TLS ClientHello with SNI (one event each), an undecodable packet
(error) or a non-IP frame (skipped). Packets of a known flow only update its counters. The flow
table is capped (``MAX_FLOWS``); packets of flows beyond it are counted as errors and the run is
``partial``. No TCP reassembly: HTTP/TLS are read from single segments. Packet times are Unix
epoch (UTC) as stored in the capture.
"""

from __future__ import annotations

import importlib.metadata
import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dpkt

from app.parsers.base import Event, ParseContext, ParserInputError, record_cap_reached
from app.parsers.registry import register
from app.parsers.timeconv import Converted, TimestampError, unix_seconds

SOURCE = "pcap"
MAX_FLOWS = 200_000
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
)
PROTOCOLS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}


@dataclass
class Flow:
    index: int
    first: Converted
    last_ts: float
    proto: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    packets: int = 0
    bytes: int = 0
    tcp_flags: set[str] = field(default_factory=set)


def _ip(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))


def tls_sni(payload: bytes) -> str | None:
    """Server name from a TLS ClientHello in one segment (bounded walk), or None."""
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    pos = 9 + 2 + 32  # record header 5 + handshake header 4, version, random
    if pos >= len(payload):
        return None
    pos += 1 + payload[pos]  # session id
    if pos + 2 > len(payload):
        return None
    pos += 2 + struct.unpack_from(">H", payload, pos)[0]  # cipher suites
    if pos >= len(payload):
        return None
    pos += 1 + payload[pos]  # compression methods
    if pos + 2 > len(payload):
        return None
    end = min(len(payload), pos + 2 + struct.unpack_from(">H", payload, pos)[0])
    pos += 2
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack_from(">HH", payload, pos)
        pos += 4
        if ext_type == 0 and pos + 5 <= end:
            name_len = struct.unpack_from(">H", payload, pos + 3)[0]
            name = payload[pos + 5 : pos + 5 + name_len]
            if len(name) == name_len and name:
                return name.decode("ascii", "replace")[:255]
            return None
        pos += ext_len
    return None


class _Decoder:
    def __init__(self, ctx: ParseContext, linktype: int) -> None:
        self.ctx = ctx
        self.linktype = linktype
        self.flows: dict[tuple[Any, ...], Flow] = {}
        self.packets = 0
        self.dropped = 0

    def network(self, buf: bytes) -> Any:
        lt = self.linktype
        if lt == dpkt.pcap.DLT_EN10MB:
            return dpkt.ethernet.Ethernet(buf).data
        if lt in (dpkt.pcap.DLT_RAW, 12, 14, 101):
            version = buf[0] >> 4 if buf else 0
            return dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf)
        if lt == dpkt.pcap.DLT_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if lt in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
            return dpkt.loopback.Loopback(buf).data
        raise ParserInputError(f"unsupported link type {lt}")

    def event(self, key: str, ts: Converted, message: str, **kw: Any) -> Event:
        return Event(
            ts=ts.ts,
            ts_original=ts.original,
            source_type=SOURCE,
            message=message,
            record_key=key,
            source_record_id=key,
            source_file=self.ctx.source_file,
            host=self.ctx.host_hint,
            event_category="network",
            **kw,
        )

    def packet(self, n: int, ts: float, buf: bytes) -> Iterator[Event]:
        stats = self.ctx.stats
        self.packets += 1
        location = f"packet {n}"
        try:
            converted = unix_seconds(ts, tag="pcap_ts")
            if converted is None:
                raise TimestampError("zero packet time")
            ip = self.network(buf)
        except ParserInputError:
            raise
        except (dpkt.UnpackError, ValueError, struct.error, IndexError, TimestampError) as exc:
            stats.read()
            stats.error(location, "undecodable_packet", type(exc).__name__)
            return
        if not isinstance(ip, dpkt.ip.IP | dpkt.ip6.IP6):
            stats.read()
            stats.skip(location, "non_ip")
            return
        try:
            src, dst = _ip(ip.src), _ip(ip.dst)
        except ValueError:
            stats.read()
            stats.error(location, "bad_address")
            return
        proto_num = ip.p if isinstance(ip, dpkt.ip.IP) else ip.nxt
        transport = ip.data
        sport = dport = None
        payload = b""
        flags: set[str] = set()
        if isinstance(transport, dpkt.tcp.TCP | dpkt.udp.UDP):
            sport, dport = int(transport.sport), int(transport.dport)
            payload = bytes(transport.data) if isinstance(transport.data, bytes) else b""
            if isinstance(transport, dpkt.tcp.TCP):
                flags = {
                    name
                    for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"))
                    if transport.flags & bit
                }
        proto = PROTOCOLS.get(proto_num, str(proto_num))
        forward = (proto, src, sport, dst, dport)
        backward = (proto, dst, dport, src, sport)
        flow = self.flows.get(forward) or self.flows.get(backward)
        if flow is None:
            if len(self.flows) >= MAX_FLOWS:
                stats.read()
                stats.error(location, "flow_table_full")
                stats.assumptions["incomplete"] = "flow_table_full"
                self.dropped += 1
                return
            stats.read()  # a new flow is a record; its event is emitted at the end
            flow = Flow(len(self.flows), converted, ts, proto, src, sport, dst, dport)
            self.flows[forward] = flow
        flow.packets += 1
        flow.bytes += len(buf)
        flow.last_ts = max(flow.last_ts, ts)
        flow.tcp_flags |= flags
        net = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
        }
        if proto == "udp" and 53 in (sport, dport) and payload:
            yield from self._dns(n, converted, payload, net)
        elif proto == "tcp" and payload.startswith(HTTP_METHODS):
            yield from self._http(n, converted, payload, net)
        elif proto == "tcp" and payload[:1] == b"\x16":
            sni = tls_sni(payload)
            if sni:
                stats.read()
                yield self.event(
                    f"pkt:{n}:tls",
                    converted,
                    f"TLS ClientHello to {sni} ({dst}:{dport})",
                    action="tls_client_hello",
                    event_code="tls_sni",
                    raw={"sni": sni, "packet": n},
                    **net,
                )

    def _dns(self, n: int, ts: Converted, payload: bytes, net: dict[str, Any]) -> Iterator[Event]:
        stats = self.ctx.stats
        try:
            dns = dpkt.dns.DNS(payload)
        except (dpkt.UnpackError, ValueError, struct.error, IndexError):
            stats.warn("dns_undecodable", f"packet {n}")
            return
        if not dns.qd:
            return
        stats.read()
        query = dns.qd[0]
        qname = str(query.name)[:255]
        qtype = DNS_TYPES.get(query.type, str(query.type))
        if dns.qr == dpkt.dns.DNS_Q:
            yield self.event(
                f"pkt:{n}:dns",
                ts,
                f"DNS query {qname} ({qtype})",
                action="dns_query",
                event_code="dns_query",
                raw={"query": qname, "qtype": qtype, "id": dns.id, "packet": n},
                **net,
            )
            return
        answers: list[str] = []
        for rr in dns.an[:32]:
            if (rr.type == 1 and len(rr.rdata) == 4) or (rr.type == 28 and len(rr.rdata) == 16):
                answers.append(_ip(rr.rdata))
            elif rr.type == 5:
                answers.append(str(getattr(rr, "cname", ""))[:255])
        yield self.event(
            f"pkt:{n}:dns",
            ts,
            f"DNS response {qname} ({qtype}) -> {', '.join(answers[:5]) or dns.rcode}",
            action="dns_response",
            event_code="dns_response",
            raw={
                "query": qname,
                "qtype": qtype,
                "id": dns.id,
                "rcode": dns.rcode,
                "answers": answers,
                "packet": n,
            },
            **net,
        )

    def _http(self, n: int, ts: Converted, payload: bytes, net: dict[str, Any]) -> Iterator[Event]:
        stats = self.ctx.stats
        head = payload.split(b"\r\n\r\n", 1)[0][:8192]
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) < 3:
            stats.warn("http_undecodable", f"packet {n}")
            return
        headers: dict[str, str] = {}
        for line in lines[1:64]:
            name, sep, value = line.partition(b":")
            if sep:
                headers[name.strip().lower().decode("latin-1")[:64]] = value.strip().decode(
                    "latin-1"
                )[:1024]
        stats.read()
        method = parts[0].decode("latin-1")
        uri = parts[1].decode("latin-1")[:4096]
        host = headers.get("host")
        yield self.event(
            f"pkt:{n}:http",
            ts,
            f"HTTP {method} http://{host or net['dst_ip']}{uri}",
            action="http_request",
            event_code="http_request",
            raw={
                "method": method,
                "uri": uri,
                "host": host,
                "user_agent": headers.get("user-agent"),
                "packet": n,
            },
            **net,
        )

    def flow_events(self) -> Iterator[Event]:
        for flow in self.flows.values():
            ports = f":{flow.sport}" if flow.sport is not None else ""
            dports = f":{flow.dport}" if flow.dport is not None else ""
            yield self.event(
                f"flow:{flow.index}",
                flow.first,
                f"{flow.proto} {flow.src}{ports} -> {flow.dst}{dports} "
                f"({flow.packets} packets, {flow.bytes} bytes)",
                action="connection",
                event_code="flow",
                src_ip=flow.src,
                dst_ip=flow.dst,
                src_port=flow.sport,
                dst_port=flow.dport,
                protocol=flow.proto,
                raw={
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                    "duration_s": round(flow.last_ts - flow.first.ts.timestamp(), 6),
                    "tcp_flags": sorted(flow.tcp_flags),
                },
            )


@register
class PcapParser:
    name = "pcap"
    version = "1.0.0"
    description = "pcap/pcapng: flows, DNS, HTTP requests, TLS SNI (pure Python, dpkt)"
    source_types = (SOURCE,)

    def tool_versions(self) -> dict[str, str]:
        return {"dpkt": importlib.metadata.version("dpkt")}

    def can_parse(self, path: Path | None, head: bytes, filename: str) -> float:
        return 0.9 if head[:4] in PCAP_MAGICS or head[:4] == PCAPNG_MAGIC else 0.0

    def parse(self, ctx: ParseContext) -> Iterator[Event]:
        stats = ctx.stats
        total = max(ctx.path.stat().st_size, 1)
        with ctx.path.open("rb") as fh:
            magic = fh.read(4)
            fh.seek(0)
            try:
                reader: Any = (
                    dpkt.pcapng.Reader(fh) if magic == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)
                )
            except (ValueError, dpkt.UnpackError, struct.error) as exc:
                raise ParserInputError(f"not a readable capture: {type(exc).__name__}") from exc
            decoder = _Decoder(ctx, int(reader.datalink()))
            stats.assumptions.update(
                {
                    "timezone": "UTC (capture epoch)",
                    "format": "pcapng" if magic == PCAPNG_MAGIC else "pcap",
                    "linktype": decoder.linktype,
                }
            )
            n = 0
            packets = iter(reader)
            while True:
                try:
                    ts, buf = next(packets)
                except StopIteration:
                    break
                except (ValueError, dpkt.UnpackError, dpkt.NeedData, struct.error) as exc:
                    stats.read()
                    stats.error(f"after packet {n}", "capture_truncated", type(exc).__name__)
                    stats.assumptions["incomplete"] = "capture_truncated"
                    break
                n += 1
                if record_cap_reached(ctx):
                    break
                yield from decoder.packet(n, float(ts), bytes(buf))
                if n % 5000 == 0:
                    ctx.progress(min(fh.tell() / total, 0.95))
            stats.bytes_read = fh.tell()
        stats.assumptions.update(
            {
                "packets": decoder.packets,
                "flows": len(decoder.flows),
                "packets_in_dropped_flows": decoder.dropped,
            }
        )
        yield from decoder.flow_events()
        ctx.progress(1.0)
