"""Outbound network access for integrations: the ONLY module that sends HTTP or SMTP for them.

Webhooks, Slack/Teams/e-mail notifications and the MISP/VirusTotal providers all go through
:class:`OutboundHttp` or :class:`OutboundMailer` (the LLM gateway and the object store have their
own clients). Server-side request forgery defences (guide 20.1):

* ``https`` only; ``http`` (and SMTP without TLS) only with ``OUTBOUND_ALLOW_HTTP`` (dev).
* No credentials in URLs, no control characters or spaces, bounded length.
* The host is resolved once, through an injectable resolver. Every resolved address must be
  public unless ``OUTBOUND_ALLOW_HOSTS`` permits it: loopback, private, link-local, cloud metadata,
  CGNAT, multicast, unspecified, reserved and IPv6 forms that embed an IPv4 address are refused.
  A host-name entry permits that host's private, loopback and CGNAT addresses; any other class is
  permitted only by a CIDR entry that contains the address.
* The connection goes to the validated address (TLS still checks the host name), so a second DNS
  answer cannot redirect it (DNS rebinding). Redirects are never followed.
* Connect and read timeouts, a total deadline, a streamed response cap and a request cap.

Errors carry a category and the host only: never the URL path/query, headers or bodies.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import smtplib
import socket
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any, Protocol
from urllib.parse import urlsplit

from app import __version__
from app.config import Settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
# host, port -> IP address strings (the default asks the system resolver once).
Resolver = Callable[[str, int], Sequence[str]]

USER_AGENT = f"dfirbench/{__version__}"
MAX_URL_CHARS = 2048
MAX_RESOLVED = 16
MAX_HEADERS = 32
MAX_HEADER_VALUE = 4096
MAX_RECIPIENTS = 20
READ_CHUNK = 16 * 1024
HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

METADATA_NETS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
# IPv6 ranges that carry an IPv4 address inside (mapped, compatible, NAT64, 6to4, Teredo).
EMBEDDED_V4_NETS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("::/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
)
_V6_UNSPECIFIED = ipaddress.IPv6Address("::")
_V6_LOOPBACK = ipaddress.IPv6Address("::1")
# Classes a host-name allowlist entry unlocks; everything else needs a CIDR entry.
HOST_ENTRY_UNLOCKS = frozenset({"private", "loopback", "cgnat"})


class OutboundBlockedError(Exception):
    """The destination is not allowed by the outbound policy (never retried)."""

    def __init__(self, reason: str, host: str | None = None) -> None:
        super().__init__(f"outbound request blocked: {reason}")
        self.reason = reason
        self.host = host
        self.category = f"blocked:{reason}"
        self.transient = False


class OutboundError(Exception):
    """A request that was allowed but did not complete (``category`` is safe to store)."""

    def __init__(self, category: str, *, transient: bool, host: str | None = None) -> None:
        super().__init__(f"outbound request failed: {category}")
        self.category = category
        self.transient = transient
        self.host = host


@dataclass(frozen=True)
class OutboundPolicy:
    allow_http: bool = False
    allow_hosts: frozenset[str] = frozenset()
    allow_networks: tuple[IPNetwork, ...] = ()
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 10.0
    total_timeout_s: float = 30.0
    max_response_bytes: int = 256 * 1024
    max_request_bytes: int = 256 * 1024

    @classmethod
    def from_settings(cls, settings: Settings) -> OutboundPolicy:
        hosts, networks = parse_allowlist(settings.outbound_allow_hosts)
        return cls(
            allow_http=settings.outbound_allow_http,
            allow_hosts=hosts,
            allow_networks=networks,
            connect_timeout_s=settings.outbound_connect_timeout_s,
            read_timeout_s=settings.outbound_read_timeout_s,
            total_timeout_s=settings.outbound_connect_timeout_s
            + 3 * settings.outbound_read_timeout_s,
            max_response_bytes=settings.outbound_max_response_kb * 1024,
            max_request_bytes=settings.outbound_max_request_kb * 1024,
        )


def parse_allowlist(entries: Sequence[str]) -> tuple[frozenset[str], tuple[IPNetwork, ...]]:
    """Split ``OUTBOUND_ALLOW_HOSTS`` into host names and networks (raises ValueError)."""
    hosts: set[str] = set()
    networks: list[IPNetwork] = []
    for raw in entries:
        entry = raw.strip().lower()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
            continue
        except ValueError:
            pass
        if not HOST_RE.fullmatch(entry):
            raise ValueError(f"invalid OUTBOUND_ALLOW_HOSTS entry {raw!r}")
        hosts.add(entry)
    return frozenset(hosts), tuple(networks)


def classify_ip(addr: IPAddress) -> str:
    """``public`` or the reason an address is not routable on the public Internet."""
    if isinstance(addr, ipaddress.IPv6Address) and any(addr in net for net in EMBEDDED_V4_NETS):
        # ``::`` and ``::1`` sit inside ::/96 but are not embedded IPv4 addresses. Compared by
        # value: ``is_loopback`` of a mapped address differs between Python patch releases.
        if addr == _V6_UNSPECIFIED:
            return "unspecified"
        if addr == _V6_LOOPBACK:
            return "loopback"
        return "embedded_ipv4"
    if any(addr in net for net in METADATA_NETS if net.version == addr.version):
        return "metadata"
    if addr.is_unspecified or (addr.version == 4 and int(addr) >> 24 == 0):
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.version == 4 and addr in CGNAT_NET:
        return "cgnat"
    if addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    if not addr.is_global:
        return "reserved"
    return "public"


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str  # lower-case ASCII host name or IP literal (no brackets)
    port: int
    path: str  # path + query, as sent on the request line

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def check_url(url: str, policy: OutboundPolicy) -> Target:
    """Validate the URL shape and scheme (no resolution yet)."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise OutboundBlockedError("invalid_url")
    if any(ch <= " " or ch == "\x7f" or ord(ch) > 126 or ch == "\\" for ch in url):
        raise OutboundBlockedError("invalid_url")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise OutboundBlockedError("invalid_url") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise OutboundBlockedError("scheme_not_allowed")
    if scheme == "http" and not policy.allow_http:
        raise OutboundBlockedError("http_not_allowed")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise OutboundBlockedError("credentials_in_url")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise OutboundBlockedError("invalid_host")
    if _literal(host) is None and not HOST_RE.fullmatch(host):
        raise OutboundBlockedError("invalid_host", host[:64])
    if port is None:
        port = 443 if scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise OutboundBlockedError("invalid_port", host)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme=scheme, host=host, port=port, path=path)


def _literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def system_resolver(host: str, port: int) -> Sequence[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def _allowed(addr: IPAddress, host: str, policy: OutboundPolicy) -> str | None:
    """None when the address may be contacted, else the refusal reason."""
    kind = classify_ip(addr)
    if kind == "public":
        return None
    if any(addr in net for net in policy.allow_networks if net.version == addr.version):
        return None
    if host in policy.allow_hosts and kind in HOST_ENTRY_UNLOCKS:
        return None
    return kind


def resolve_target(
    host: str, port: int, policy: OutboundPolicy, resolver: Resolver = system_resolver
) -> str:
    """The address to connect to. Every resolved address must pass the policy."""
    literal = _literal(host)
    if literal is not None:
        addresses: list[IPAddress] = [literal]
    else:
        try:
            raw = list(resolver(host, port))[:MAX_RESOLVED]
        except OSError as exc:
            raise OutboundError("dns_error", transient=True, host=host) from exc
        addresses = []
        for item in raw:
            try:
                addresses.append(ipaddress.ip_address(str(item).split("%", 1)[0]))
            except ValueError as exc:
                raise OutboundError("dns_error", transient=True, host=host) from exc
        if not addresses:
            raise OutboundError("dns_error", transient=True, host=host)
    for addr in addresses:
        reason = _allowed(addr, host, policy)
        if reason is not None:
            raise OutboundBlockedError(f"address_{reason}", host)
    return str(addresses[0])


# ------------------------------------------------------------------------------ HTTP


@dataclass(frozen=True)
class PreparedRequest:
    """A validated request: ``ip`` is the address the transport must connect to."""

    method: str
    target: Target
    ip: str
    headers: Mapping[str, str]
    body: bytes
    connect_timeout_s: float
    read_timeout_s: float
    total_timeout_s: float
    max_response_bytes: int


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class Transport(Protocol):
    def send(self, request: PreparedRequest) -> HttpResponse: ...


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, *, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, port: int, *, ip: str, timeout: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._pinned_context = context

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            # SNI and the certificate check use the host name, not the pinned address.
            self.sock = self._pinned_context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


def default_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class SocketTransport:
    """The real transport: one connection per request, to the pinned address, no redirects."""

    def __init__(self, ssl_context: ssl.SSLContext | None = None) -> None:
        self._ssl_context = ssl_context

    def send(self, request: PreparedRequest) -> HttpResponse:
        target = request.target
        deadline = time.monotonic() + request.total_timeout_s
        conn: http.client.HTTPConnection
        if target.scheme == "https":
            conn = _PinnedHTTPSConnection(
                target.host,
                target.port,
                ip=request.ip,
                timeout=request.connect_timeout_s,
                context=self._ssl_context or default_ssl_context(),
            )
        else:
            conn = _PinnedHTTPConnection(
                target.host, target.port, ip=request.ip, timeout=request.connect_timeout_s
            )
        try:
            try:
                conn.connect()
            except ssl.SSLError as exc:
                raise OutboundError("tls_error", transient=False, host=target.host) from exc
            except TimeoutError as exc:
                raise OutboundError("timeout", transient=True, host=target.host) from exc
            except OSError as exc:
                raise OutboundError("connect_error", transient=True, host=target.host) from exc
            if conn.sock is not None:
                conn.sock.settimeout(request.read_timeout_s)
            try:
                conn.request(
                    request.method, target.path, body=request.body, headers=dict(request.headers)
                )
                resp = conn.getresponse()
                chunks: list[bytes] = []
                size = 0
                while True:
                    if time.monotonic() > deadline:
                        raise OutboundError("timeout", transient=True, host=target.host)
                    chunk = resp.read(READ_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > request.max_response_bytes:
                        raise OutboundError("response_too_large", transient=False, host=target.host)
                    chunks.append(chunk)
            except TimeoutError as exc:
                raise OutboundError("timeout", transient=True, host=target.host) from exc
            except ssl.SSLError as exc:
                raise OutboundError("tls_error", transient=False, host=target.host) from exc
            except (http.client.HTTPException, OSError) as exc:
                raise OutboundError("protocol_error", transient=True, host=target.host) from exc
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return HttpResponse(status=int(resp.status), headers=headers, body=b"".join(chunks))
        finally:
            conn.close()


def _clean_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if not HEADER_NAME_RE.fullmatch(name) or len(out) >= MAX_HEADERS:
            raise OutboundBlockedError("invalid_header")
        text = str(value)
        if CONTROL_RE.search(text) or len(text) > MAX_HEADER_VALUE:
            raise OutboundBlockedError("invalid_header")
        try:
            text.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise OutboundBlockedError("invalid_header") from exc
        out[name] = text
    return out


class OutboundHttp:
    """Policy-checked HTTP client. ``resolver`` and ``transport`` are injectable (tests)."""

    def __init__(
        self,
        policy: OutboundPolicy,
        *,
        resolver: Resolver = system_resolver,
        transport: Transport | None = None,
    ) -> None:
        self.policy = policy
        self.resolver = resolver
        self.transport: Transport = transport or SocketTransport()

    def prepare(
        self, method: str, url: str, *, headers: Mapping[str, str] | None, body: bytes
    ) -> PreparedRequest:
        if method not in ("GET", "POST"):
            raise OutboundBlockedError("method_not_allowed")
        if len(body) > self.policy.max_request_bytes:
            raise OutboundError("request_too_large", transient=False)
        target = check_url(url, self.policy)
        ip = resolve_target(target.host, target.port, self.policy, self.resolver)
        final = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
            "Connection": "close",
            **_clean_headers(headers),
        }
        return PreparedRequest(
            method=method,
            target=target,
            ip=ip,
            headers=final,
            body=body,
            connect_timeout_s=self.policy.connect_timeout_s,
            read_timeout_s=self.policy.read_timeout_s,
            total_timeout_s=self.policy.total_timeout_s,
            max_response_bytes=self.policy.max_response_bytes,
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes = b"",
    ) -> HttpResponse:
        """One request; 3xx answers are returned, never followed."""
        return self.transport.send(self.prepare(method, url, headers=headers, body=body))


# ------------------------------------------------------------------------------ SMTP


def clean_header(value: str, limit: int = 200) -> str:
    """Header-safe text: control characters (CR/LF included) become spaces; bounded."""
    return " ".join(CONTROL_RE.sub(" ", str(value)).split())[:limit]


def valid_address(value: str) -> bool:
    return bool(ADDRESS_RE.fullmatch(value))


@dataclass(frozen=True)
class MailServer:
    host: str
    port: int = 587
    security: str = "starttls"  # starttls | tls | none (none needs OUTBOUND_ALLOW_HTTP)
    username: str | None = None
    password: str | None = None


class _PinnedSMTP(smtplib.SMTP):
    pinned_ip: str = ""

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection((self.pinned_ip, port), timeout)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    pinned_ip: str = ""

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        sock = socket.create_connection((self.pinned_ip, port), timeout)
        try:
            return self.context.wrap_socket(sock, server_hostname=host)
        except BaseException:
            sock.close()
            raise


def _smtp_session(server: MailServer, ip: str, timeout: float) -> Any:
    context = default_ssl_context()
    if server.security == "tls":
        cls_ssl = type("PinnedSMTPSSL", (_PinnedSMTPSSL,), {"pinned_ip": ip})
        return cls_ssl(server.host, server.port, timeout=timeout, context=context)
    cls = type("PinnedSMTP", (_PinnedSMTP,), {"pinned_ip": ip})
    client = cls(server.host, server.port, timeout=timeout)
    if server.security == "starttls":
        client.starttls(context=context)
    return client


class OutboundMailer:
    """Policy-checked SMTP submission. ``session_factory`` is injectable (tests)."""

    def __init__(
        self,
        policy: OutboundPolicy,
        *,
        resolver: Resolver = system_resolver,
        session_factory: Callable[[MailServer, str, float], Any] = _smtp_session,
    ) -> None:
        self.policy = policy
        self.resolver = resolver
        self.session_factory = session_factory

    def send(
        self,
        server: MailServer,
        *,
        sender: str,
        recipients: Sequence[str],
        subject: str,
        body: str,
    ) -> None:
        if server.security not in ("starttls", "tls", "none"):
            raise OutboundBlockedError("invalid_smtp_security")
        if server.security == "none" and not self.policy.allow_http:
            raise OutboundBlockedError("smtp_plaintext_not_allowed")
        host = server.host.strip().lower().rstrip(".")
        if (_literal(host) is None and not HOST_RE.fullmatch(host)) or not (
            1 <= server.port <= 65535
        ):
            raise OutboundBlockedError("invalid_host")
        if not valid_address(sender) or not recipients or len(recipients) > MAX_RECIPIENTS:
            raise OutboundBlockedError("invalid_address")
        if not all(valid_address(r) for r in recipients):
            raise OutboundBlockedError("invalid_address")
        if len(body.encode("utf-8")) > self.policy.max_request_bytes:
            raise OutboundError("request_too_large", transient=False)
        ip = resolve_target(host, server.port, self.policy, self.resolver)
        message = EmailMessage()
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message["Subject"] = clean_header(subject)
        message["X-Mailer"] = USER_AGENT
        message.set_content(body, subtype="plain", charset="utf-8")
        pinned = MailServer(host, server.port, server.security, server.username, server.password)
        try:
            client = self.session_factory(pinned, ip, self.policy.connect_timeout_s)
        except ssl.SSLError as exc:
            raise OutboundError("tls_error", transient=False, host=host) from exc
        except TimeoutError as exc:
            raise OutboundError("timeout", transient=True, host=host) from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise OutboundError("connect_error", transient=True, host=host) from exc
        try:
            if server.username and server.password:
                client.login(server.username, server.password)
            client.send_message(message, from_addr=sender, to_addrs=list(recipients))
        except smtplib.SMTPAuthenticationError as exc:
            raise OutboundError("smtp_auth_failed", transient=False, host=host) from exc
        except smtplib.SMTPRecipientsRefused as exc:
            raise OutboundError("smtp_rejected", transient=False, host=host) from exc
        except TimeoutError as exc:
            raise OutboundError("timeout", transient=True, host=host) from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise OutboundError("smtp_error", transient=True, host=host) from exc
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                client.close()
