"""The single outbound module: SSRF policy, pinned connections, limits, SMTP. No external network:
names resolve through an injected resolver and the only sockets are loopback servers started here.
"""

from __future__ import annotations

import ast
import datetime as dt
import http.server
import ipaddress
import smtplib
import socket
import socketserver
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.config import Settings
from app.integrations.outbound import (
    HttpResponse,
    MailServer,
    OutboundBlockedError,
    OutboundError,
    OutboundHttp,
    OutboundMailer,
    OutboundPolicy,
    SocketTransport,
    check_url,
    classify_ip,
    clean_header,
    parse_allowlist,
    resolve_target,
)
from tests.fakes import FakeResolver, FakeSmtpSession, FakeTransport

APP_DIR = Path(__file__).resolve().parents[2] / "app"
PUBLIC_IP = "93.184.216.34"  # never contacted: only the fake resolver/transport see it
STRICT = OutboundPolicy()


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("93.184.216.34", "public"),
        ("2606:2800:220:1:248:1893:25c8:1946", "public"),
        ("127.0.0.1", "loopback"),
        ("127.8.9.10", "loopback"),
        ("::1", "loopback"),
        ("10.1.2.3", "private"),
        ("172.16.0.1", "private"),
        ("172.31.255.254", "private"),
        ("192.168.1.10", "private"),
        ("fd12:3456::1", "private"),
        ("169.254.10.10", "link_local"),
        ("fe80::1", "link_local"),
        ("169.254.169.254", "metadata"),
        ("fd00:ec2::254", "metadata"),
        ("100.64.0.1", "cgnat"),
        ("100.127.255.254", "cgnat"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
        ("0.0.0.0", "unspecified"),
        ("0.1.2.3", "unspecified"),
        ("::", "unspecified"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "reserved"),
        ("192.0.2.10", "private"),  # documentation range: not routable
        ("::ffff:127.0.0.1", "embedded_ipv4"),
        ("::ffff:93.184.216.34", "embedded_ipv4"),
        ("::ffff:169.254.169.254", "embedded_ipv4"),
        ("64:ff9b::7f00:1", "embedded_ipv4"),
        ("2002:7f00:1::", "embedded_ipv4"),
        ("::7f00:1", "embedded_ipv4"),
    ],
)
def test_address_classes(address: str, expected: str) -> None:
    assert classify_ip(ipaddress.ip_address(address)) == expected


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://hooks.example.test/x", "http_not_allowed"),
        ("ftp://hooks.example.test/x", "scheme_not_allowed"),
        ("file:///etc/passwd", "scheme_not_allowed"),
        ("gopher://hooks.example.test/", "scheme_not_allowed"),
        ("https://user:pw@hooks.example.test/x", "credentials_in_url"),
        ("https://user@hooks.example.test/x", "credentials_in_url"),
        ("https:///nohost", "invalid_host"),
        ("https://hooks.example.test:0/x", "invalid_port"),
        ("https://hooks.example.test:99999/x", "invalid_url"),
        ("https://hooks.example.test/a b", "invalid_url"),
        ("https://hooks.example.test/a\r\nX-Injected: 1", "invalid_url"),
        ("https://hooks.example.test\\@evil.test/", "invalid_url"),
        ("https://bad_host!.test/", "invalid_host"),
        ("https://" + "a" * 2100 + ".test/", "invalid_url"),
        ("", "invalid_url"),
    ],
)
def test_url_shape_is_checked(url: str, reason: str) -> None:
    with pytest.raises(OutboundBlockedError) as err:
        check_url(url, STRICT)
    assert err.value.reason == reason


def test_url_defaults_and_http_only_when_allowed() -> None:
    target = check_url("https://Hooks.Example.TEST./path?x=1", STRICT)
    assert (target.scheme, target.host, target.port, target.path) == (
        "https",
        "hooks.example.test",
        443,
        "/path?x=1",
    )
    dev = OutboundPolicy(allow_http=True)
    assert check_url("http://hooks.example.test:8080", dev).port == 8080


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.0.9",
        "169.254.169.254",
        "100.64.1.1",
        "224.0.0.251",
        "0.0.0.0",
        "::1",
        "::ffff:10.0.0.5",
        "fe80::1",
    ],
)
def test_names_resolving_to_internal_addresses_are_refused(address: str) -> None:
    resolver = FakeResolver({"internal.example.test": [address]})
    with pytest.raises(OutboundBlockedError) as err:
        resolve_target("internal.example.test", 443, STRICT, resolver)
    assert err.value.reason.startswith("address_")
    literal = f"[{address}]" if ":" in address else address
    with pytest.raises(OutboundBlockedError):
        OutboundHttp(STRICT, resolver=resolver, transport=FakeTransport()).request(
            "POST", f"https://{literal}/hook", body=b"{}"
        )


def test_every_resolved_address_must_pass() -> None:
    """One private answer among public ones (a rebinding trick) refuses the whole request."""
    resolver = FakeResolver({"mixed.example.test": [PUBLIC_IP, "10.0.0.7"]})
    with pytest.raises(OutboundBlockedError):
        resolve_target("mixed.example.test", 443, STRICT, resolver)
    assert (
        resolve_target(
            "ok.example.test", 443, STRICT, FakeResolver({"ok.example.test": [PUBLIC_IP]})
        )
        == PUBLIC_IP
    )


def test_dns_failure_is_a_transient_error_not_a_bypass() -> None:
    with pytest.raises(OutboundError) as err:
        resolve_target("missing.example.test", 443, STRICT, FakeResolver())
    assert err.value.category == "dns_error" and err.value.transient
    with pytest.raises(OutboundError):
        resolve_target(
            "weird.example.test", 443, STRICT, FakeResolver({"weird.example.test": ["x"]})
        )
    with pytest.raises(OutboundError):
        resolve_target("empty.example.test", 443, STRICT, FakeResolver({"empty.example.test": []}))


def test_allowlist_semantics() -> None:
    hosts, networks = parse_allowlist(["Relay.Internal", " 10.20.0.0/16 ", "", "169.254.169.254"])
    assert hosts == {"relay.internal"} and len(networks) == 2
    policy = OutboundPolicy(allow_hosts=hosts, allow_networks=networks)
    relay = FakeResolver({"relay.internal": ["192.168.5.5"], "other.internal": ["192.168.5.5"]})
    # A host-name entry unlocks that host's private address, not the address for other names.
    assert resolve_target("relay.internal", 25, policy, relay) == "192.168.5.5"
    with pytest.raises(OutboundBlockedError):
        resolve_target("other.internal", 25, policy, relay)
    # A CIDR entry unlocks exactly the addresses inside it.
    assert resolve_target("10.20.3.4", 443, policy) == "10.20.3.4"
    with pytest.raises(OutboundBlockedError):
        resolve_target("10.21.3.4", 443, policy)
    # A host-name entry never unlocks link-local/metadata; an explicit CIDR does.
    meta = FakeResolver({"relay.internal": ["169.254.10.10"]})
    with pytest.raises(OutboundBlockedError):
        resolve_target("relay.internal", 80, policy, meta)
    assert resolve_target("169.254.169.254", 80, policy) == "169.254.169.254"
    with pytest.raises(ValueError, match="invalid OUTBOUND_ALLOW_HOSTS"):
        parse_allowlist(["bad host!"])


def test_policy_from_settings_and_settings_validation(bare_env: None) -> None:
    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        app_env="test",
        outbound_allow_hosts="mail.internal, 10.9.0.0/16",  # type: ignore[arg-type]
        outbound_max_response_kb=8,
    )
    policy = OutboundPolicy.from_settings(settings)
    assert policy.allow_hosts == {"mail.internal"} and policy.max_response_bytes == 8192
    assert not policy.allow_http
    with pytest.raises(ValueError, match="OUTBOUND_ALLOW_HOSTS"):
        Settings(_env_file=None, app_env="test", outbound_allow_hosts="bad host!")  # type: ignore[call-arg,arg-type]
    with pytest.raises(ValueError, match="development only"):
        Settings(
            _env_file=None,  # type: ignore[call-arg]
            app_env="prod",
            jwt_secret="x" * 40,
            totp_enc_key="y" * 40,
            s3_secret_key="z" * 20,
            database_url="postgresql+psycopg://u:p@db/d",
            cors_origins=["https://dfir.example"],
            custody_signing_key_path="/k.pem",
            custody_key_id="k1",
            outbound_allow_http=True,
        )


def test_prepared_request_is_pinned_and_headers_are_checked() -> None:
    resolver = FakeResolver({"hooks.example.test": [PUBLIC_IP]})
    transport = FakeTransport()
    http = OutboundHttp(STRICT, resolver=resolver, transport=transport)  # type: ignore[arg-type]
    http.request(
        "POST", "https://hooks.example.test/hook", headers={"X-Signature": "sha256=ab"}, body=b"{}"
    )
    prepared = transport.requests[0]
    assert prepared.ip == PUBLIC_IP and prepared.target.host == "hooks.example.test"  # type: ignore[attr-defined]
    assert prepared.headers["Accept-Encoding"] == "identity"  # type: ignore[attr-defined]
    assert resolver.calls == ["hooks.example.test"]  # resolved exactly once
    for bad in ({"X-Bad\r\nInjected": "1"}, {"X-Ok": "line1\r\nX-Injected: 1"}, {"X-Ok": "é中"}):
        with pytest.raises(OutboundBlockedError, match="invalid_header"):
            http.request("POST", "https://hooks.example.test/hook", headers=bad, body=b"{}")
    with pytest.raises(OutboundBlockedError, match="method_not_allowed"):
        http.request("DELETE", "https://hooks.example.test/hook")
    small = OutboundHttp(
        OutboundPolicy(max_request_bytes=10), resolver=resolver, transport=transport
    )  # type: ignore[arg-type]
    with pytest.raises(OutboundError) as err:
        small.request("POST", "https://hooks.example.test/hook", body=b"x" * 11)
    assert err.value.category == "request_too_large"


# ------------------------------------------------------------------------------ real transport


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    seen: ClassVar[list[dict[str, object]]] = []

    def log_message(self, *args: object) -> None:
        return

    def _answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen.append({"path": self.path, "host": self.headers.get("Host"), "body": body})
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"x" * 300_000)
        elif self.path == "/slow":
            time.sleep(1.5)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    do_GET = do_POST = _answer  # noqa: N815


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


@pytest.fixture
def http_server() -> Iterator[tuple[int, type[_Handler]]]:
    handler = type("Handler", (_Handler,), {"seen": []})
    server = _Server(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _loopback_client(**policy: object) -> OutboundHttp:
    """A name that only the injected resolver knows, allowlisted, resolving to loopback."""
    base: dict[str, object] = {
        "allow_http": True,
        "allow_hosts": frozenset({"sink.example.test"}),
        "connect_timeout_s": 3.0,
        "read_timeout_s": 3.0,
        "total_timeout_s": 6.0,
    }
    base.update(policy)
    return OutboundHttp(
        OutboundPolicy(**base),  # type: ignore[arg-type]
        resolver=FakeResolver({"sink.example.test": ["127.0.0.1"]}),
    )


def test_real_transport_connects_to_the_validated_address(
    http_server: tuple[int, type[_Handler]],
) -> None:
    port, handler = http_server
    client = _loopback_client()
    resp = client.request("POST", f"http://sink.example.test:{port}/hook?a=1", body=b'{"n":1}')
    assert (
        resp.ok
        and resp.body == b'{"ok":true}'
        and resp.headers["content-type"] == "application/json"
    )
    # The name does not exist in real DNS: reaching the server proves the pinned IP was used,
    # and the Host header still carries the name.
    assert handler.seen == [
        {"path": "/hook?a=1", "host": f"sink.example.test:{port}", "body": b'{"n":1}'}
    ]


def test_redirects_are_returned_not_followed(http_server: tuple[int, type[_Handler]]) -> None:
    port, handler = http_server
    resp = _loopback_client().request("GET", f"http://sink.example.test:{port}/redirect")
    assert resp.status == 302 and not resp.ok
    assert [s["path"] for s in handler.seen] == ["/redirect"]


def test_response_size_is_capped_while_streaming(http_server: tuple[int, type[_Handler]]) -> None:
    port, _ = http_server
    with pytest.raises(OutboundError) as err:
        _loopback_client(max_response_bytes=64 * 1024).request(
            "GET", f"http://sink.example.test:{port}/big"
        )
    assert err.value.category == "response_too_large" and not err.value.transient


def test_read_timeout(http_server: tuple[int, type[_Handler]]) -> None:
    port, _ = http_server
    with pytest.raises(OutboundError) as err:
        _loopback_client(read_timeout_s=0.3).request("GET", f"http://sink.example.test:{port}/slow")
    assert err.value.category == "timeout" and err.value.transient


def test_connection_refused_is_transient() -> None:
    with socket.socket() as probe:  # a port nothing listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(OutboundError) as err:
        _loopback_client(connect_timeout_s=1.0).request("GET", f"http://sink.example.test:{port}/")
    assert err.value.category in {"connect_error", "timeout"} and err.value.transient


def _self_signed(host: str, tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_https_checks_the_certificate_against_the_host_name_not_the_ip(tmp_path: Path) -> None:
    cert_path, key_path = _self_signed("sink.example.test", tmp_path)
    handler = type("Handler", (_Handler,), {"seen": []})
    server = _Server(("127.0.0.1", 0), handler)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_path, key_path)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        trust = ssl.create_default_context(cafile=str(cert_path))
        policy = OutboundPolicy(
            allow_hosts=frozenset({"sink.example.test", "other.example.test"}),
            connect_timeout_s=3.0,
            read_timeout_s=3.0,
        )
        resolver = FakeResolver(
            {"sink.example.test": ["127.0.0.1"], "other.example.test": ["127.0.0.1"]}
        )
        client = OutboundHttp(policy, resolver=resolver, transport=SocketTransport(trust))
        assert client.request("GET", f"https://sink.example.test:{port}/ok").ok
        # Same address, another name: the certificate does not match, so TLS fails.
        with pytest.raises(OutboundError) as err:
            client.request("GET", f"https://other.example.test:{port}/ok")
        assert err.value.category == "tls_error"
        # The default trust store does not know this certificate either.
        with pytest.raises(OutboundError):
            OutboundHttp(policy, resolver=resolver).request(
                "GET", f"https://sink.example.test:{port}/ok"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ------------------------------------------------------------------------------ SMTP


def _mailer(sink: list[dict[str, object]], **policy: object) -> OutboundMailer:
    return OutboundMailer(
        OutboundPolicy(**policy),  # type: ignore[arg-type]
        resolver=FakeResolver({"smtp.example.test": [PUBLIC_IP], "relay.internal": ["10.0.0.25"]}),
        session_factory=lambda server, ip, timeout: FakeSmtpSession(sink, server, ip),
    )


def test_mail_is_sent_to_the_validated_address_with_clean_headers() -> None:
    sink: list[dict[str, object]] = []
    _mailer(sink).send(
        MailServer("smtp.example.test", 587, "starttls", "bot", "pw"),
        sender="dfir@example.test",
        recipients=["lead@example.test"],
        subject="New alert\r\nBcc: attacker@evil.test",
        body="Severity: high\n",
    )
    sent = sink[0]
    message = sent["message"]
    assert sent["ip"] == PUBLIC_IP and sent["login"] == ("bot", "pw")
    assert message["Subject"] == "New alert Bcc: attacker@evil.test"  # type: ignore[index]
    assert message["Bcc"] is None and message["To"] == "lead@example.test"  # type: ignore[index]
    assert "\r" not in str(message["Subject"]) and "\n" not in str(message["Subject"])  # type: ignore[index]


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"recipients": ["a@example.test\r\nBcc: x@evil.test"]}, "invalid_address"),
        ({"recipients": []}, "invalid_address"),
        ({"sender": "Display <a@example.test>"}, "invalid_address"),
        ({"recipients": [f"u{i}@example.test" for i in range(21)]}, "invalid_address"),
    ],
)
def test_mail_addresses_are_validated(kwargs: dict[str, object], reason: str) -> None:
    args: dict[str, object] = {
        "sender": "dfir@example.test",
        "recipients": ["lead@example.test"],
        "subject": "s",
        "body": "b",
    }
    args.update(kwargs)
    with pytest.raises(OutboundBlockedError) as err:
        _mailer([]).send(MailServer("smtp.example.test"), **args)  # type: ignore[arg-type]
    assert err.value.reason == reason


def test_mail_session_has_a_total_deadline() -> None:
    """A server that never finishes its reply is cut off at the policy's total timeout."""
    shut = threading.Event()

    class StalledSocket:
        """Stands in for the SMTP socket: shutdown() wakes the stalled read (as it does on
        Linux for a real socket)."""

        def shutdown(self, how: int) -> None:
            assert how == socket.SHUT_RDWR
            shut.set()

    class StalledSession(FakeSmtpSession):
        sock = StalledSocket()

        def send_message(self, message: object, from_addr: str, to_addrs: list[str]) -> None:
            if shut.wait(10):  # the server never answers; only the watchdog ends the wait
                raise smtplib.SMTPServerDisconnected("closed")

        def close(self) -> None:
            return None

    mailer = OutboundMailer(
        OutboundPolicy(total_timeout_s=0.3),
        resolver=FakeResolver({"smtp.example.test": [PUBLIC_IP]}),
        session_factory=lambda server, ip, timeout: StalledSession([], server, ip),
    )
    started = time.monotonic()
    with pytest.raises(OutboundError) as err:
        mailer.send(
            MailServer("smtp.example.test"),
            sender="a@example.test",
            recipients=["b@example.test"],
            subject="s",
            body="b",
        )
    assert err.value.category == "timeout" and err.value.transient
    assert time.monotonic() - started < 5


def test_mail_policy() -> None:
    sink: list[dict[str, object]] = []
    args = {
        "sender": "a@example.test",
        "recipients": ["b@example.test"],
        "subject": "s",
        "body": "b",
    }
    with pytest.raises(OutboundBlockedError, match="smtp_plaintext_not_allowed"):
        _mailer(sink).send(MailServer("smtp.example.test", 25, "none"), **args)  # type: ignore[arg-type]
    with pytest.raises(OutboundBlockedError, match="address_private"):
        _mailer(sink).send(MailServer("relay.internal", 25), **args)  # type: ignore[arg-type]
    with pytest.raises(OutboundBlockedError, match="invalid_host"):
        _mailer(sink).send(MailServer("bad host", 25), **args)  # type: ignore[arg-type]
    # An internal relay must be allowlisted explicitly.
    _mailer(sink, allow_hosts=frozenset({"relay.internal"})).send(
        MailServer("relay.internal", 25),
        **args,  # type: ignore[arg-type]
    )
    assert sink[0]["ip"] == "10.0.0.25"
    assert clean_header("a\r\nb\tc\x00d" + "x" * 300, 20) == "a b c d" + "x" * 13


class _TinySmtp(socketserver.StreamRequestHandler):
    """Just enough SMTP for smtplib to deliver one message."""

    received: ClassVar[list[str]] = []

    def handle(self) -> None:
        self.wfile.write(b"220 test ESMTP\r\n")
        data_mode = False
        lines: list[str] = []
        for raw in self.rfile:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if data_mode:
                if line == ".":
                    type(self).received.append("\n".join(lines))
                    data_mode = False
                    self.wfile.write(b"250 queued\r\n")
                else:
                    lines.append(line)
                continue
            verb = line.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250 test\r\n")
            elif verb == "DATA":
                data_mode = True
                self.wfile.write(b"354 go\r\n")
            elif verb == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


def test_real_smtp_session_uses_the_pinned_address() -> None:
    handler = type("Smtp", (_TinySmtp,), {"received": []})
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        mailer = OutboundMailer(
            OutboundPolicy(allow_http=True, allow_hosts=frozenset({"mail.example.test"})),
            resolver=FakeResolver({"mail.example.test": ["127.0.0.1"]}),
        )
        mailer.send(
            MailServer("mail.example.test", server.server_address[1], "none"),
            sender="dfir@example.test",
            recipients=["lead@example.test"],
            subject="Report signed",
            body="Kind: technical\n",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert len(handler.received) == 1
    assert (
        "Subject: Report signed" in handler.received[0] and "Kind: technical" in handler.received[0]
    )


# ------------------------------------------------------------------------------ one module only

NETWORK_MODULES = {
    "socket",
    "ssl",
    "smtplib",
    "http.client",
    "urllib.request",
    "urllib3",
    "requests",
    "httpx",
    "httpx2",
    "aiohttp",
    "ftplib",
    "telnetlib",
    "pymisp",
}
# Who may import them, and why: the outbound module (this phase), the LLM gateway (Phase 7), the
# object-store client (Phase 0), and the two job services that only call socket.gethostname().
ALLOWED = {
    "integrations/outbound.py": NETWORK_MODULES,
    "ai/gateway.py": {"httpx2"},
    "storage.py": {"urllib3"},
    "services/detection.py": {"socket"},
    "services/processing.py": {"socket"},
}


def test_only_the_outbound_module_opens_connections_for_integrations() -> None:
    offenders: list[str] = []
    for path in sorted(APP_DIR.rglob("*.py")):
        rel = path.relative_to(APP_DIR).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                used.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                used.add(node.module)
                used.update(f"{node.module}.{a.name}" for a in node.names)
        hits = {
            m for m in used if m in NETWORK_MODULES or m.split(".")[0] in {"requests", "pymisp"}
        }
        extra = hits - ALLOWED.get(rel, set())
        if extra:
            offenders.append(f"{rel}: {sorted(extra)}")
    assert offenders == []
    for rel in ("services/detection.py", "services/processing.py"):
        src = (APP_DIR / rel).read_text(encoding="utf-8")
        assert src.count("socket.") == src.count("socket.gethostname()"), rel


def test_fake_transport_returns_canned_responses() -> None:
    transport = FakeTransport()
    transport.responses = [HttpResponse(500, {}, b""), OutboundError("timeout", transient=True)]
    http = OutboundHttp(
        STRICT, resolver=FakeResolver({"a.example.test": [PUBLIC_IP]}), transport=transport
    )  # type: ignore[arg-type]
    assert http.request("GET", "https://a.example.test/").status == 500
    with pytest.raises(OutboundError):
        http.request("GET", "https://a.example.test/")
    assert http.request("GET", "https://a.example.test/").ok
