"""Notification messages, inbound payload mapping and enrichment providers (pure; fake transport)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from email.message import EmailMessage

import pytest

from app.integrations import messages as M  # noqa: N812
from app.integrations.enrichment import (
    EnrichmentError,
    FakeEnrichmentProvider,
    Indicator,
    MispProvider,
    VirusTotalProvider,
    tlp_allows,
)
from app.integrations.inbound import (
    ItemError,
    PayloadError,
    map_item,
    parse_items,
    validate_field_map,
)
from app.integrations.outbound import HttpResponse, OutboundError, OutboundHttp, OutboundPolicy
from tests.fakes import FakeResolver, FakeTransport

CASE_ID = "0b0e3f0a-9a2f-4c53-8a6e-5c3d4e1f2a3b"
HOSTILE = "<!channel> *bold* <https://evil.test|click> & `code`\r\nSubject: x \u202e reversed"
ALERT = {
    "event": M.EVENT_ALERT_CREATED,
    "case_id": CASE_ID,
    "case_number": "IR-2026-0007",
    "alert_id": "5f0c7c2e-1111-4222-8333-444455556666",
    "severity": "high",
    "rule_id": "DFIR-WIN-0010",
    "source": "detection",
    "event_count": 3,
    "attack": ["T1490", "<b>not-a-technique</b>"],
    "details": {"title": HOSTILE, "host": "WS-042\nX-Injected: 1"},
}


# ------------------------------------------------------------------------------ messages


def test_messages_carry_no_evidence_text_by_default() -> None:
    message = M.build_message(ALERT, base_url="https://dfir.example/")
    text = json.dumps([message.title, message.lines, message.link])
    assert message.title == "New alert in case IR-2026-0007"
    assert ("Severity", "high") in message.lines and ("ATT&CK", "T1490") in message.lines
    assert message.link == f"https://dfir.example/cases/{CASE_ID}/alerts"
    for leaked in ("channel", "WS-042", "evil.test", "not-a-technique", "reversed"):
        assert leaked not in text
    for rendered in (
        M.render_slack(message),
        M.render_teams(message),
        M.render_email(message)[1].encode(),
        M.render_webhook("e1", "2026-10-01T00:00:00Z", ALERT, include_details=False),
        json.dumps(M.in_app_payload(ALERT)).encode(),
    ):
        assert b"WS-042" not in rendered and b"evil.test" not in rendered


def test_values_outside_the_closed_vocabulary_are_dropped() -> None:
    payload = dict(ALERT, severity="high<script>", rule_id="x y z", case_number="IR-1\r\nBcc: a")
    message = M.build_message(payload)
    assert message.title == "New alert"
    labels = [label for label, _ in message.lines]
    assert "Severity" not in labels and "Rule" not in labels
    assert M.build_message(dict(ALERT, case_id="not-a-uuid"), base_url="https://x.test").link is None
    with pytest.raises(ValueError, match="unknown event"):
        M.build_message({"event": "{{7*7}}"})


def test_details_are_escaped_for_slack() -> None:
    message = M.build_message(ALERT, include_details=True)
    body = json.loads(M.render_slack(message))
    assert body["mrkdwn"] is False
    text = body["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    assert "<https://evil.test|click>" not in text and "&amp;" in text
    assert all("\r" not in line for line in text.split("\n"))
    title_line = next(line for line in text.split("\n") if line.startswith("Title:"))
    assert "Subject: x" in title_line  # the injected line break became a space
    assert chr(0x202E) not in text


def test_details_are_escaped_for_teams() -> None:
    message = M.build_message(ALERT, include_details=True, base_url="https://dfir.example")
    card = json.loads(M.render_teams(message))["attachments"][0]["content"]
    title = next(b["text"] for b in card["body"] if b["text"].startswith("Title"))
    assert "\\*bold\\*" in title and "\\<https://evil.test\\|click\\>" in title
    assert "\\`code\\`" in title and "\n" not in title
    assert card["actions"][0]["url"].startswith("https://dfir.example/cases/")


def test_email_rendering_cannot_inject_headers() -> None:
    message = M.build_message(ALERT, include_details=True)
    subject, body = M.render_email(message)
    assert "\r" not in subject and "\n" not in subject and len(subject) <= 150
    mail = EmailMessage()
    mail["Subject"] = subject  # would raise on a line break
    assert "Title: " in body and "X-Injected: 1" in body  # on the Host line, as inert text
    host_line = next(line for line in body.split("\n") if line.startswith("Host:"))
    assert host_line == "Host: WS-042 X-Injected: 1"


def test_webhook_body_is_canonical_and_details_are_opt_in() -> None:
    plain = M.render_webhook("e1", "2026-10-01T00:00:00Z", ALERT, include_details=False)
    assert plain == M.render_webhook("e1", "2026-10-01T00:00:00Z", dict(ALERT), include_details=False)
    data = json.loads(plain)
    assert data["type"] == "alert.created" and "details" not in data["data"]
    detailed = json.loads(
        M.render_webhook("e1", "2026-10-01T00:00:00Z", ALERT, include_details=True)
    )
    assert detailed["data"]["details"]["host"] == "WS-042 X-Injected: 1"
    assert len(detailed["data"]["details"]["title"]) <= 200
    assert plain.decode("ascii")  # ASCII only: nothing a receiver could mis-decode


def test_every_event_type_renders() -> None:
    for event in M.EVENT_TYPES:
        message = M.build_message({"event": event, "case_id": CASE_ID}, base_url="https://x.test")
        assert message.title and M.render_slack(message) and M.render_teams(message)
        assert M.render_email(message)[0].startswith("[dfirbench]")
        assert M.in_app_payload({"event": event})["tab"] == M.TABS[event]
    assert M.plain("a" * 500, 20).endswith(chr(0x2026)) and len(M.plain("a" * 500, 20)) == 20


# ------------------------------------------------------------------------------ inbound

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def test_parse_items_shapes_and_limits() -> None:
    assert parse_items(b'[{"id":1},{"id":2}]', 10) == [{"id": 1}, {"id": 2}]
    assert parse_items(b'{"alerts":[{"id":1}]}', 10) == [{"id": 1}]
    assert parse_items(b'{"id":"solo","title":"t"}', 10) == [{"id": "solo", "title": "t"}]
    for body, code in (
        (b"not json", "invalid_json"),
        (b"\xff\xfe", "invalid_json"),
        (b'"text"', "invalid_payload"),
        (b"[" * 100_000, "invalid_json"),  # nesting bomb
        (b"[" + b"{}," * 20 + b"{}]", "too_many_items"),
    ):
        with pytest.raises(PayloadError) as err:
            parse_items(body, 10)
        assert err.value.code == code


def test_map_item_cleans_and_caps_untrusted_fields() -> None:
    item = {
        "id": 42,
        "title": "Ransomware\x00 detected " + "A" * 1000,
        "severity": "CRITICAL",
        "timestamp": "2026-09-30T10:00:00+05:30",
        "host": "ws-01",
        "user": {"nested": "ignored"},
        "attack": ["t1486", "T1490", "nope", "T1486"],
        "src_ip": "203.0.113.9",
        "dst_ip": "not-an-ip",
        "description": "x" * 10_000,
        "case_id": "11111111-1111-1111-1111-111111111111",  # never used for routing
        "extra": {"deep": [[[[[["v"]]]]]]},
    }
    alert = map_item(item, {}, NOW)
    assert alert.external_id == "42" and alert.severity == "critical"
    assert "\x00" not in alert.title and len(alert.title) <= 320
    assert alert.ts == datetime(2026, 9, 30, 4, 30, tzinfo=UTC)
    assert alert.ts_original == "2026-09-30T10:00:00+05:30" and alert.ts_source == "payload"
    assert alert.attack == ("T1486", "T1490") and alert.user is None
    assert alert.src_ip == "203.0.113.9" and alert.dst_ip is None
    assert alert.description is not None and len(alert.description) < 4200
    assert len(alert.id_sha256) == 64 and not hasattr(alert, "case_id")


@pytest.mark.parametrize(
    ("item", "reason"),
    [
        ("text", "not_an_object"),
        ([1], "not_an_object"),
        ({"title": "t"}, "missing_id"),
        ({"id": "", "title": "t"}, "missing_id"),
        ({"id": {"a": 1}, "title": "t"}, "missing_id"),
        ({"id": "x" * 300, "title": "t"}, "id_too_long"),
        ({"id": "1"}, "missing_title"),
        ({"id": "1", "title": "t", "timestamp": "yesterday"}, "invalid_timestamp"),
        ({"id": "1", "title": "t", "timestamp": "2026-09-30T10:00:00"}, "timestamp_without_timezone"),
        ({"id": "1", "title": "t", "timestamp": 10**30}, "invalid_timestamp"),
        ({"id": "1", "title": "t", "timestamp": True}, "invalid_timestamp"),
        ({"id": "1", "title": "t", "timestamp": "0001-01-01T00:00:00Z"}, "timestamp_out_of_range"),
        ({"id": "1", "title": "t", "timestamp": ["2026"]}, "invalid_timestamp"),
    ],
)
def test_malformed_items_raise_a_fixed_reason(item: object, reason: str) -> None:
    with pytest.raises(ItemError) as err:
        map_item(item, {}, NOW)
    assert err.value.reason == reason


def test_map_item_defaults_field_map_and_epoch() -> None:
    alert = map_item({"alert_id": "a-1", "name": "N", "level": "weird"}, {}, NOW)
    assert (alert.external_id, alert.title, alert.severity) == ("a-1", "N", "medium")
    assert alert.ts == NOW and alert.ts_source == "received" and alert.ts_original is None
    mapped = map_item(
        {"evt": {"uid": "u-9", "sig": "Sig"}, "host.name": "flat", "when": 1_759_312_800_000},
        validate_field_map({"id": "evt.uid", "title": "evt.sig", "host": "host.name", "timestamp": "when"}),
        NOW,
    )
    assert (mapped.external_id, mapped.title, mapped.host) == ("u-9", "Sig", "flat")
    assert mapped.ts == datetime.fromtimestamp(1_759_312_800, UTC)
    big = map_item({"id": "1", "title": "t", "blob": "z" * 60_000}, {}, NOW)
    assert big.raw["_truncated"] is True
    with pytest.raises(ValueError, match="unknown field"):
        validate_field_map({"case_id": "x"})
    with pytest.raises(ValueError, match="invalid path"):
        validate_field_map({"id": "a..b"})
    with pytest.raises(ValueError, match="invalid path"):
        validate_field_map({"id": "__class__.__init__['x']"})


# ------------------------------------------------------------------------------ enrichment


@pytest.mark.parametrize(
    ("max_tlp", "tlp", "allowed"),
    [
        ("green", "clear", True),
        ("green", "white", True),
        ("green", "green", True),
        ("green", "amber", False),
        ("green", "amber+strict", False),
        ("green", "red", False),
        ("green", None, False),  # unmarked counts as amber
        ("amber", "amber", True),
        ("amber", "amber+strict", False),
        ("amber+strict", "amber+strict", True),
        ("amber+strict", "red", False),
        ("red", "red", False),  # red is never sent anywhere
        ("red", "clear", False),
        ("green", "purple", False),
        ("bogus", "clear", False),
    ],
)
def test_tlp_policy(max_tlp: str, tlp: str | None, allowed: bool) -> None:
    assert tlp_allows(max_tlp, tlp) is allowed


def _http(transport: FakeTransport) -> OutboundHttp:
    return OutboundHttp(
        OutboundPolicy(),
        resolver=FakeResolver(
            {"www.virustotal.com": ["93.184.216.34"], "misp.example.test": ["93.184.216.35"]}
        ),
        transport=transport,  # type: ignore[arg-type]
    )


def _vt_body(malicious: int, harmless: int) -> bytes:
    stats = {"malicious": malicious, "suspicious": 0, "harmless": harmless, "undetected": 5}
    return json.dumps({"data": {"attributes": {"last_analysis_stats": stats}}}).encode()


def test_virustotal_sends_only_the_indicator() -> None:
    transport = FakeTransport()
    transport.responses = [HttpResponse(200, {}, _vt_body(7, 60))]
    transport.default = HttpResponse(404, {}, b"{}")
    vt = VirusTotalProvider(_http(transport), "vt-key-123")
    sha = "a" * 64
    verdict = vt.lookup(Indicator("sha256", sha))
    assert verdict.verdict == "malicious" and verdict.score == round(7 / 72, 3)
    request = transport.requests[0]
    assert request.method == "GET" and request.body == b""  # type: ignore[attr-defined]
    assert request.target.path == f"/api/v3/files/{sha}"  # type: ignore[attr-defined]
    assert request.headers["x-apikey"] == "vt-key-123"  # type: ignore[attr-defined]
    assert vt.lookup(Indicator("ip", "203.0.113.5")).verdict == "unknown"
    assert transport.requests[1].target.path == "/api/v3/ip_addresses/203.0.113.5"  # type: ignore[attr-defined]
    vt.lookup(Indicator("domain", "evil.example"))
    vt.lookup(Indicator("url", "http://evil.example/a?b=1"))
    paths = [r.target.path for r in transport.requests[2:]]  # type: ignore[attr-defined]
    assert paths[0] == "/api/v3/domains/evil.example"
    assert paths[1].startswith("/api/v3/urls/") and "?" not in paths[1] and "=" not in paths[1]
    with pytest.raises(EnrichmentError, match="unsupported_type"):
        vt.lookup(Indicator("email", "a@b.test"))
    with pytest.raises(EnrichmentError, match="sightings_unsupported"):
        vt.add_sighting(Indicator("ip", "203.0.113.5"), datetime.now(UTC))
    assert vt.max_tlp == "green" and vt.supports("md5") and not vt.supports("filename")


@pytest.mark.parametrize(
    ("response", "category", "transient"),
    [
        (HttpResponse(429, {}, b""), "rate_limited", True),
        (HttpResponse(401, {}, b""), "unauthorized", False),
        (HttpResponse(503, {}, b""), "http_503", True),
        (HttpResponse(400, {}, b""), "http_400", False),
        (HttpResponse(200, {}, b"<html>"), "invalid_response", False),
        (HttpResponse(200, {}, b"[1]"), "invalid_response", False),
        (HttpResponse(200, {}, b'{"data": {"attributes": {}}}'), "invalid_response", False),
        (OutboundError("timeout", transient=True), "timeout", True),
    ],
)
def test_provider_errors_are_categories(response: object, category: str, transient: bool) -> None:
    transport = FakeTransport()
    transport.responses = [response]
    with pytest.raises(EnrichmentError) as err:
        VirusTotalProvider(_http(transport), "k" * 10).lookup(Indicator("ip", "203.0.113.5"))
    assert err.value.category == category and err.value.transient is transient


def test_blocked_destination_is_reported_not_contacted() -> None:
    transport = FakeTransport()
    http = OutboundHttp(
        OutboundPolicy(), resolver=FakeResolver({"vt.internal": ["10.0.0.9"]}), transport=transport  # type: ignore[arg-type]
    )
    with pytest.raises(EnrichmentError) as err:
        VirusTotalProvider(http, "k" * 10, "https://vt.internal").lookup(Indicator("ip", "1.1.1.1"))
    assert err.value.category == "blocked:address_private" and transport.requests == []


def test_misp_lookup_and_sighting() -> None:
    transport = FakeTransport()
    found = {
        "response": {
            "Attribute": [
                {"event_id": "12", "to_ids": True, "Tag": [{"name": "tlp:green"}, {"name": "x" * 99}]},
                {"event_id": "13", "to_ids": False, "Tag": [{"name": "<script>"}]},
                "junk",
            ]
        }
    }
    transport.responses = [
        HttpResponse(200, {}, json.dumps(found).encode()),
        HttpResponse(200, {}, b'{"response": {"Attribute": []}}'),
        HttpResponse(200, {}, b"{}"),
    ]
    misp = MispProvider(_http(transport), "misp-key-1", "https://misp.example.test/", "amber")
    verdict = misp.lookup(Indicator("domain", "evil.example"))
    assert verdict.verdict == "malicious" and verdict.summary["events"] == 2
    assert verdict.summary["tags"] == ["tlp:green"]  # only short safe tokens are kept
    sent = json.loads(transport.requests[0].body)  # type: ignore[attr-defined]
    assert sent == {"returnFormat": "json", "value": "evil.example", "limit": 50}
    assert transport.requests[0].headers["Authorization"] == "misp-key-1"  # type: ignore[attr-defined]
    assert misp.lookup(Indicator("ip", "203.0.113.5")).verdict == "unknown"
    when = datetime(2026, 10, 1, tzinfo=UTC)
    misp.add_sighting(Indicator("ip", "203.0.113.5"), when)
    sighting = json.loads(transport.requests[2].body)  # type: ignore[attr-defined]
    assert sighting == {"value": "203.0.113.5", "timestamp": int(when.timestamp()), "source": "dfirbench"}
    assert transport.requests[2].target.path == "/sightings/add"  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="max_tlp"):
        MispProvider(_http(transport), "k", "https://misp.example.test", "red")


def test_fake_provider_is_deterministic_and_offline() -> None:
    fake = FakeEnrichmentProvider("virustotal")
    first = fake.lookup(Indicator("ip", "203.0.113.5"))
    assert first == FakeEnrichmentProvider().lookup(Indicator("ip", "203.0.113.5"))
    assert first.summary["simulated"] is True and first.verdict in {"malicious", "suspicious", "harmless"}
    fake.add_sighting(Indicator("ip", "203.0.113.5"), datetime.now(UTC))
    assert fake.lookups == [Indicator("ip", "203.0.113.5")] and len(fake.sightings) == 1
    fake.fail_with = EnrichmentError("rate_limited", transient=True)
    with pytest.raises(EnrichmentError):
        fake.lookup(Indicator("ip", "203.0.113.5"))
    with pytest.raises(EnrichmentError):
        fake.add_sighting(Indicator("ip", "203.0.113.5"), datetime.now(UTC))
