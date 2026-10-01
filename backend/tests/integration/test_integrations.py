"""Phase 9: integrations end to end on the test database with fake network doubles.

Covers write-only encrypted secrets, the outbox (events never break the business transaction),
signed webhook deliveries with bounded retries and a terminal failed state, SSRF-blocked
deliveries, notification channels with deduplication and rate limits, HMAC-authenticated SIEM
ingest (uniform 401, replay, size cap, malformed items, idempotency, closed case, rate limits),
enrichment (policy switch, TLP, cache, indicators only, sightings), notification rules, key
rotation and the grants of the app role. Nothing here touches the network.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import DBAPIError

import app.services.outbox as outbox
from app.config import Settings
from app.core.signing import CustodySigner
from app.db.models import (
    Alert,
    AlertHistory,
    AuditLog,
    InboundDelivery,
    Integration,
    IocEnrichment,
    Notification,
    OutboundDelivery,
    OutboundEvent,
    UserRole,
)
from app.integrations import webhooks
from app.integrations.crypto import Keyring, SealedSecret, integration_aad
from app.integrations.enrichment import EnrichmentError, Indicator
from app.integrations.outbound import HttpResponse, OutboundError
from app.services.integrations import IntegrationService
from app.services.outbox import DISPATCH_KEY, emit_event
from tests.fakes import FakeVault
from tests.integration.conftest import make_test_settings
from tests.integration.harness import Harness

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUTH_LOG = (FIXTURES / "linux" / "auth.log").read_bytes()
SIGNING = "whsec-test-signing-secret-0123456789abcdef"
SLACK_URL = "https://hooks.example.test/services/T000/B000/slack-token-do-not-leak"
PUBLIC_IP = "93.184.216.34"


class World:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.admin = h.make_user(UserRole.admin)
        self.lead = h.make_user(UserRole.lead)
        self.analyst = h.make_user(UserRole.analyst)
        self.viewer = h.make_user(UserRole.viewer)
        self.case = h.create_case(self.lead, "Integration case")
        self.cid = self.case["id"]
        for user, role in ((self.analyst, UserRole.analyst), (self.viewer, UserRole.viewer)):
            h.add_member(self.lead, self.cid, user, role)
        # Leave earlier tests' outbox rows behind: deliver them now against the fake transport.
        h.deliver()
        h.transport.requests.clear()
        h.mails.clear()

    def name(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:10]}"

    def create(self, kind: str, **body: Any) -> dict[str, Any]:
        payload = {"type": kind, "name": self.name(kind), **body}
        r = self.h.post("/integrations", self.admin, json=payload)
        assert r.status_code == 201, r.text
        return dict(r.json())

    def webhook(self, events: list[str], **config: Any) -> dict[str, Any]:
        return self.create(
            "webhook_out",
            config={
                "url": "https://hooks.example.test/hook",
                "events": events,
                "case_ids": [self.cid],
                **config,
            },
            secret={"signing_secret": SIGNING},
            enabled=True,
        )

    def emit(self, event_type: str, payload: dict[str, Any], **kw: Any) -> str:
        with self.h.sessions() as session:
            outcome = emit_event(
                session, event_type, case_id=uuid.UUID(self.cid), payload=payload, **kw
            )
            session.commit()
        return outcome

    def deliveries(self, integration_id: str) -> list[OutboundDelivery]:
        with self.h.sessions() as session:
            return list(
                session.execute(
                    select(OutboundDelivery)
                    .join(OutboundEvent, OutboundEvent.id == OutboundDelivery.event_id)
                    .where(OutboundDelivery.integration_id == uuid.UUID(integration_id))
                    .order_by(OutboundEvent.created_at, OutboundEvent.id)  # in event order
                ).scalars()
            )


@pytest.fixture
def world(h: Harness) -> World:
    return World(h)


def other_harness(
    app_engine: Engine, db_url: str, signer: CustodySigner, **overrides: Any
) -> Harness:
    return Harness(app_engine, make_test_settings(db_url, **overrides), signer, FakeVault())


# ------------------------------------------------------------------ secrets


def test_integration_crud_and_write_only_secrets(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    h = world.h
    caplog.set_level(logging.DEBUG)
    name = world.name("hook")
    body = {
        "type": "webhook_out",
        "name": name,
        "config": {"url": "https://hooks.example.test/hook", "events": ["report.signed"]},
        "secret": {"signing_secret": SIGNING},
        "enabled": True,
    }
    for user in (world.lead, world.analyst, world.viewer):
        assert h.post("/integrations", user, json=body).status_code == 403
        assert h.get("/integrations", user).status_code == 403
    assert h.get("/integrations").status_code == 401
    r = h.post("/integrations", world.admin, json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    iid = created["id"]
    assert created["has_secret"] is True and created["enabled"] is True
    assert len(created["secret_fingerprint"]) == 12 and created["secret_key_id"] == "test-kek-1"
    assert "secret" not in created and SIGNING not in r.text
    assert h.post("/integrations", world.admin, json=body).status_code == 409  # name taken

    listed = h.get("/integrations", world.admin)
    assert listed.json()["secrets_available"] is True and SIGNING not in listed.text
    detail = h.get(f"/integrations/{iid}", world.admin)
    assert detail.status_code == 200 and SIGNING not in detail.text
    assert h.get(f"/integrations/{uuid.uuid4()}", world.admin).status_code == 404

    # At rest: ciphertext only, bound to this row, readable with the KEK from settings only.
    with h.sessions() as session:
        row = session.get(Integration, uuid.UUID(iid))
        assert row is not None and row.config_encrypted and row.secret_wrapped_key
        blob = bytes(row.config_encrypted) + bytes(row.secret_wrapped_key)
        assert SIGNING.encode() not in blob and SIGNING not in json.dumps(row.config)
        sealed = SealedSecret(
            bytes(row.config_encrypted), bytes(row.secret_wrapped_key), row.secret_key_id or ""
        )
        ring = Keyring.from_settings(h.settings)
        assert ring.open(sealed, integration_aad(iid)) == {"signing_secret": SIGNING}
        with pytest.raises(Exception, match="authentication failed"):
            ring.open(sealed, integration_aad(uuid.uuid4()))

    # Replacing the secret changes the fingerprint; it still never comes back.
    new_secret = "whsec-rotated-" + "z" * 32
    r = h.patch(
        f"/integrations/{iid}", world.admin, json={"secret": {"signing_secret": new_secret}}
    )
    assert r.status_code == 200 and r.json()["secret_fingerprint"] != created["secret_fingerprint"]
    assert new_secret not in r.text
    r = h.patch(f"/integrations/{iid}", world.admin, json={"enabled": False, "name": name + "-x"})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["has_secret"]
    assert h.patch(f"/integrations/{iid}", world.lead, json={"enabled": True}).status_code == 403
    assert (
        h.client.request(
            "DELETE", f"/api/v1/integrations/{iid}", headers=world.admin.headers
        ).status_code
        == 405
    )  # disabled, never deleted

    # Never in the audit log, the request log or any error message.
    with h.sessions() as session:
        rows = (
            session.execute(
                select(AuditLog).where(
                    AuditLog.object_type == "integration", AuditLog.object_id == iid
                )
            )
            .scalars()
            .all()
        )
        everything = session.execute(
            text("SELECT string_agg(detail::text, ' ') FROM audit_log WHERE object_id = :i"),
            {"i": iid},
        ).scalar_one()
    assert {r.action for r in rows} == {"integration.created", "integration.updated"}
    assert any(r.detail.get("secret_changed") is True for r in rows)
    for secret in (SIGNING, new_secret):
        assert secret not in everything and secret not in caplog.text
    short = h.post(
        "/integrations",
        world.admin,
        json={
            **body,
            "name": world.name("short"),
            "secret": {"signing_secret": "too-short-secret"},
        },
    )
    assert short.status_code == 422 and "too-short-secret" not in short.text
    assert "too-short-secret" not in caplog.text


def test_integration_validation(world: World) -> None:
    h = world.h

    def post(**changes: Any) -> Any:
        body: dict[str, Any] = {
            "type": "webhook_out",
            "name": world.name("v"),
            "config": {"url": "https://hooks.example.test/hook", "events": ["alert.created"]},
            "secret": {"signing_secret": SIGNING},
        }
        body.update(changes)
        return h.post("/integrations", world.admin, json=body)

    def cfg(**changes: Any) -> dict[str, Any]:
        return {"url": "https://hooks.example.test/hook", "events": ["alert.created"], **changes}

    for config, reason in (
        (cfg(url="http://hooks.example.test/hook"), "http_not_allowed"),
        (cfg(url="https://user:pw@hooks.example.test/hook"), "credentials_in_url"),
        (cfg(url="https://127.0.0.1/hook"), "address_loopback"),
        (cfg(url="https://10.0.0.8:8443/hook"), "address_private"),
        (cfg(url="https://169.254.169.254/latest/meta-data"), "address_metadata"),
        (cfg(url="https://[::ffff:10.0.0.8]/hook"), "address_embedded_ipv4"),
        (cfg(url="ftp://hooks.example.test/hook"), "scheme_not_allowed"),
    ):
        r = post(config=config)
        assert r.status_code == 422 and r.json()["error"]["details"]["reason"] == reason, r.text
    for config in (cfg(events=["user.deleted"]), cfg(extra=1), cfg(min_severity="urgent"), {}):
        assert post(config=config).status_code == 422
    assert post(type="ftp").status_code == 422
    assert post(name="bad name!").status_code == 422
    assert post(secret={"api_key": "x" * 40}).status_code == 422  # not a field of this type
    assert post(secret={"signing_secret": "has\nnewline" + "x" * 40}).status_code == 422
    assert post(case_id=world.cid).status_code == 422  # only ingest sources have a case
    # Enabling needs a complete integration.
    assert post(secret=None, enabled=True).status_code == 422
    assert post(config=cfg(events=[]), enabled=True).status_code == 422
    r = post(secret=None)
    assert r.status_code == 201 and r.json()["has_secret"] is False
    assert r.json()["secret_fingerprint"] is None
    iid = r.json()["id"]
    assert h.patch(f"/integrations/{iid}", world.admin, json={"enabled": True}).status_code == 422
    assert h.post(f"/integrations/{iid}/test", world.admin).status_code == 409  # disabled
    # Other types.
    slack = world.create("slack", config={"events": ["alert.created"]})
    r = h.patch(
        f"/integrations/{slack['id']}",
        world.admin,
        json={"secret": {"webhook_url": "http://hooks.example.test/x"}},
    )
    assert r.status_code == 422 and "hooks.example.test/x" not in r.text
    mail = {
        "host": "smtp.example.test",
        "sender": "dfir@example.test",
        "recipients": ["lead@example.test"],
        "events": ["report.signed"],
    }
    assert world.create("email", config=mail)["has_secret"] is False
    for bad in (
        {**mail, "recipients": ["Lead <lead@example.test>"]},
        {**mail, "sender": "a@example.test\r\nBcc: x@evil.test"},
        {**mail, "security": "none"},
        {**mail, "recipients": []},
    ):
        r = h.post(
            "/integrations",
            world.admin,
            json={"type": "email", "name": world.name("m"), "config": bad},
        )
        assert r.status_code == 422, r.text
    r = h.post(
        "/integrations",
        world.admin,
        json={
            "type": "webhook_in",
            "name": world.name("in"),
            "config": {"field_map": {"case_id": "x"}},
        },
    )
    assert r.status_code == 422
    r = h.post(
        "/integrations",
        world.admin,
        json={
            "type": "webhook_in",
            "name": world.name("in"),
            "secret": {"signing_secret": SIGNING},
            "enabled": True,
        },
    )
    assert r.status_code == 422 and "case" in r.json()["error"]["message"]
    r = h.post(
        "/integrations",
        world.admin,
        json={"type": "webhook_in", "name": world.name("in"), "case_id": str(uuid.uuid4())},
    )
    assert r.status_code == 404
    assert (
        h.post(
            "/integrations",
            world.admin,
            json={
                "type": "misp",
                "name": world.name("misp"),
                "config": {"url": "https://misp.example.test", "max_tlp": "red"},
            },
        ).status_code
        == 422
    )


def test_secrets_cannot_be_saved_without_a_kek(
    app_engine: Engine, migrated_db_url: str, signer: CustodySigner
) -> None:
    h = other_harness(app_engine, migrated_db_url, signer, integration_kek=None)
    with h.client:
        admin = h.make_user(UserRole.admin)
        body = {
            "type": "virustotal",
            "name": f"vt-{uuid.uuid4().hex[:8]}",
            "secret": {"api_key": "vt-api-key-0123456789"},
        }
        r = h.post("/integrations", admin, json=body)
        assert r.status_code == 503 and r.json()["error"]["code"] == "secrets_unavailable"
        assert "vt-api-key" not in r.text
        assert h.get("/integrations", admin).json()["secrets_available"] is False
        del body["secret"]
        assert h.post("/integrations", admin, json=body).status_code == 201  # no secret: fine


def test_kek_rotation_rewrap(world: World, tmp_path: Path) -> None:
    h = world.h
    hook = world.webhook(["report.signed"])
    previous = tmp_path / "previous.json"
    previous.write_text(
        json.dumps({"test-kek-1": "integration-test-kek-0123456789abcdef"}), encoding="utf-8"
    )
    rotated = h.settings.model_copy(
        update={
            "integration_kek": Settings(
                _env_file=None,
                integration_kek="rotated-kek-material-abcdef0123456789",  # type: ignore[call-arg,arg-type]
            ).integration_kek,
            "integration_kek_id": "test-kek-2",
            "integration_kek_previous_path": str(previous),
        }
    )
    with h.sessions() as session:
        counts = IntegrationService(session, rotated).rewrap_all()
    assert counts["rewrapped"] >= 1 and counts["failed"] == 0
    with h.sessions() as session:
        row = session.get(Integration, uuid.UUID(hook["id"]))
        assert row is not None and row.secret_key_id == "test-kek-2"
        sealed = SealedSecret(
            bytes(row.config_encrypted or b""), bytes(row.secret_wrapped_key or b""), "test-kek-2"
        )
        new_only = Keyring("test-kek-2", "rotated-kek-material-abcdef0123456789")
        assert new_only.open(sealed, integration_aad(row.id)) == {"signing_secret": SIGNING}
        assert IntegrationService(session, rotated).rewrap_all()["rewrapped"] == 0
    # Put the rows back under the test KEK so other tests keep reading them.
    back = tmp_path / "back.json"
    back.write_text(json.dumps({"test-kek-2": "rotated-kek-material-abcdef0123456789"}), "utf-8")
    with h.sessions() as session:
        restore = h.settings.model_copy(update={"integration_kek_previous_path": str(back)})
        assert IntegrationService(session, restore).rewrap_all()["failed"] == 0


# ------------------------------------------------------------------ outbox and webhooks


def test_signed_webhook_delivery_and_log(world: World) -> None:
    h = world.h
    hook = world.webhook(["case.status_changed"])
    dispatched = h.outbound_dispatched
    r = h.patch(f"/cases/{world.cid}", world.lead, json={"status": "triage"})
    assert r.status_code == 200, r.text
    assert h.outbound_dispatched == dispatched + 1  # the commit asked the worker to run
    result = h.deliver()
    assert result.delivered == 1 and result.failed == 0
    request = h.transport.requests[-1]
    assert request.target.host == "hooks.example.test" and request.ip == PUBLIC_IP  # type: ignore[attr-defined]
    assert request.method == "POST" and request.target.path == "/hook"  # type: ignore[attr-defined]
    headers = request.headers  # type: ignore[attr-defined]
    body = request.body  # type: ignore[attr-defined]
    assert (
        headers["X-Event"] == "case.status_changed"
        and headers["Content-Type"] == "application/json"
    )
    digest = webhooks.verify(
        SIGNING, headers["X-Timestamp"], body, headers["X-Signature"], now=time.time(), window_s=300
    )
    assert digest is not None
    assert (
        webhooks.verify(
            "wrong",
            headers["X-Timestamp"],
            body,
            headers["X-Signature"],
            now=time.time(),
            window_s=300,
        )
        is None
    )
    data = json.loads(body)
    assert data["type"] == "case.status_changed" and data["data"]["case_id"] == world.cid
    assert data["data"]["from_status"] == "open" and data["data"]["to_status"] == "triage"
    assert (
        data["data"]["case_number"] == world.case["case_number"] and "details" not in data["data"]
    )
    assert SIGNING.encode() not in body and SIGNING not in json.dumps(dict(headers))
    log = h.get(f"/integrations/{hook['id']}/deliveries", world.admin).json()
    assert len(log["outbound"]) == 1 and log["inbound"] == []
    entry = log["outbound"][0]
    assert (entry["status"], entry["attempts"], entry["response_status"]) == ("delivered", 1, 200)
    assert (
        entry["id"] == headers["X-Delivery-Id"]
        and entry["delivered_at"]
        and not entry["last_error"]
    )
    assert h.get(f"/integrations/{hook['id']}", world.admin).json()["last_status"] == "ok"
    assert h.get(f"/integrations/{hook['id']}/deliveries", world.lead).status_code == 403
    # Closing the case is a status change too; other event types are not sent to this hook.
    assert (
        h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"}).status_code == 200
    )
    world.emit("report.signed", {"report_id": str(uuid.uuid4())})
    assert h.deliver().delivered == 1
    assert json.loads(h.transport.requests[-1].body)["data"]["to_status"] == "closed"  # type: ignore[attr-defined]
    assert h.deliver().attempted == 0  # nothing is delivered twice


def test_delivery_retries_with_backoff_then_fails_for_good(world: World, db_engine: Engine) -> None:
    h = world.h
    hook = world.webhook(["report.signed"])
    now = {"t": datetime.now(UTC)}
    world.emit("report.signed", {"report_id": str(uuid.uuid4())})
    h.transport.default = HttpResponse(500, {}, b"upstream body that must not be stored")
    first = h.deliver(clock=lambda: now["t"])
    assert (first.attempted, first.retried, first.failed, first.retry_in_s) == (1, 1, 0, 30)
    row = world.deliveries(hook["id"])[0]
    assert (row.status, row.attempts, row.last_error, row.response_status) == (
        "pending",
        1,
        "http_500",
        500,
    )
    assert row.next_attempt_at == now["t"] + timedelta(seconds=30) and row.locked_until is None
    assert h.deliver(clock=lambda: now["t"]).attempted == 0  # not due yet
    now["t"] += timedelta(seconds=31)
    h.transport.responses = [OutboundError("timeout", transient=True)]
    second = h.deliver(clock=lambda: now["t"])
    assert (second.attempted, second.retried, second.retry_in_s) == (1, 1, 60)  # backoff doubles
    assert world.deliveries(hook["id"])[0].last_error == "timeout"
    now["t"] += timedelta(seconds=61)
    third = h.deliver(clock=lambda: now["t"])
    assert (third.attempted, third.failed, third.retried) == (1, 1, 0)  # attempt 3 of 3: terminal
    row = world.deliveries(hook["id"])[0]
    assert (row.status, row.attempts, row.max_attempts) == ("failed", 3, 3)
    assert row.next_attempt_at is None and row.delivered_at is None and row.last_error == "http_500"
    now["t"] += timedelta(days=1)
    assert h.deliver(clock=lambda: now["t"]).attempted == 0  # never again
    assert len(h.transport.requests) == 3
    assert h.get(f"/integrations/{hook['id']}", world.admin).json()["last_status"] == "http_500"
    log = h.get(f"/integrations/{hook['id']}/deliveries", world.admin)
    assert "upstream body" not in log.text and "hooks.example.test" not in log.text

    # A permanent answer (4xx) fails at once; a redirect is not followed and counts as failure.
    for response, error in (
        (HttpResponse(410, {}, b""), "http_410"),
        (HttpResponse(302, {"location": "https://evil.test/"}, b""), "http_302"),
    ):
        world.emit("report.signed", {"report_id": str(uuid.uuid4())})
        h.transport.responses = [response]
        result = h.deliver(clock=lambda: now["t"])
        assert (result.attempted, result.failed) == (1, 1)
        last = world.deliveries(hook["id"])[-1]
        assert (last.status, last.attempts, last.last_error) == ("failed", 1, error)
    assert all(r.target.host == "hooks.example.test" for r in h.transport.requests)  # type: ignore[attr-defined]

    # The log is frozen once terminal, and the app role cannot delete or re-target it.
    p = {"d": str(row.id)}
    for sql, match in (
        (
            "UPDATE outbound_deliveries SET status = 'pending', next_attempt_at = now() "
            "WHERE id = :d",
            "is failed and cannot change",
        ),
        (
            "UPDATE outbound_deliveries SET last_error = NULL WHERE id = :d",
            "is failed and cannot change",
        ),
        ("DELETE FROM outbound_deliveries WHERE id = :d", "permission denied"),
        (
            "UPDATE outbound_deliveries SET integration_id = integration_id WHERE id = :d",
            "permission denied",
        ),
        ("UPDATE outbound_deliveries SET max_attempts = 99 WHERE id = :d", "permission denied"),
        ("DELETE FROM outbound_events", "permission denied"),
        ("UPDATE outbound_events SET payload = '{}'::jsonb", "permission denied"),
    ):
        with pytest.raises(DBAPIError, match=match), db_engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE dfirbench_app"))
            conn.execute(text(sql), p)
    h.transport.default = HttpResponse(200, {}, b"ok")


def test_crashed_attempt_is_reclaimed_after_its_lease(world: World) -> None:
    h = world.h
    hook = world.webhook(["report.signed"])
    world.emit("report.signed", {"report_id": str(uuid.uuid4())})
    now = {"t": datetime.now(UTC)}
    service = h.outbound(clock=lambda: now["t"])
    service.fan_out(outbox.ProcessResult())
    assert service._claim() is not None  # a worker took it and then died
    assert service._claim() is None  # leased: nobody else sends it meanwhile
    row = world.deliveries(hook["id"])[0]
    assert row.attempts == 1 and row.locked_until is not None and row.locked_until > now["t"]
    now["t"] = row.locked_until + timedelta(seconds=1)
    result = h.deliver(clock=lambda: now["t"])
    assert (result.attempted, result.delivered) == (1, 1)
    assert world.deliveries(hook["id"])[0].attempts == 2


def test_ssrf_blocked_delivery_never_leaves(world: World) -> None:
    h = world.h
    h.resolver.table["internal.example.test"] = ["10.0.0.5"]
    h.resolver.table["rebind.example.test"] = [PUBLIC_IP, "169.254.169.254"]
    hooks = [
        world.webhook(["report.signed"], url=f"https://{host}/hook")
        for host in ("internal.example.test", "rebind.example.test", "unresolvable.example.test")
    ]
    world.emit("report.signed", {"report_id": str(uuid.uuid4())})
    result = h.deliver()
    assert result.attempted == 3 and result.failed == 2 and result.retried == 1
    assert h.transport.requests == []  # nothing was sent anywhere
    rows = [world.deliveries(x["id"])[0] for x in hooks]
    assert (rows[0].status, rows[0].last_error, rows[0].attempts) == (
        "failed",
        "blocked:address_private",
        1,
    )
    assert (rows[1].status, rows[1].last_error) == ("failed", "blocked:address_metadata")
    assert (rows[2].status, rows[2].last_error) == ("pending", "dns_error")  # transient: retried
    # http:// is refused at save time unless the dev switch is on, and then at send time too.
    with h.sessions() as session:
        row = session.get(Integration, uuid.UUID(hooks[0]["id"]))
        assert row is not None
        row.config = {**row.config, "url": "http://hooks.example.test/hook"}
        session.commit()
    world.emit("report.signed", {"report_id": str(uuid.uuid4())})
    h.deliver()
    assert world.deliveries(hooks[0]["id"])[-1].last_error == "blocked:http_not_allowed"
    assert h.transport.requests == []


def test_emitting_never_breaks_the_business_transaction(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = world.h

    def events() -> int:
        with h.sessions() as session:
            return int(
                session.execute(
                    select(func.count())
                    .select_from(OutboundEvent)
                    .where(OutboundEvent.case_id == uuid.UUID(world.cid))
                ).scalar_one()
            )

    before = events()

    # 1. The outbox insert itself blows up: the case update still commits.
    def boom(*args: Any, **kw: Any) -> Any:
        raise RuntimeError("outbox down")

    monkeypatch.setattr(outbox, "pg_insert", boom)
    r = h.patch(f"/cases/{world.cid}", world.lead, json={"status": "triage"})
    assert r.status_code == 200 and r.json()["status"] == "triage"
    assert events() == before
    monkeypatch.undo()
    # 2. A database error inside the SAVEPOINT (unknown case: FK violation) leaves the outer
    #    transaction usable; what the caller wrote before and after still commits.
    with h.sessions() as session:
        session.add(Notification(user_id=world.lead.id, kind="before", payload={}))
        session.flush()
        outcome = emit_event(session, "report.signed", case_id=uuid.uuid4(), payload={"x": 1})
        assert outcome == "error"
        session.add(Notification(user_id=world.lead.id, kind="after", payload={}))
        session.commit()
        kinds = set(
            session.execute(
                select(Notification.kind).where(Notification.user_id == world.lead.id)
            ).scalars()
        )
    assert {"before", "after"} <= kinds
    # 3. The dispatcher fails (broker down): the request still succeeds, the event is stored and
    #    the next worker run delivers it.
    hook = world.webhook(["case.status_changed"])

    def broker_down() -> None:
        raise ConnectionError("redis is down")

    h.sessions.configure(info={DISPATCH_KEY: broker_down})
    r = h.patch(f"/cases/{world.cid}", world.lead, json={"status": "containment"})
    assert r.status_code == 200 and r.json()["status"] == "containment"
    h.sessions.configure(info={DISPATCH_KEY: h._dispatch_outbound})
    assert events() == before + 1
    assert h.deliver().delivered == 1 and world.deliveries(hook["id"])[0].status == "delivered"
    # 4. A rolled-back business transaction leaves no event and triggers no dispatch.
    count = h.outbound_dispatched
    with h.sessions() as session:
        assert (
            emit_event(session, "report.signed", case_id=uuid.UUID(world.cid), payload={})
            == "created"
        )
        session.rollback()
    assert events() == before + 1 and h.outbound_dispatched == count
    # 5. The dedup key makes an event unique.
    key = f"k-{uuid.uuid4()}"
    assert world.emit("report.signed", {}, dedup_key=key) == "created"
    assert world.emit("report.signed", {}, dedup_key=key) == "duplicate"


def test_detection_emits_alert_created_once_per_alert(world: World) -> None:
    h = world.h
    hook = world.webhook(["alert.created"], include_details=True)
    ev = h.stored_evidence(world.analyst, world.cid, AUTH_LOG, original_name="auth.log")
    r = h.post(f"/evidence/{ev['id']}/process", world.analyst, json={"parsers": ["linux_auth"]})
    assert r.status_code == 202, r.text
    assert {x.outcome for x in h.run_pending()} == {"succeeded"}
    assert h.post(f"/cases/{world.cid}/detect", world.analyst).status_code in (200, 202)
    assert {x.outcome for x in h.run_detect_pending()} == {"succeeded"}
    with h.sessions() as session:
        alerts = (
            session.execute(select(Alert).where(Alert.case_id == uuid.UUID(world.cid)))
            .scalars()
            .all()
        )
        created = (
            session.execute(
                select(OutboundEvent).where(
                    OutboundEvent.case_id == uuid.UUID(world.cid),
                    OutboundEvent.event_type == "alert.created",
                )
            )
            .scalars()
            .all()
        )
    assert alerts and {e.payload["alert_id"] for e in created} == {str(a.id) for a in alerts}
    one = created[0].payload
    assert one["source"] == "detection" and one["severity"] in ("low", "medium", "high", "critical")
    assert one["rule_id"].startswith("DFIR-") and "title" in one["details"]
    assert h.deliver().delivered == len(alerts)
    sent = json.loads(h.transport.requests[-1].body)  # type: ignore[attr-defined]
    assert sent["type"] == "alert.created" and sent["data"]["details"]["title"]
    # A second detection run finds the same alerts: no new events, nothing sent again.
    r = h.post(f"/cases/{world.cid}/detect", world.analyst)
    assert r.status_code in (200, 202), r.text
    assert {x.outcome for x in h.run_detect_pending()} == {"succeeded"}
    assert h.deliver().attempted == 0 and len(world.deliveries(hook["id"])) == len(alerts)


def test_evidence_verification_failure_is_emitted(world: World) -> None:
    h = world.h
    hook = world.webhook(["evidence.verification_failed"], include_details=True)
    ev = h.stored_evidence(
        world.analyst, world.cid, b"evidence bytes\n" * 50, original_name="x.log"
    )
    assert h.vault is not None
    h.vault.corrupt(h.key_of(ev), ev["storage_version_id"], offset=3)
    r = h.post(f"/evidence/{ev['id']}/verify", world.analyst)
    assert r.status_code == 200 and r.json()["ok"] is False, r.text
    assert h.post(f"/evidence/{ev['id']}/verify", world.analyst).status_code in (200, 409)
    assert h.deliver().delivered == 1  # one event per evidence item and hour
    sent = json.loads(h.transport.requests[-1].body)  # type: ignore[attr-defined]
    assert sent["type"] == "evidence.verification_failed"
    assert sent["data"]["evidence_id"] == ev["id"] and sent["data"]["stage"] == "verify"
    assert sent["data"]["details"]["label"] == ev["label"]
    assert len(world.deliveries(hook["id"])) == 1


# ------------------------------------------------------------------ notification channels


def test_notification_dedup_rate_limit_and_content(world: World) -> None:
    h = world.h
    slack = world.create(
        "slack",
        config={"events": ["alert.created"], "min_severity": "high", "case_ids": [world.cid]},
        secret={"webhook_url": SLACK_URL},
        enabled=True,
    )
    hostile = "<!channel> *x* <https://evil.test|click>\r\nBcc: a@evil.test"

    def alert(rule: str, severity: str = "high") -> None:
        aid = str(uuid.uuid4())
        assert (
            world.emit(
                "alert.created",
                {
                    "alert_id": aid,
                    "severity": severity,
                    "rule_id": rule,
                    "source": "detection",
                    "event_count": 2,
                },
                details={"title": hostile, "host": "WS-042"},
                dedup_key=f"alert.created:{aid}",
            )
            == "created"
        )

    for _ in range(3):
        alert("DFIR-WIN-0010")  # an alert storm from one rule
    alert("DFIR-WIN-0011")
    alert("DFIR-WIN-0012", "low")  # below the channel's threshold: no row at all
    result = h.deliver()
    rows = world.deliveries(slack["id"])
    assert [(r.status, r.last_error) for r in rows] == [
        ("delivered", None),
        ("suppressed", "duplicate"),
        ("suppressed", "duplicate"),
        ("delivered", None),
    ]
    assert result.delivered == 2 and result.suppressed == 2
    sent = h.transport.requests[-2:]  # the two that were delivered, in either order
    assert {r.target.path for r in sent} == {"/services/T000/B000/slack-token-do-not-leak"}  # type: ignore[attr-defined]
    messages = [json.loads(r.body) for r in sent]  # type: ignore[attr-defined]
    assert all(m["mrkdwn"] is False for m in messages)
    texts = sorted(m["text"] for m in messages)
    assert all(t.startswith(f"New alert in case {world.case['case_number']}") for t in texts)
    assert "Severity: high" in texts[0] and "Rule: DFIR-WIN-0010" in texts[0]
    assert "Rule: DFIR-WIN-0011" in texts[1]
    for leak in ("WS-042", "evil.test", "channel"):  # no evidence text by default
        assert leak not in texts[0] + texts[1]
    log = h.get(f"/integrations/{slack['id']}/deliveries", world.admin)
    assert "slack-token-do-not-leak" not in log.text
    assert "slack-token-do-not-leak" not in h.get("/integrations", world.admin).text

    # The per-channel rate limit (2 per hour here): the next distinct alert is recorded, not sent.
    alert("DFIR-WIN-0003")
    limited = h.deliver(notify_rate_limit_per_hour=2)
    assert limited.suppressed == 1 and limited.attempted == 0
    assert world.deliveries(slack["id"])[-1].last_error == "rate_limited"
    # With details switched on, evidence text is escaped for Slack.
    assert (
        h.patch(
            f"/integrations/{slack['id']}",
            world.admin,
            json={
                "config": {
                    "events": ["alert.created"],
                    "include_details": True,
                    "case_ids": [world.cid],
                }
            },
        ).status_code
        == 200
    )
    alert("DFIR-LNX-0001", "critical")
    h.deliver()
    text_ = json.loads(h.transport.requests[-1].body)["text"]  # type: ignore[attr-defined]
    assert "&lt;!channel&gt;" in text_ and "<!channel>" not in text_ and "\r" not in text_
    assert "Host: WS-042" in text_

    # In-app: the default rule sends high alerts to the case lead, once per rule in the window.
    with h.sessions() as session:
        mine = (
            session.execute(
                select(Notification).where(
                    Notification.user_id == world.lead.id,
                    Notification.kind == "alert.created",
                    Notification.case_id == uuid.UUID(world.cid),
                )
            )
            .scalars()
            .all()
        )
        others = session.execute(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.kind == "alert.created",
                Notification.case_id == uuid.UUID(world.cid),
                Notification.user_id != world.lead.id,
            )
        ).scalar_one()
    rules = sorted(f["value"] for n in mine for f in n.payload["fields"] if f["label"] == "Rule")
    # (DFIR-WIN-0003 arrived while the lead already had two this hour: rate-limited in-app too.)
    assert rules == ["DFIR-LNX-0001", "DFIR-WIN-0010", "DFIR-WIN-0011"]
    assert others == 0 and all("WS-042" not in json.dumps(n.payload) for n in mine)


def test_email_and_teams_channels(world: World) -> None:
    h = world.h
    h.resolver.table["smtp.example.test"] = [PUBLIC_IP]
    h.resolver.table["relay.internal"] = ["10.0.0.25"]
    mail = world.create(
        "email",
        config={
            "host": "smtp.example.test",
            "username": "bot",
            "sender": "dfir@example.test",
            "recipients": ["lead@example.test", "soc@example.test"],
            "events": ["report.signed"],
            "case_ids": [world.cid],
        },
        secret={"password": "smtp-password-do-not-leak"},
        enabled=True,
    )
    internal = world.create(
        "email",
        config={
            "host": "relay.internal",
            "port": 25,
            "sender": "dfir@example.test",
            "recipients": ["lead@example.test"],
            "events": ["report.signed"],
            "case_ids": [world.cid],
        },
        enabled=True,
    )
    teams = world.create(
        "teams",
        config={"events": ["report.signed"], "case_ids": [world.cid]},
        secret={"webhook_url": "https://hooks.example.test/teams/hook-token"},
        enabled=True,
    )
    rid = str(uuid.uuid4())
    world.emit(
        "report.signed",
        {"report_id": rid, "kind": "technical", "version": 2, "manifest_sha256": "a" * 64},
    )
    result = h.deliver(public_base_url="https://dfir.example")
    assert result.delivered == 2 and result.failed == 1
    sent = h.mails[-1]
    message = sent["message"]
    assert sent["ip"] == PUBLIC_IP and sent["login"] == ("bot", "smtp-password-do-not-leak")
    assert sent["to"] == ["lead@example.test", "soc@example.test"]
    assert message["Subject"] == f"[dfirbench] Report signed in case {world.case['case_number']}"
    body = message.get_content()
    assert "Kind: technical" in body and f"Report: {rid}" in body
    assert f"https://dfir.example/cases/{world.cid}/reports" in body
    assert world.deliveries(mail["id"])[0].status == "delivered"
    blocked = world.deliveries(internal["id"])[0]
    assert (blocked.status, blocked.last_error) == ("failed", "blocked:address_private")
    card = json.loads(h.transport.requests[-1].body)  # type: ignore[attr-defined]
    assert h.transport.requests[-1].target.path == "/teams/hook-token"  # type: ignore[attr-defined]
    content = card["attachments"][0]["content"]
    assert content["type"] == "AdaptiveCard" and "Report signed" in content["body"][0]["text"]
    assert world.deliveries(teams["id"])[0].status == "delivered"
    assert "smtp-password-do-not-leak" not in h.get("/integrations", world.admin).text


def test_integration_test_event_goes_to_one_integration_only(world: World) -> None:
    h = world.h
    first = world.webhook(["report.signed"])
    second = world.webhook(["report.signed"])
    ingest = world.create("webhook_in", case_id=world.cid, secret={"signing_secret": SIGNING})
    r = h.post(f"/integrations/{first['id']}/test", world.admin)
    assert r.status_code == 202 and r.json()["queued"] is True
    assert h.post(f"/integrations/{first['id']}/test", world.lead).status_code == 403
    assert h.post(f"/integrations/{ingest['id']}/test", world.admin).status_code == 422
    assert h.deliver().delivered == 1
    request = h.transport.requests[-1]
    assert request.headers["X-Event"] == "integration.test"  # type: ignore[attr-defined]
    assert json.loads(request.body)["data"]["integration"] == first["id"]  # type: ignore[attr-defined]
    assert len(world.deliveries(first["id"])) == 1 and world.deliveries(second["id"]) == []


def test_notification_rules_api(world: World) -> None:
    h = world.h
    assert h.get("/settings/notification-rules", world.lead).status_code == 403
    current = h.get("/settings/notification-rules", world.admin)
    assert current.status_code == 200 and current.json()["rules"]
    for bad in (
        [{"event": "user.deleted", "recipients": ["admins"]}],
        [{"event": "alert.created", "recipients": []}],
        [{"event": "alert.created", "recipients": ["everyone"]}],
        [{"event": "alert.created", "recipients": ["admins"], "min_severity": "urgent"}],
        [{"event": "alert.created", "recipients": ["admins"], "template": "{{7*7}}"}],
    ):
        assert (
            h.put("/settings/notification-rules", world.admin, json={"rules": bad}).status_code
            == 422
        )
    assert h.put("/settings/notification-rules", world.lead, json={"rules": []}).status_code == 403
    r = h.put("/settings/notification-rules", world.admin, json={"rules": current.json()["rules"]})
    assert r.status_code == 200 and r.json() == current.json()
    with h.sessions() as session:
        audited = session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "settings.notification_rules", AuditLog.user_id == world.admin.id
            )
        ).scalar_one()
    assert audited == 1


# ------------------------------------------------------------------ inbound ingest


class Source:
    def __init__(self, world: World, secret: str = SIGNING, **config: Any) -> None:
        self.world = world
        self.secret = secret
        self.row = world.create(
            "webhook_in",
            case_id=world.cid,
            config=config,
            secret={"signing_secret": secret},
            enabled=True,
        )
        self.id = self.row["id"]

    def send(
        self,
        payload: Any,
        *,
        ts: int | None = None,
        secret: str | None = None,
        ref: str | None = None,
        headers: dict[str, str] | None = None,
        client: Any = None,
    ) -> Any:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        stamp = int(time.time()) if ts is None else ts
        base = {
            "Content-Type": "application/json",
            "X-Timestamp": str(stamp),
            "X-Signature": webhooks.sign(secret or self.secret, stamp, body),
        }
        base.update(headers or {})
        return (client or self.world.h.client).post(
            f"/api/v1/ingest/webhook/{ref or self.id}", content=body, headers=base
        )


def alerts_of(world: World) -> list[Alert]:
    with world.h.sessions() as session:
        return list(
            session.execute(
                select(Alert)
                .where(Alert.case_id == uuid.UUID(world.cid), Alert.dedup_key.like("ext:%"))
                .order_by(Alert.title)
            ).scalars()
        )


def test_ingest_creates_alerts_in_the_configured_case(world: World) -> None:
    h = world.h
    other_case = h.create_case(world.lead, "Not the target")["id"]
    source = Source(world)
    hostile = '<script>alert(1)</script>"; DROP TABLE alerts; --'
    payload = {
        "alerts": [
            {
                "id": "siem-1",
                "title": hostile,
                "severity": "CRITICAL",
                "timestamp": "2026-09-30T10:00:00+02:00",
                "host": "WS-042",
                "user": "jdoe",
                "attack": ["T1486", "bogus"],
                "case_id": other_case,  # a payload cannot choose its case
                "tenant": "someone-else",
            },
            {"id": "siem-2", "title": "Beacon " + "A" * 5000, "severity": "low"},
            {"title": "no id"},
            "not an object",
            {"id": "siem-3", "title": "t", "timestamp": "2026-09-30 10:00"},
        ]
    }
    r = source.send(payload)
    assert r.status_code == 200, r.text
    assert r.json() == {
        "accepted": True,
        "duplicate": False,
        "items": 5,
        "created": 2,
        "updated": 0,
        "errors": 3,
        "error_reasons": {"missing_id": 1, "not_an_object": 1, "timestamp_without_timezone": 1},
    }
    rows = alerts_of(world)
    assert len(rows) == 2 and all(a.rule_id is None for a in rows)
    crit = next(a for a in rows if a.details["external_id"] == "siem-1")
    assert crit.title == hostile and crit.severity.value == "critical" and crit.host == "WS-042"
    assert crit.attack_tags == ["T1486"] and crit.first_seen == datetime(
        2026, 9, 30, 8, 0, tzinfo=UTC
    )
    assert crit.details["ts_original"] == "2026-09-30T10:00:00+02:00"
    assert crit.details["integration_id"] == source.id and crit.status.value == "new"
    assert crit.dedup_key == f"ext:{source.id}:{hashlib.sha256(b'siem-1').hexdigest()}"
    long = next(a for a in rows if a.details["external_id"] == "siem-2")
    assert (
        len(long.title) <= 500
        and long.severity.value == "low"
        and long.details["ts_source"] == "received"
    )
    with h.sessions() as session:
        elsewhere = session.execute(
            select(func.count()).select_from(Alert).where(Alert.case_id == uuid.UUID(other_case))
        ).scalar_one()
        history = (
            session.execute(
                select(AlertHistory).where(AlertHistory.alert_id.in_([a.id for a in rows]))
            )
            .scalars()
            .all()
        )
        events = (
            session.execute(
                select(OutboundEvent).where(
                    OutboundEvent.case_id == uuid.UUID(world.cid),
                    OutboundEvent.event_type == "alert.created",
                )
            )
            .scalars()
            .all()
        )
        delivery = session.execute(
            select(InboundDelivery).where(InboundDelivery.integration_id == uuid.UUID(source.id))
        ).scalar_one()
        audit = session.execute(
            select(AuditLog).where(
                AuditLog.action == "ingest.webhook", AuditLog.object_id == source.id
            )
        ).scalar_one()
    assert elsewhere == 0
    assert {(x.action, x.to_status.value if x.to_status else None) for x in history} == {
        ("created", "new")
    }
    assert {e.payload["alert_id"] for e in events} == {str(a.id) for a in rows}
    assert all(e.payload["source"] == "ingest" for e in events)
    assert (delivery.items, delivery.created, delivery.errors) == (5, 2, 3)
    assert delivery.case_id == uuid.UUID(world.cid) and len(delivery.nonce) == 64
    assert audit.detail["created"] == 2 and audit.user_id is None
    assert SIGNING not in json.dumps(audit.detail) and SIGNING not in r.text
    # The alerts show up through the normal API and can be triaged.
    listed = h.get(f"/cases/{world.cid}/alerts", world.viewer).json()["items"]
    assert {a["id"] for a in listed} >= {str(a.id) for a in rows}
    assert (
        h.patch(f"/alerts/{crit.id}", world.analyst, json={"status": "triaged"}).status_code == 200
    )
    log = h.get(f"/integrations/{source.id}/deliveries", world.admin).json()
    assert len(log["inbound"]) == 1 and log["inbound"][0]["created"] == 2


def test_ingest_is_idempotent_and_replay_protected(world: World) -> None:
    h = world.h
    source = Source(world, field_map={"id": "event.uid", "title": "event.name", "severity": "sev"})
    payload = [
        {"event": {"uid": "u-1", "name": "First"}, "sev": "high"},
        {"event": {"uid": "u-2", "name": "Second"}, "sev": "medium"},
    ]
    stamp = int(time.time())
    first = source.send(payload, ts=stamp)
    assert first.status_code == 200 and first.json()["created"] == 2
    # The identical delivery again (a replay or a sender retry): answered, nothing changes.
    replay = source.send(payload, ts=stamp)
    assert replay.status_code == 200
    assert replay.json() == {**first.json(), "duplicate": True}
    assert len(alerts_of(world)) == 2
    # The same alerts in a new delivery are updates, not new alerts or new events.
    payload[0]["sev"] = "critical"
    again = source.send(payload, ts=stamp + 1)
    assert again.status_code == 200
    assert (again.json()["created"], again.json()["updated"]) == (0, 2)
    rows = alerts_of(world)
    assert len(rows) == 2 and {a.title: a.severity.value for a in rows} == {
        "First": "critical",
        "Second": "medium",
    }
    with h.sessions() as session:
        deliveries = session.execute(
            select(func.count())
            .select_from(InboundDelivery)
            .where(InboundDelivery.integration_id == uuid.UUID(source.id))
        ).scalar_one()
        events = session.execute(
            select(func.count())
            .select_from(OutboundEvent)
            .where(
                OutboundEvent.case_id == uuid.UUID(world.cid),
                OutboundEvent.event_type == "alert.created",
            )
        ).scalar_one()
        history = session.execute(
            select(func.count())
            .select_from(AlertHistory)
            .where(AlertHistory.alert_id.in_([a.id for a in rows]))
        ).scalar_one()
    assert (deliveries, events, history) == (2, 2, 2)


def test_ingest_authentication_gives_one_answer(world: World) -> None:
    h = world.h
    source = Source(world)
    hook = world.webhook(["report.signed"])  # another type with the same secret value
    disabled = Source(world)
    assert (
        h.patch(f"/integrations/{disabled.id}", world.admin, json={"enabled": False}).status_code
        == 200
    )
    payload = {"alerts": [{"id": "a", "title": "t"}]}
    now = int(time.time())
    body = json.dumps(payload).encode()
    good_sig = webhooks.sign(SIGNING, now, body)
    attempts = [
        source.send(payload, secret="wrong-secret-" + "x" * 30),
        source.send(payload, ts=now - 301),
        source.send(payload, ts=now + 600),
        source.send(payload, ref=str(uuid.uuid4())),
        source.send(payload, ref="not-a-uuid"),
        source.send(payload, ref=hook["id"]),
        disabled.send(payload),
        source.send(payload, headers={"X-Signature": ""}),
        source.send(payload, headers={"X-Signature": "sha256=" + "0" * 64}),
        source.send(payload, headers={"X-Timestamp": "yesterday"}),
        source.send(payload, headers={"X-Timestamp": str(now + 1), "X-Signature": good_sig}),
        h.client.post(f"/api/v1/ingest/webhook/{source.id}", content=body),
        h.client.post(
            f"/api/v1/ingest/webhook/{source.id}",
            content=body + b" ",
            headers={"X-Timestamp": str(now), "X-Signature": good_sig},
        ),
        h.client.post(
            f"/api/v1/ingest/webhook/{source.id}", content=body, headers=world.admin.headers
        ),
    ]
    answers = set()
    for r in attempts:
        assert r.status_code == 401, r.text
        error = r.json()["error"]
        answers.add((error["code"], error["message"], json.dumps(error["details"], sort_keys=True)))
        assert "www-authenticate" not in {k.lower() for k in r.headers}
    assert answers == {("webhook_unauthenticated", "Webhook authentication failed.", "{}")}
    assert alerts_of(world) == []
    assert source.send(payload, ts=now).status_code == 200  # the real sender still works


def test_ingest_limits_and_bad_payloads(world: World) -> None:
    h = world.h
    source = Source(world)
    limit = h.settings.ingest_max_body_kb * 1024
    big = json.dumps({"alerts": [{"id": "x", "title": "y" * (limit + 10)}]}).encode()
    # Too large by Content-Length: refused before the body is read (also unauthenticated).
    r = source.send(big)
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    r = h.client.post(f"/api/v1/ingest/webhook/{source.id}", content=big)
    assert r.status_code == 413

    def chunks() -> Any:  # no Content-Length: the cap is enforced while streaming
        for _ in range(limit // 1024 + 8):
            yield b"x" * 1024

    r = h.client.post(f"/api/v1/ingest/webhook/{source.id}", content=chunks())
    assert r.status_code == 413
    assert source.send(b"{not json").status_code == 422
    assert source.send(b'"text"').json()["error"]["code"] == "invalid_payload"
    r = source.send([{"id": str(i), "title": "t"} for i in range(h.settings.ingest_max_items + 1)])
    assert r.status_code == 422 and r.json()["error"]["code"] == "too_many_items"
    r = source.send(b"[" * 5000)
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_json"
    assert alerts_of(world) == []
    # An item-level problem is counted, never a 500.
    r = source.send(
        {"alerts": [None, 5, [], {"id": {"x": 1}, "title": "t"}, {"id": "ok", "title": "fine"}]}
    )
    assert r.status_code == 200 and (r.json()["created"], r.json()["errors"]) == (1, 4)
    # A closed case refuses ingest.
    assert (
        h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"}).status_code == 200
    )
    r = source.send({"alerts": [{"id": "late", "title": "after close"}]})
    assert r.status_code == 409 and "closed" in r.json()["error"]["message"]
    assert len(alerts_of(world)) == 1


def test_ingest_rate_limits(
    app_engine: Engine, migrated_db_url: str, signer: CustodySigner
) -> None:
    h = other_harness(app_engine, migrated_db_url, signer, ingest_rate_limit_per_minute=2)
    with h.client:
        world = World(h)
        source = Source(world)
        codes = [
            source.send({"alerts": [{"id": f"r{i}", "title": "t"}]}).status_code for i in range(3)
        ]
        assert codes == [200, 200, 429]
        limited = source.send({"alerts": [{"id": "r9", "title": "t"}]})
        assert limited.status_code == 429 and int(limited.headers["Retry-After"]) >= 1
        # Unauthenticated floods are limited per client address (4x the source limit).
        flood = [
            h.client.post(f"/api/v1/ingest/webhook/{uuid.uuid4()}", content=b"{}").status_code
            for _ in range(8)
        ]
        assert flood.count(401) == 4 and flood.count(429) == 4
        assert len(alerts_of(world)) == 2


def test_inbound_log_is_append_only(world: World, db_engine: Engine) -> None:
    source = Source(world)
    assert source.send({"alerts": [{"id": "a", "title": "t"}]}).status_code == 200
    for sql, match, role in (
        ("UPDATE inbound_deliveries SET created = 0", "permission denied", True),
        ("DELETE FROM inbound_deliveries", "permission denied", True),
        ("TRUNCATE inbound_deliveries", "permission denied", True),
        ("UPDATE inbound_deliveries SET created = 0", "append-only", False),
        ("DELETE FROM inbound_deliveries", "append-only", False),
        ("DELETE FROM integrations", "permission denied", True),
        ("TRUNCATE integrations", "permission denied", True),
        ("DELETE FROM ioc_enrichments", "permission denied", True),
        ("DELETE FROM notifications", "permission denied", True),
        ("UPDATE notifications SET payload = '{}'::jsonb", "permission denied", True),
        ("UPDATE notifications SET user_id = user_id", "permission denied", True),
    ):
        with pytest.raises(DBAPIError, match=match), db_engine.begin() as conn:
            if role:
                conn.execute(text("SET LOCAL ROLE dfirbench_app"))
            conn.execute(text(sql))
    with db_engine.begin() as conn:  # the app may mark its notifications read, nothing else
        conn.execute(text("SET LOCAL ROLE dfirbench_app"))
        conn.execute(text("UPDATE notifications SET read_at = now() WHERE false"))
    # The replay key is a database constraint, not only a lookup.
    with (
        pytest.raises(DBAPIError, match="uq_inbound_deliveries_integration_id_nonce"),
        db_engine.begin() as conn,
    ):
        conn.execute(
            text(
                "INSERT INTO inbound_deliveries (integration_id, case_id, nonce, body_sha256) "
                "SELECT integration_id, case_id, nonce, body_sha256 FROM inbound_deliveries "
                "WHERE integration_id = :i"
            ),
            {"i": source.id},
        )
    # An enabled ingest source always has a case; a secret always comes with its key.
    for sql, match in (
        ("UPDATE integrations SET case_id = NULL WHERE id = :i", "ck_integrations_ingest_case"),
        (
            "UPDATE integrations SET secret_wrapped_key = NULL WHERE id = :i",
            "ck_integrations_secret",
        ),
        ("UPDATE integrations SET type = 'ftp' WHERE id = :i", "ck_integrations_type"),
    ):
        with pytest.raises(DBAPIError, match=match), db_engine.begin() as conn:
            conn.execute(text(sql), {"i": source.id})


# ------------------------------------------------------------------ enrichment


def iocs(world: World, items: list[tuple[str, str, str]]) -> dict[str, str]:
    ids = {}
    for kind, value, tlp in items:
        r = world.h.post(
            f"/cases/{world.cid}/iocs",
            world.analyst,
            json={"type": kind, "value": value, "tlp": tlp},
        )
        assert r.status_code == 201, r.text
        ids[value] = r.json()["id"]
    return ids


def enabled_providers(h: Harness, keep: set[str]) -> None:
    """Enrichment providers are global rows in the shared test database: switch off the ones
    other tests left enabled so each test controls exactly which provider is on."""
    with h.sessions() as session:
        for row in session.execute(
            select(Integration).where(
                Integration.type.in_(("virustotal", "misp")), Integration.enabled.is_(True)
            )
        ).scalars():
            if str(row.id) not in keep:
                row.enabled = False
        session.commit()


def test_enrichment_policy_tlp_and_cache(world: World) -> None:
    h = world.h
    enabled_providers(h, set())
    suffix = uuid.uuid4().hex[:8]
    sha = hashlib.sha256(suffix.encode()).hexdigest()
    ids = iocs(
        world,
        [
            ("ip", "198.51.100.77", "clear"),
            ("domain", f"c2-{suffix}.example", "green"),
            ("sha256", sha, "amber"),
            ("url", f"http://evil-{suffix}.example/x", "red"),
            ("email", f"phish-{suffix}@evil.example", "clear"),  # not an enrichable type
        ],
    )
    r = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={})
    assert r.status_code == 409 and r.json()["error"]["code"] == "no_enrichment_provider"
    vt = world.create("virustotal", secret={"api_key": "vt-key-do-not-leak-0001"}, enabled=True)
    enabled_providers(h, {vt["id"]})
    assert h.post(f"/cases/{world.cid}/iocs/enrich", world.viewer, json={}).status_code == 403
    r = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={})
    assert r.status_code == 200, r.text
    result = r.json()
    by_ioc = {(e["ioc_id"], e["provider"]): e for e in result["results"]}
    assert result["counts"] == {"fetched": 2, "skipped_tlp": 2}
    assert by_ioc[(ids["198.51.100.77"], "virustotal")]["status"] == "fetched"
    assert by_ioc[(ids["198.51.100.77"], "virustotal")]["verdict"] in (
        "malicious",
        "suspicious",
        "harmless",
    )
    assert by_ioc[(ids[sha], "virustotal")] | {"tlp": "amber"} == by_ioc[(ids[sha], "virustotal")]
    assert by_ioc[(ids[sha], "virustotal")]["status"] == "skipped_tlp"
    assert ids[f"phish-{suffix}@evil.example"] not in {e["ioc_id"] for e in result["results"]}
    fake = h.enrichers["virustotal"]
    # Only indicators left the platform, and only the ones their TLP allows.
    assert sorted(fake.lookups, key=lambda i: i.type) == [
        Indicator("domain", f"c2-{suffix}.example"),
        Indicator("ip", "198.51.100.77"),
    ]
    # Again: served from the cache, no provider call.
    again = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={}).json()
    assert again["counts"] == {"cached": 2, "skipped_tlp": 2} and len(fake.lookups) == 2
    one = h.post(
        f"/cases/{world.cid}/iocs/enrich",
        world.analyst,
        json={"ioc_ids": [ids["198.51.100.77"]], "refresh": True},
    ).json()
    assert one["counts"] == {"fetched": 1} and len(fake.lookups) == 3
    listed = h.get(f"/cases/{world.cid}/enrichments", world.viewer).json()["items"]
    assert {e["ioc_id"] for e in listed} == {ids["198.51.100.77"], ids[f"c2-{suffix}.example"]}
    # A provider error is a result, not a failure of the request.
    fake.fail_with = EnrichmentError("rate_limited", transient=True)
    failed = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={"refresh": True}).json()
    assert failed["counts"] == {"error": 2, "skipped_tlp": 2}
    assert {e.get("error") for e in failed["results"] if e["status"] == "error"} == {"rate_limited"}
    fake.fail_with = None
    with h.sessions() as session:
        audits = (
            session.execute(
                select(AuditLog).where(
                    AuditLog.action == "ioc.enriched", AuditLog.object_id == world.cid
                )
            )
            .scalars()
            .all()
        )
        cached = session.execute(
            select(IocEnrichment).where(IocEnrichment.value == "198.51.100.77")
        ).scalar_one()
    assert len(audits) == 4 and all("198.51.100.77" not in json.dumps(a.detail) for a in audits)
    assert audits[0].detail["fake"] is True and cached.expires_at > datetime.now(UTC) + timedelta(
        hours=23
    )
    assert "vt-key-do-not-leak" not in json.dumps([a.detail for a in audits])
    # Closed cases are read-only.
    assert (
        h.post(f"/cases/{world.cid}/close", world.lead, json={"reason": "done"}).status_code == 200
    )
    assert h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={}).status_code == 409
    assert h.get(f"/cases/{world.cid}/enrichments", world.viewer).status_code == 200


def test_misp_tlp_ceiling_and_sightings(world: World) -> None:
    h = world.h
    suffix = uuid.uuid4().hex[:8]
    ids = iocs(
        world,
        [
            ("domain", f"amber-{suffix}.example", "amber"),
            ("domain", f"red-{suffix}.example", "red"),
            ("domain", f"green-{suffix}.example", "green"),
        ],
    )
    amber, red, green = (ids[f"{c}-{suffix}.example"] for c in ("amber", "red", "green"))
    enabled_providers(h, set())
    r = h.post(f"/cases/{world.cid}/iocs/{green}/sighting", world.analyst)
    assert r.status_code == 409 and r.json()["error"]["code"] == "no_enrichment_provider"
    misp = world.create(
        "misp",
        config={"url": "https://misp.example.test", "max_tlp": "amber"},
        secret={"api_key": "misp-key-do-not-leak-01"},
        enabled=True,
    )
    vt = world.create("virustotal", secret={"api_key": "vt-key-do-not-leak-0002"}, enabled=True)
    enabled_providers(h, {misp["id"], vt["id"]})
    result = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={"refresh": True}).json()
    status = {(e["ioc_id"], e["provider"]): e["status"] for e in result["results"]}
    assert status[(amber, "misp")] == "fetched" and status[(amber, "virustotal")] == "skipped_tlp"
    assert status[(red, "misp")] == "skipped_tlp" and status[(red, "virustotal")] == "skipped_tlp"
    assert status[(green, "misp")] == "fetched" and status[(green, "virustotal")] == "fetched"
    only_misp = h.post(
        f"/cases/{world.cid}/iocs/enrich", world.analyst, json={"providers": ["misp"]}
    ).json()
    assert {e["provider"] for e in only_misp["results"]} == {"misp"}
    # Sightings follow the same ceiling.
    r = h.post(f"/cases/{world.cid}/iocs/{amber}/sighting", world.analyst)
    assert r.status_code == 200 and r.json() == {
        "ioc_id": amber,
        "provider": "misp",
        "exported": True,
    }
    r = h.post(f"/cases/{world.cid}/iocs/{red}/sighting", world.analyst)
    assert r.status_code == 409 and r.json()["error"]["code"] == "tlp_restricted"
    assert h.post(f"/cases/{world.cid}/iocs/{amber}/sighting", world.viewer).status_code == 403
    assert (
        h.post(f"/cases/{world.cid}/iocs/{uuid.uuid4()}/sighting", world.analyst).status_code == 404
    )
    assert h.enrichers["misp"].sightings == [Indicator("domain", f"amber-{suffix}.example")]
    # Lowering the ceiling to green holds the amber indicator back.
    assert (
        h.patch(
            f"/integrations/{misp['id']}",
            world.admin,
            json={"config": {"url": "https://misp.example.test", "max_tlp": "green"}},
        ).status_code
        == 200
    )
    assert h.post(f"/cases/{world.cid}/iocs/{amber}/sighting", world.analyst).status_code == 409
    with h.sessions() as session:
        audit = session.execute(
            select(AuditLog).where(
                AuditLog.action == "ioc.sighting_exported", AuditLog.object_id == amber
            )
        ).scalar_one()
    assert audit.detail["provider"] == "misp" and f"amber-{suffix}" not in json.dumps(audit.detail)


def test_enrichment_is_off_by_default(
    app_engine: Engine, migrated_db_url: str, signer: CustodySigner
) -> None:
    defaults = Settings(_env_file=None)  # type: ignore[call-arg]
    assert defaults.enable_enrichment is False and defaults.enrichment_fake is False
    assert defaults.outbound_allow_http is False and defaults.outbound_allow_hosts == []
    h = other_harness(app_engine, migrated_db_url, signer, enable_enrichment=False)
    with h.client:
        world = World(h)
        ids = iocs(world, [("ip", "198.51.100.99", "clear")])
        world.create("virustotal", secret={"api_key": "vt-key-do-not-leak-0003"}, enabled=True)
        r = h.post(f"/cases/{world.cid}/iocs/enrich", world.analyst, json={})
        assert r.status_code == 409 and r.json()["error"]["code"] == "enrichment_disabled"
        sighting = h.post(f"/cases/{world.cid}/iocs/{ids['198.51.100.99']}/sighting", world.analyst)
        assert sighting.status_code == 409
        assert h.enrichers == {}  # no provider was even built
