from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.services.audit import AuditRecord, DbAuditSink, clean_ip
from tests.conftest import FakeAuditSink


def _routes(app: FastAPI) -> uuid.UUID:
    user_id = uuid.uuid4()

    @app.get("/api/v1/cases/{case_id}/thing")
    def thing(case_id: uuid.UUID, request: Request) -> dict[str, str]:
        request.state.user_id = user_id  # what the auth dependency does
        request.state.auth_method = "jwt"
        return {"ok": "yes"}

    @app.delete("/api/v1/evidence/{evidence_id}")
    def boom(evidence_id: uuid.UUID) -> None:
        raise RuntimeError("kaboom")

    return user_id


def test_records_authenticated_request(app: FastAPI, audit_sink: FakeAuditSink) -> None:
    user_id = _routes(app)
    case_id = uuid.uuid4()
    with TestClient(app, client=("203.0.113.5", 1234)) as client:
        r = client.get(
            f"/api/v1/cases/{case_id}/thing?secret=do-not-log",
            headers={"X-Request-ID": "req-12345678"},
        )
    assert r.status_code == 200
    [record] = audit_sink.records
    assert record.user_id == user_id
    assert record.ip == "203.0.113.5"
    assert (record.method, record.path, record.status) == (
        "GET",
        f"/api/v1/cases/{case_id}/thing",
        200,
    )
    assert record.action == "read"
    assert (record.object_type, record.object_id) == ("case", str(case_id))
    assert record.detail["request_id"] == "req-12345678"
    assert record.detail["auth"] == "jwt"
    assert "secret" not in repr(record)  # query strings are never recorded


def test_records_failures_and_anonymous_requests(app: FastAPI, audit_sink: FakeAuditSink) -> None:
    _routes(app)
    evidence_id = uuid.uuid4()
    with TestClient(app, raise_server_exceptions=False) as client:
        assert client.delete(f"/api/v1/evidence/{evidence_id}").status_code == 500
        assert client.get("/api/v1/nope").status_code == 404
    first, second = audit_sink.records
    assert (first.action, first.status, first.user_id) == ("delete", 500, None)
    assert (first.object_type, first.object_id) == ("evidence", str(evidence_id))
    assert (second.status, second.object_type) == (404, None)


def test_skips_probes_docs_and_non_api(app: FastAPI, audit_sink: FakeAuditSink) -> None:
    with TestClient(app) as client:
        client.get("/api/v1/health")
        client.get("/api/v1/ready")
        client.get("/api/v1/openapi.json")
        client.get("/not-api")
        client.options("/api/v1/cases", headers={"Origin": "http://localhost:5173"})
    assert audit_sink.records == []


def test_sink_failure_never_breaks_the_response(app: FastAPI) -> None:
    class Broken:
        def write(self, record: AuditRecord) -> None:
            raise RuntimeError("db down")

    _routes(app)
    app.state.audit_sink = Broken()
    with TestClient(app) as client:
        assert client.get(f"/api/v1/cases/{uuid.uuid4()}/thing").status_code == 200


def test_disabled_sink(app: FastAPI) -> None:
    _routes(app)
    app.state.audit_sink = None
    with TestClient(app) as client:
        assert client.get(f"/api/v1/cases/{uuid.uuid4()}/thing").status_code == 200


def test_db_sink_swallows_errors() -> None:
    def factory() -> object:
        raise RuntimeError("no db")

    DbAuditSink(factory).write(AuditRecord(action="read"))  # type: ignore[arg-type]


def test_clean_ip() -> None:
    assert clean_ip("198.51.100.1") == "198.51.100.1"
    assert clean_ip("2001:db8::1") == "2001:db8::1"
    assert clean_ip("testclient") is None
    assert clean_ip(None) is None
    row = AuditRecord(action="x", ip="testclient").to_row()
    assert row.ip is None
