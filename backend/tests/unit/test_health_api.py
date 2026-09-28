from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import __version__
from app.deps import get_readiness_checks
from tests.conftest import failing_check, ok_check


def test_health_ok(client: TestClient) -> None:
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "dfirbench-api"
    assert body["version"] == __version__
    assert body["env"] == "test"
    ts = datetime.fromisoformat(body["time"].replace("Z", "+00:00"))
    assert ts.utcoffset() is not None and ts.utcoffset().total_seconds() == 0  # type: ignore[union-attr]
    assert r.headers["x-request-id"]


def test_ready_ok(client: TestClient) -> None:
    r = client.get("/api/v1/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert set(body["checks"]) == {"database", "redis", "storage"}
    assert all(c["ok"] for c in body["checks"].values())


def test_ready_503_uses_error_envelope(app: FastAPI, client: TestClient) -> None:
    app.dependency_overrides[get_readiness_checks] = lambda: [
        ok_check("database"),
        failing_check("redis", "ConnectionError"),
        ok_check("storage"),
    ]
    r = client.get("/api/v1/ready", headers={"X-Request-ID": "probe-12345678"})
    assert r.status_code == 503
    err = r.json()["error"]
    assert err["code"] == "not_ready"
    assert "redis" in err["message"]
    assert err["details"]["checks"]["redis"] == {
        "ok": False,
        "latency_ms": 0.1,
        "error": "ConnectionError",
    }
    assert err["details"]["checks"]["database"]["ok"] is True
    assert err["request_id"] == "probe-12345678"
    assert r.headers["x-request-id"] == "probe-12345678"


def test_openapi_is_served_under_api_prefix(client: TestClient) -> None:
    r = client.get("/api/v1/openapi.json")
    assert r.status_code == 200
    paths = r.json()["paths"]
    assert "/api/v1/health" in paths
    assert "/api/v1/ready" in paths
