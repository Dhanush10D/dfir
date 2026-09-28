from __future__ import annotations

import io
import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.core.logging import setup_logging
from app.core.request_context import new_request_id, sanitize_request_id


def test_generates_request_id_when_missing(client: TestClient) -> None:
    r1 = client.get("/api/v1/health")
    r2 = client.get("/api/v1/health")
    assert len(r1.headers["x-request-id"]) == 32
    assert r1.headers["x-request-id"] != r2.headers["x-request-id"]


def test_echoes_safe_inbound_request_id(client: TestClient) -> None:
    r = client.get("/api/v1/health", headers={"X-Request-ID": "abc-123_def.456"})
    assert r.headers["x-request-id"] == "abc-123_def.456"


@pytest.mark.parametrize(
    "bad",
    ["short", "has space in it", "inject\\nfake log line", "x" * 200, "<script>alert(1)</script>"],
)
def test_replaces_unsafe_inbound_request_id(client: TestClient, bad: str) -> None:
    r = client.get("/api/v1/health", headers={"X-Request-ID": bad})
    assert r.headers["x-request-id"] != bad
    assert len(r.headers["x-request-id"]) == 32


def test_sanitize_helpers() -> None:
    assert sanitize_request_id(None) != sanitize_request_id(None)
    assert sanitize_request_id("good-id-0001") == "good-id-0001"
    assert len(new_request_id()) == 32


def test_access_log_is_json_with_request_id(client: TestClient) -> None:
    buf = io.StringIO()
    setup_logging("INFO", json=True, stream=buf)
    try:
        client.get("/api/v1/health", headers={"X-Request-ID": "logcheck-0001"})
    finally:
        setup_logging("INFO", json=True)
    lines = [ln for ln in buf.getvalue().splitlines() if ln.startswith("{")]
    records = [json.loads(ln) for ln in lines]
    access = [r for r in records if r.get("event") == "http_request"]
    assert access, f"no access log line in {lines!r}"
    rec = access[-1]
    assert rec["request_id"] == "logcheck-0001"
    assert rec["path"] == "/api/v1/health"
    assert rec["status"] == 200
    assert rec["level"] == "info"
    assert rec["timestamp"].endswith("Z")
    assert logging.getLogger().handlers  # root logger configured by setup_logging
