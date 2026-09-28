"""Every error response uses the guide 15.3 envelope and carries the request id."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError, ConflictError, NotFoundError, code_for_status, error_body


class Payload(BaseModel):
    n: int


@pytest.fixture
def app_with_routes(app: FastAPI) -> FastAPI:
    @app.get("/test/app-error")
    def raise_app_error() -> None:
        raise AppError(
            "evidence_hash_mismatch",
            "Computed SHA-256 does not match the supplied hash.",
            status_code=409,
            details={"expected": "aa", "actual": "bb"},
        )

    @app.get("/test/not-found")
    def raise_not_found() -> None:
        raise NotFoundError("Case not found.", case_id="x")

    @app.get("/test/conflict")
    def raise_conflict() -> None:
        raise ConflictError("Duplicate idempotency key.", key="k")

    @app.get("/test/boom")
    def boom() -> None:
        raise RuntimeError("secret internal detail: postgresql://user:pw@db")

    @app.post("/test/validate")
    def validate(payload: Payload) -> dict[str, int]:
        return {"n": payload.n}

    return app


def assert_envelope(body: dict[str, Any], code: str) -> dict[str, Any]:
    assert set(body) == {"error"}
    err = body["error"]
    assert set(err) == {"code", "message", "details", "request_id"}
    assert err["code"] == code
    assert isinstance(err["message"], str) and err["message"]
    assert isinstance(err["details"], dict)
    assert isinstance(err["request_id"], str) and err["request_id"]
    return err


def test_app_error(app_with_routes: FastAPI, client: TestClient) -> None:
    r = client.get("/test/app-error")
    assert r.status_code == 409
    err = assert_envelope(r.json(), "evidence_hash_mismatch")
    assert err["details"] == {"expected": "aa", "actual": "bb"}
    assert err["request_id"] == r.headers["x-request-id"]


def test_not_found_and_conflict_subclasses(app_with_routes: FastAPI, client: TestClient) -> None:
    r = client.get("/test/not-found")
    assert r.status_code == 404
    assert assert_envelope(r.json(), "not_found")["details"] == {"case_id": "x"}
    r = client.get("/test/conflict")
    assert r.status_code == 409
    assert assert_envelope(r.json(), "conflict")["details"] == {"key": "k"}


def test_unknown_route_404(client: TestClient) -> None:
    r = client.get("/api/v1/does-not-exist")
    assert r.status_code == 404
    assert_envelope(r.json(), "not_found")


def test_method_not_allowed(client: TestClient) -> None:
    r = client.post("/api/v1/health")
    assert r.status_code == 405
    assert_envelope(r.json(), "method_not_allowed")


def test_validation_error(app_with_routes: FastAPI, client: TestClient) -> None:
    r = client.post("/test/validate", json={"n": "not-a-number"})
    assert r.status_code == 422
    err = assert_envelope(r.json(), "validation_error")
    assert err["details"]["errors"][0]["loc"] == ["body", "n"]


def test_unhandled_exception_does_not_leak(app_with_routes: FastAPI, client: TestClient) -> None:
    r = client.get("/test/boom", headers={"X-Request-ID": "trace-abcdef12"})
    assert r.status_code == 500
    err = assert_envelope(r.json(), "internal_error")
    assert "secret" not in r.text and "postgresql" not in r.text
    # The request id survives even though Starlette runs this handler outside our middleware.
    assert err["request_id"] == "trace-abcdef12"
    assert r.headers["x-request-id"] == "trace-abcdef12"


def test_error_body_shape() -> None:
    body = error_body("x", "msg", None, request_id="rid")
    assert body == {"error": {"code": "x", "message": "msg", "details": {}, "request_id": "rid"}}


@pytest.mark.parametrize(
    ("status", "code"),
    [(401, "unauthenticated"), (403, "forbidden"), (429, "rate_limited"), (418, "http_error")],
)
def test_code_for_status(status: int, code: str) -> None:
    assert code_for_status(status) == code
