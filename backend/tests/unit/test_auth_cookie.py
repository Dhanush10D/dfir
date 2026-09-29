"""Refresh-cookie options (PHASE-4 "cookie options"): no Docker, no network."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import Response
from starlette.requests import Request

from app.api.v1.auth import (
    COOKIE_PATH,
    _refresh_token,
    clear_refresh_cookie,
    set_refresh_cookie,
    wants_cookie,
)
from app.config import Settings
from app.services.iam import TokenPair


def _settings(**kwargs: object) -> Settings:
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


def _request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw})


def _pair() -> TokenPair:
    now = datetime.now(UTC)
    return TokenPair("access", now + timedelta(minutes=5), "r" * 40, now + timedelta(days=1))


def _attrs(header: str) -> dict[str, str]:
    parts = [p.strip() for p in header.split(";")]
    out = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        out[key.lower()] = value
    return out


def test_refresh_cookie_is_httponly_secure_strict_and_scoped() -> None:
    response = Response()
    set_refresh_cookie(response, _settings(), _pair())
    header = response.headers["set-cookie"]
    assert header.startswith("dfir_refresh=" + "r" * 40 + ";")
    attrs = _attrs(header)
    assert "httponly" in attrs and "secure" in attrs
    assert attrs["samesite"].lower() == "strict"
    assert attrs["path"] == COOKIE_PATH == "/api/v1/auth"
    assert 86000 <= int(attrs["max-age"]) <= 86400
    assert "domain" not in attrs


def test_clear_cookie_expires_it_with_the_same_scope() -> None:
    response = Response()
    clear_refresh_cookie(response, _settings())
    attrs = _attrs(response.headers["set-cookie"])
    assert attrs["max-age"] == "0" and attrs["path"] == COOKIE_PATH
    assert "httponly" in attrs and attrs["samesite"].lower() == "strict"


def test_cookie_is_read_only_with_the_delivery_header() -> None:
    settings = _settings()
    token = "t" * 40
    cookie = {"cookie": f"dfir_refresh={token}"}
    assert not wants_cookie(_request(cookie))
    assert _refresh_token(None, _request(cookie), settings) is None  # CSRF: header required
    with_header = _request({**cookie, "X-Token-Delivery": " Cookie "})
    assert wants_cookie(with_header)
    assert _refresh_token(None, with_header, settings) == token
    too_short = _request({"cookie": "dfir_refresh=abc", "X-Token-Delivery": "cookie"})
    assert _refresh_token(None, too_short, settings) is None
