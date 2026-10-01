"""Phase 10 security regression tests (guide 20.2, 22.1 "Security").

* every route needs authentication unless it is on a short public list;
* every case-scoped route refuses a user who is not a member of the case;
* per-IP rate limits on authentication;
* admin changes lock their rows: no deadlock, the last active admin survives a race.
"""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.core.exceptions import AppError
from app.core.permissions import Principal
from app.core.ratelimit import RateLimiterUnavailableError
from app.db.models import UserRole
from app.deps import get_app_settings, get_auth_limiter
from app.services.audit import RequestMeta
from app.services.iam import IAMService
from tests.integration.harness import API, TEST_PASSWORD, Harness, UserCtx

pytestmark = pytest.mark.integration

# Routes that answer without a user: probes, API docs and the login steps; refresh and logout
# authenticate with the refresh token in their body (422 for an empty body, 401 for a bad token).
# The HMAC-signed SIEM ingest endpoint is not listed: it answers 401 without a valid signature.
PUBLIC = {
    ("POST", "/auth/refresh"),
    ("POST", "/auth/logout"),
    ("GET", "/health"),
    ("GET", "/ready"),
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("POST", "/auth/login"),
    ("POST", "/auth/mfa/verify"),
}
PARAM = re.compile(r"\{([a-z_]+)(?::[a-z]+)?\}")


def _routes(h: Harness) -> list[tuple[str, str]]:
    """(method, path) of every API operation, from the OpenAPI schema (no route is hidden)."""
    found: list[tuple[str, str]] = []
    for path, operations in h.app.openapi()["paths"].items():
        if not path.startswith(API):
            continue
        for method in operations:
            if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                found.append((method.upper(), path[len(API) :]))
    return sorted(found)


def _fill(path: str, values: dict[str, str]) -> str:
    return PARAM.sub(lambda m: values.get(m.group(1), str(uuid.uuid4())), path)


def _call(h: Harness, method: str, path: str, user: UserCtx | None) -> Any:
    headers = user.headers if user else {}
    kwargs: dict[str, Any] = {"headers": headers}
    if method in ("POST", "PUT", "PATCH"):
        kwargs["json"] = {}
    return h.client.request(method, API + path, **kwargs)


def test_every_route_needs_authentication(h: Harness) -> None:
    routes = _routes(h)
    assert len(routes) > 100  # the matrix really enumerates the API
    unexpected: list[str] = []
    for method, path in routes:
        if (method, path) in PUBLIC:
            continue
        r = _call(h, method, _fill(path, {}), None)
        if r.status_code != 401:
            unexpected.append(f"{method} {path} -> {r.status_code}")
    assert unexpected == []


def test_every_route_rejects_a_forged_token(h: Harness) -> None:
    forged = UserCtx(
        uuid.uuid4(), "x@dfir.test", "", UserRole.admin, {"Authorization": "Bearer abc.def.ghi"}
    )
    for method, path in _routes(h):
        if (method, path) in PUBLIC or path.startswith("/auth/"):
            continue
        r = _call(h, method, _fill(path, {}), forged)
        assert r.status_code == 401, f"{method} {path} -> {r.status_code}"


@pytest.fixture
def victim(h: Harness) -> dict[str, str]:
    """A case with evidence and a job that the outsider must never reach."""
    lead = h.make_user(UserRole.lead)
    case = h.create_case(lead, "Isolation target")
    ev = h.stored_evidence(lead, case["id"], b"Jan  1 00:00:01 host sshd[1]: test\n")
    r = h.post(f"/evidence/{ev['id']}/process", lead, json={"parsers": ["linux_auth"]})
    assert r.status_code == 202, r.text
    return {"case_id": case["id"], "evidence_id": ev["id"], "job_id": r.json()["jobs"][0]["id"]}


def test_case_scoped_routes_refuse_outsiders(h: Harness, victim: dict[str, str]) -> None:
    outsider = h.make_user(UserRole.analyst)
    scoped = [
        (m, p)
        for m, p in _routes(h)
        if any(f"{{{k}}}" in p for k in ("case_id", "evidence_id", "job_id"))
    ]
    assert len(scoped) > 40
    leaks: list[str] = []
    for method, path in scoped:
        r = _call(h, method, _fill(path, victim), outsider)
        if r.status_code < 400 or r.status_code >= 500:
            leaks.append(f"{method} {path} -> {r.status_code}")
    assert leaks == []
    with h.engine.connect() as conn:  # nothing of the victim case was changed or removed
        status = conn.execute(
            text("SELECT status FROM cases WHERE id = :c"), {"c": victim["case_id"]}
        ).scalar_one()
        assert str(status).endswith("open")


# ------------------------------------------------------------------ per-IP auth rate limits


def _with_limits(h: Harness, **limits: int) -> None:
    settings = h.settings.model_copy(update=limits)
    h.app.dependency_overrides[get_app_settings] = lambda: settings


def test_login_attempts_are_limited_per_ip(h: Harness, db_engine: Engine) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    _with_limits(h, auth_rate_limit_per_minute=3, auth_refresh_rate_limit_per_minute=50)
    codes = [
        h.client.post(
            f"{API}/auth/login", json={"email": user.email, "password": "Wrong-Password-1"}
        ).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    r = h.client.post(f"{API}/auth/login", json={"email": user.email, "password": TEST_PASSWORD})
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert r.json()["error"]["code"] == "rate_limited"
    # MFA attempts share the login budget; refresh has its own.
    r = h.client.post(f"{API}/auth/mfa/verify", json={"mfa_challenge": "x" * 40, "code": "123456"})
    assert r.status_code == 429
    r = h.client.post(f"{API}/auth/refresh", json={"refresh_token": "x" * 40})
    assert r.status_code == 401
    # Another address is not affected (the proxy-trusted client address is the key).
    other = h.client.__class__(h.app, raise_server_exceptions=False, client=("203.0.113.9", 1))
    r = other.post(f"{API}/auth/login", json={"email": user.email, "password": TEST_PASSWORD})
    assert r.status_code == 200
    with db_engine.connect() as conn:
        n = conn.execute(
            text(
                "SELECT count(*) FROM audit_log WHERE action = 'auth.rate_limited' "
                "AND ip = '198.51.100.7'"
            )
        ).scalar_one()
    assert n >= 3


def test_refresh_is_limited_separately(h: Harness) -> None:
    _with_limits(h, auth_rate_limit_per_minute=50, auth_refresh_rate_limit_per_minute=2)
    codes = [
        h.client.post(f"{API}/auth/refresh", json={"refresh_token": "y" * 40}).status_code
        for _ in range(3)
    ]
    assert codes == [401, 401, 429]


def test_auth_fails_closed_without_the_limiter(h: Harness) -> None:
    class Down:
        def hit(self, key: str, limit: int, window_s: int = 60) -> None:
            raise RateLimiterUnavailableError("down")

    h.app.dependency_overrides[get_auth_limiter] = lambda: Down()
    r = h.client.post(f"{API}/auth/login", json={"email": "a@b.test", "password": "x" * 12})
    assert r.status_code == 503 and r.json()["error"]["code"] == "auth_unavailable"


# ------------------------------------------------------------------ admin changes under races


def _parallel(n: int, fn: Callable[[int], Any]) -> list[Any]:
    barrier = threading.Barrier(n)

    def run(i: int) -> Any:
        barrier.wait()
        try:
            return fn(i)
        except AppError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(run, range(n)))


def test_two_admins_demoting_each_other_keep_one_admin(h: Harness, db_engine: Engine) -> None:
    meta = RequestMeta(ip="198.51.100.9")
    for _ in range(4):
        with db_engine.begin() as conn:  # isolate: only the two admins below are active
            conn.execute(text("UPDATE users SET is_active = false WHERE role = 'admin'"))
        admins = [h.make_user(UserRole.admin, login=False) for _ in range(2)]

        def demote(i: int, admins: list[UserCtx] = admins) -> Any:
            actor, target = admins[i], admins[1 - i]
            principal = Principal(actor.id, actor.email, "Admin", UserRole.admin)
            with h.sessions() as session:
                IAMService(session, h.settings).update_user(
                    principal,
                    target.id,
                    meta=meta,
                    role=UserRole.analyst,
                    admin_password=TEST_PASSWORD,
                )
                return "ok"

        results = _parallel(2, demote)
        assert sorted(results) == ["last_admin", "ok"], results
        with db_engine.connect() as conn:
            active = conn.execute(
                text("SELECT count(*) FROM users WHERE role = 'admin' AND is_active")
            ).scalar_one()
        assert active == 1


def test_admins_editing_each_other_do_not_deadlock(h: Harness) -> None:
    meta = RequestMeta(ip="198.51.100.9")
    admins = [h.make_user(UserRole.admin, login=False) for _ in range(2)]

    def rename(i: int) -> Any:
        actor, target = admins[i], admins[1 - i]
        principal = Principal(actor.id, actor.email, "Admin", UserRole.admin)
        with h.sessions() as session:
            user = IAMService(session, h.settings).update_user(
                principal, target.id, meta=meta, display_name=f"Renamed {i}", is_active=True
            )
            return user.display_name

    for _ in range(5):
        assert sorted(_parallel(2, rename)) == ["Renamed 0", "Renamed 1"]
