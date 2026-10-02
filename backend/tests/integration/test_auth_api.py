"""Authentication flows over the API: passwords, lockout, MFA, refresh rotation, API keys."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, text

from app.core.security import JwtCodec, totp_code
from app.db.models import UserRole
from tests.integration.harness import TEST_PASSWORD, Harness, UserCtx

pytestmark = pytest.mark.integration


def _login(h: Harness, email: str, password: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    r = h.client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return r.status_code, r.json()


def _enable_mfa(h: Harness, user: UserCtx) -> tuple[str, list[str]]:
    secret, codes, _ = _enable_mfa_with_code(h, user)
    return secret, codes


def _enable_mfa_with_code(h: Harness, user: UserCtx) -> tuple[str, list[str], str]:
    r = h.post("/me/mfa/enroll", user)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    confirm_code = totp_code(secret)
    r = h.post("/me/mfa/confirm", user, json={"code": confirm_code})
    assert r.status_code == 200, r.text
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10
    return secret, codes, confirm_code


def test_login_returns_tokens_and_me(h: Harness, db_engine: Engine) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    status, body = _login(h, user.email.upper(), TEST_PASSWORD)  # citext: case-insensitive
    assert status == 200, body
    assert body["mfa_required"] is False
    tokens = body["tokens"]
    assert tokens["token_type"] == "bearer"
    me = h.client.get(
        "/api/v1/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    ).json()
    assert me["user"]["email"] == user.email
    assert me["user"]["role"] == "analyst"
    assert "evidence:add" in me["permissions"] and "users:manage" not in me["permissions"]
    with db_engine.connect() as conn:
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE id = :u"), {"u": user.id}
        ).scalar_one()
        assert stored.startswith("$argon2id$")
        tokens_stored = conn.execute(
            text("SELECT token_hash FROM refresh_tokens WHERE user_id = :u"), {"u": user.id}
        ).scalars()
        assert tokens["refresh_token"] not in set(tokens_stored)  # only hashes are stored


def test_wrong_password_and_unknown_user_look_the_same(h: Harness) -> None:
    user = h.make_user(UserRole.viewer, login=False)
    s1, b1 = _login(h, user.email, "Wrong-Password-123")
    s2, b2 = _login(h, f"nobody-{uuid.uuid4().hex}@dfir.test", "Wrong-Password-123")
    assert s1 == s2 == 401
    assert b1["error"]["code"] == b2["error"]["code"] == "invalid_credentials"
    assert b1["error"]["message"] == b2["error"]["message"]


def test_lockout_after_repeated_failures_then_expiry(h: Harness, db_engine: Engine) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    threshold = h.settings.login_lockout_threshold
    for _ in range(threshold):
        status, body = _login(h, user.email, "Wrong-Password-123")
        assert status == 401
    # Locked: even the correct password is refused, with Retry-After.
    r = h.client.post("/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD})
    assert r.status_code == 429
    assert r.json()["error"]["code"] == "account_locked"
    assert 1 <= int(r.headers["retry-after"]) <= h.settings.login_lockout_base_s + 1
    with db_engine.connect() as conn:
        failed, locked = conn.execute(
            text("SELECT failed_logins, locked_until FROM users WHERE id = :u"), {"u": user.id}
        ).one()
    assert failed == threshold and locked > datetime.now(UTC)

    # Another failure after the lock expires doubles the lock (exponential backoff).
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET locked_until = now() - interval '1 second' WHERE id = :u"),
            {"u": user.id},
        )
    assert _login(h, user.email, "Wrong-Password-123")[0] == 401
    with db_engine.connect() as conn:
        locked2 = conn.execute(
            text("SELECT locked_until - now() FROM users WHERE id = :u"), {"u": user.id}
        ).scalar_one()
    assert locked2 > timedelta(seconds=h.settings.login_lockout_base_s * 1.5)

    # Once the lock expires the correct password works and the counter resets.
    with db_engine.begin() as conn:
        conn.execute(
            text("UPDATE users SET locked_until = now() - interval '1 second' WHERE id = :u"),
            {"u": user.id},
        )
    status, body = _login(h, user.email, TEST_PASSWORD)
    assert status == 200, body
    with db_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT failed_logins FROM users WHERE id = :u"), {"u": user.id}
            ).scalar_one()
            == 0
        )
        actions = set(
            conn.execute(
                text("SELECT action FROM audit_log WHERE user_id = :u"), {"u": user.id}
            ).scalars()
        )
    assert {"auth.login_failed", "auth.login_locked", "auth.login"} <= actions


def test_admin_can_unlock(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    user = h.make_user(UserRole.analyst, login=False)
    for _ in range(h.settings.login_lockout_threshold):
        _login(h, user.email, "Wrong-Password-123")
    assert _login(h, user.email, TEST_PASSWORD)[0] == 429
    r = h.patch(f"/users/{user.id}", admin, json={"unlock": True})
    assert r.status_code == 200 and r.json()["failed_logins"] == 0
    assert _login(h, user.email, TEST_PASSWORD)[0] == 200


def test_inactive_user_cannot_login_or_use_tokens(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    user = h.make_user(UserRole.analyst)
    assert h.get("/me", user).status_code == 200
    r = h.delete(f"/users/{user.id}", admin, json={"admin_password": TEST_PASSWORD})
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert h.get("/me", user).status_code == 401
    assert _login(h, user.email, TEST_PASSWORD)[0] == 401


def test_mfa_login_flow_with_replay_protection(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    secret, _, confirm_code = _enable_mfa_with_code(h, user)
    status, body = _login(h, user.email, TEST_PASSWORD)
    assert status == 200 and body["mfa_required"] is True and body["tokens"] is None
    challenge = body["mfa_challenge"]

    # The code used to confirm enrollment was consumed; its time step is now a replay.
    r = h.client.post(
        "/api/v1/auth/mfa/verify", json={"mfa_challenge": challenge, "code": confirm_code}
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "mfa_invalid"

    next_step = datetime.now(UTC) + timedelta(seconds=30)
    r = h.client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_challenge": challenge, "code": totp_code(secret, next_step)},
    )
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    # Replaying the same code again is refused.
    r = h.client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_challenge": challenge, "code": totp_code(secret, next_step)},
    )
    assert r.status_code == 401


def test_mfa_challenge_cannot_be_used_as_access_token(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    _enable_mfa(h, user)
    _, body = _login(h, user.email, TEST_PASSWORD)
    r = h.client.get("/api/v1/me", headers={"Authorization": f"Bearer {body['mfa_challenge']}"})
    assert r.status_code == 401


def test_recovery_code_is_single_use(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    _, codes = _enable_mfa(h, user)
    _, body = _login(h, user.email, TEST_PASSWORD)
    payload = {"mfa_challenge": body["mfa_challenge"], "recovery_code": codes[0].upper()}
    assert h.client.post("/api/v1/auth/mfa/verify", json=payload).status_code == 200
    _, body = _login(h, user.email, TEST_PASSWORD)
    payload["mfa_challenge"] = body["mfa_challenge"]
    assert h.client.post("/api/v1/auth/mfa/verify", json=payload).status_code == 401


def test_bad_mfa_codes_count_towards_lockout(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    _enable_mfa(h, user)
    _, body = _login(h, user.email, TEST_PASSWORD)
    for _ in range(h.settings.login_lockout_threshold):
        r = h.client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_challenge": body["mfa_challenge"], "code": "000000"},
        )
        assert r.status_code == 401
    r = h.client.post(
        "/api/v1/auth/mfa/verify", json={"mfa_challenge": body["mfa_challenge"], "code": "000000"}
    )
    assert r.status_code == 429


def test_mfa_disable_and_admin_reset(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    user = h.make_user(UserRole.analyst)
    secret, _ = _enable_mfa(h, user)
    later = datetime.now(UTC) + timedelta(seconds=30)
    r = h.post(
        "/me/mfa/disable", user, json={"password": "wrong-password", "code": totp_code(secret)}
    )
    assert r.status_code == 403
    r = h.post(
        "/me/mfa/disable", user, json={"password": TEST_PASSWORD, "code": totp_code(secret, later)}
    )
    assert r.status_code == 204
    _enable_mfa(h, user)
    # Admin reset requires re-authentication.
    assert h.patch(f"/users/{user.id}", admin, json={"reset_mfa": True}).status_code == 403
    r = h.patch(
        f"/users/{user.id}", admin, json={"reset_mfa": True, "admin_password": TEST_PASSWORD}
    )
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    status, body = _login(h, user.email, TEST_PASSWORD)
    assert status == 200 and body["mfa_required"] is False


def test_refresh_rotation_and_reuse_detection(h: Harness) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    _, body = _login(h, user.email, TEST_PASSWORD)
    first = body["tokens"]["refresh_token"]
    r = h.client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert r.status_code == 200
    second = r.json()["refresh_token"]
    assert second != first
    access = r.json()["access_token"]
    # Reusing the rotated token revokes the whole session family ...
    r = h.client.post("/api/v1/auth/refresh", json={"refresh_token": first})
    assert r.status_code == 401 and r.json()["error"]["code"] == "refresh_reused"
    # ... including the legitimately rotated successor.
    r = h.client.post("/api/v1/auth/refresh", json={"refresh_token": second})
    assert r.status_code == 401
    # Access tokens stay valid until they expire (short-lived by design).
    assert (
        h.client.get("/api/v1/me", headers={"Authorization": f"Bearer {access}"}).status_code == 200
    )


def test_logout_and_logout_all(h: Harness) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    _, a = _login(h, user.email, TEST_PASSWORD)
    _, b = _login(h, user.email, TEST_PASSWORD)
    headers = {"Authorization": f"Bearer {a['tokens']['access_token']}"}
    sessions = h.client.get("/api/v1/me/sessions", headers=headers).json()
    assert len(sessions) == 2
    r = h.client.post("/api/v1/auth/logout", json={"refresh_token": a["tokens"]["refresh_token"]})
    assert r.status_code == 204
    assert (
        h.client.post(
            "/api/v1/auth/refresh", json={"refresh_token": a["tokens"]["refresh_token"]}
        ).status_code
        == 401
    )
    r = h.client.post("/api/v1/auth/logout-all", headers=headers)
    assert r.status_code == 200 and r.json()["revoked"] == 1
    assert (
        h.client.post(
            "/api/v1/auth/refresh", json={"refresh_token": b["tokens"]["refresh_token"]}
        ).status_code
        == 401
    )


def test_invalid_and_expired_access_tokens(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    assert h.client.get("/api/v1/me").status_code == 401
    assert (
        h.client.get("/api/v1/me", headers={"Authorization": "Bearer nonsense"}).status_code == 401
    )
    codec = JwtCodec(h.settings)
    old = codec.issue_access(user.id, "admin", now=datetime.now(UTC) - timedelta(hours=1))
    r = h.client.get("/api/v1/me", headers={"Authorization": f"Bearer {old.token}"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "token_invalid"
    # A token claiming a higher role still gets the role stored in the database.
    fresh = codec.issue_access(user.id, "admin")
    me = h.client.get("/api/v1/me", headers={"Authorization": f"Bearer {fresh.token}"}).json()
    assert me["user"]["role"] == "analyst"


def test_password_change_policy_and_session_revocation(h: Harness) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    _, body = _login(h, user.email, TEST_PASSWORD)
    headers = {"Authorization": f"Bearer {body['tokens']['access_token']}"}
    for weak in ("short", "password1234", "aaaaaaaaaaaaaaaa"):
        r = h.client.post(
            "/api/v1/me/password",
            headers=headers,
            json={"current_password": TEST_PASSWORD, "new_password": weak},
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "weak_password"
    r = h.client.post(
        "/api/v1/me/password",
        headers=headers,
        json={"current_password": "not-it", "new_password": "Another-Good-Passphrase-9"},
    )
    assert r.status_code == 403
    r = h.client.post(
        "/api/v1/me/password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": "Another-Good-Passphrase-9"},
    )
    assert r.status_code == 204
    refresh = h.client.post(
        "/api/v1/auth/refresh", json={"refresh_token": body["tokens"]["refresh_token"]}
    )
    assert refresh.status_code == 401
    assert _login(h, user.email, "Another-Good-Passphrase-9")[0] == 200


def test_api_keys_read_only_scope_and_revocation(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    r = h.post("/me/api-keys", user, json={"name": "ci", "scopes": ["read"]})
    assert r.status_code == 201, r.text
    key = r.json()["key"]
    key_id = r.json()["id"]
    assert key.startswith("dfk_") and r.json()["key_prefix"] == key[:12]
    listed = h.get("/me/api-keys", user).json()
    assert [k["id"] for k in listed] == [key_id] and "key" not in listed[0]

    api = {"X-API-Key": key}
    me = h.client.get("/api/v1/me", headers=api).json()
    assert me["auth_method"] == "api_key"
    r = h.client.post("/api/v1/cases", headers=api, json={"title": "via key"})
    assert r.status_code == 403  # read-only key
    # API keys cannot mint more API keys.
    assert h.client.post("/api/v1/me/api-keys", headers=api, json={"name": "x"}).status_code == 403

    w = h.post("/me/api-keys", user, json={"name": "rw", "scopes": ["read", "write"]}).json()
    r = h.client.post("/api/v1/cases", headers={"X-API-Key": w["key"]}, json={"title": "via key"})
    assert r.status_code == 201

    assert h.delete(f"/me/api-keys/{key_id}", user).status_code == 204
    assert h.client.get("/api/v1/me", headers=api).status_code == 401
    assert h.client.get("/api/v1/me", headers={"X-API-Key": "dfk_bogus"}).status_code == 401


def test_admin_user_management(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    email = f"new-{uuid.uuid4().hex[:8]}@dfir.test"
    r = h.post(
        "/users",
        admin,
        json={"email": email, "display_name": "New", "role": "viewer", "password": "short"},
    )
    assert r.status_code == 422
    r = h.post(
        "/users",
        admin,
        json={"email": email, "display_name": "New", "role": "viewer", "password": TEST_PASSWORD},
    )
    assert r.status_code == 201, r.text
    new_id = r.json()["id"]
    assert r.json()["role"] == "viewer"
    r = h.post(
        "/users",
        admin,
        json={"email": email, "display_name": "Dup", "role": "viewer", "password": TEST_PASSWORD},
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "email_taken"

    # Role change needs re-authentication.
    r = h.patch(f"/users/{new_id}", admin, json={"role": "lead"})
    assert r.status_code == 403 and r.json()["error"]["code"] == "reauth_required"
    r = h.patch(f"/users/{new_id}", admin, json={"role": "lead", "admin_password": "wrong"})
    assert r.status_code == 403
    r = h.patch(f"/users/{new_id}", admin, json={"role": "lead", "admin_password": TEST_PASSWORD})
    assert r.status_code == 200 and r.json()["role"] == "lead"
    assert any(u["id"] == new_id for u in h.get("/users", admin).json())
    r = h.patch(f"/users/{new_id}", admin, json={"display_name": "Renamed"})
    assert r.status_code == 200 and r.json()["display_name"] == "Renamed"


def test_last_admin_cannot_be_removed(h: Harness, db_engine: Engine) -> None:
    with db_engine.begin() as conn:  # isolate: deactivate other admins created by earlier tests
        conn.execute(text("UPDATE users SET is_active = false WHERE role = 'admin'"))
    admin = h.make_user(UserRole.admin)
    r = h.patch(
        f"/users/{admin.id}", admin, json={"role": "analyst", "admin_password": TEST_PASSWORD}
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin"


def test_failed_reauthentication_counts_towards_lockout(h: Harness) -> None:
    user = h.make_user(UserRole.analyst)
    body = {"current_password": "Wrong-Password-123", "new_password": "Another-Good-Passphrase-9"}
    for _ in range(h.settings.login_lockout_threshold):
        assert h.post("/me/password", user, json=body).status_code == 403
    body["current_password"] = TEST_PASSWORD
    r = h.post("/me/password", user, json=body)
    assert r.status_code == 429 and r.json()["error"]["code"] == "account_locked"
    assert _login(h, user.email, TEST_PASSWORD)[0] == 429


def test_failed_admin_reauth_locks_the_admin(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    target = h.make_user(UserRole.viewer, login=False)
    for _ in range(h.settings.login_lockout_threshold):
        r = h.patch(f"/users/{target.id}", admin, json={"role": "lead", "admin_password": "nope"})
        assert r.status_code == 403
    r = h.patch(
        f"/users/{target.id}", admin, json={"role": "lead", "admin_password": TEST_PASSWORD}
    )
    assert r.status_code == 429


def test_wrong_totp_when_disabling_mfa_counts(h: Harness, db_engine: Engine) -> None:
    user = h.make_user(UserRole.analyst)
    _enable_mfa(h, user)
    r = h.post("/me/mfa/disable", user, json={"password": TEST_PASSWORD, "code": "000000"})
    assert r.status_code == 400
    with db_engine.connect() as conn:
        failed = conn.execute(
            text("SELECT failed_logins FROM users WHERE id = :u"), {"u": user.id}
        ).scalar_one()
    assert failed == 1


def test_email_is_case_insensitive_and_stored_lower_case(h: Harness, db_engine: Engine) -> None:
    admin = h.make_user(UserRole.admin)
    local = f"Mixed.Case-{uuid.uuid4().hex[:6]}"
    email = f"{local}@DFIR.Test"
    r = h.post(
        "/users",
        admin,
        json={"email": email, "display_name": "Mixed", "role": "viewer", "password": TEST_PASSWORD},
    )
    assert r.status_code == 201, r.text
    assert r.json()["email"] == email.lower()
    for variant in (email, email.lower(), email.upper()):
        assert _login(h, variant, TEST_PASSWORD)[0] == 200, variant
    r = h.post(
        "/users",
        admin,
        json={
            "email": email.lower(),
            "display_name": "Dup",
            "role": "viewer",
            "password": TEST_PASSWORD,
        },
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "email_taken"


def test_credential_events_revoke_api_keys(h: Harness) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    _, body = _login(h, user.email, TEST_PASSWORD)
    headers = {"Authorization": f"Bearer {body['tokens']['access_token']}"}
    r = h.client.post(
        "/api/v1/me/api-keys", headers=headers, json={"name": "k", "scopes": ["read", "write"]}
    )
    api = {"X-API-Key": r.json()["key"]}
    assert h.client.get("/api/v1/me", headers=api).status_code == 200
    # An API key cannot enrol MFA (it would lock the owner out with the caller's secret).
    assert h.client.post("/api/v1/me/mfa/enroll", headers=api).status_code == 403
    r = h.client.post(
        "/api/v1/me/password",
        headers=headers,
        json={"current_password": TEST_PASSWORD, "new_password": "Another-Good-Passphrase-9"},
    )
    assert r.status_code == 204
    assert h.client.get("/api/v1/me", headers=api).status_code == 401


def test_creating_a_privileged_user_needs_reauthentication(h: Harness) -> None:
    admin = h.make_user(UserRole.admin)
    payload = {
        "email": f"lead-{uuid.uuid4().hex[:8]}@dfir.test",
        "display_name": "Lead",
        "role": "lead",
        "password": TEST_PASSWORD,
    }
    r = h.post("/users", admin, json=payload)
    assert r.status_code == 403 and r.json()["error"]["code"] == "reauth_required"
    r = h.post("/users", admin, json={**payload, "admin_password": TEST_PASSWORD})
    assert r.status_code == 201 and r.json()["role"] == "lead"
