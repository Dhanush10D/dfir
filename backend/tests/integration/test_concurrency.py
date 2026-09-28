"""Races the verifier demonstrated: parallel logins vs. lockout, TOTP replay, concurrent uploads.

Each worker uses its own database session (and connection), like separate API requests.
"""

from __future__ import annotations

import io
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, text

from app.core.exceptions import AppError
from app.core.hashing import Readable
from app.core.permissions import Principal
from app.core.security import totp_code
from app.db.models import UserRole
from app.repositories.vault import PutResult
from app.services.audit import RequestMeta
from app.services.evidence import EvidenceService
from app.services.iam import IAMService
from tests.fakes import FakeVault
from tests.integration.harness import TEST_PASSWORD, Harness, UserCtx

pytestmark = pytest.mark.integration

META = RequestMeta(ip="198.51.100.9")


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


def test_parallel_wrong_passwords_engage_the_lockout(h: Harness, db_engine: Engine) -> None:
    user = h.make_user(UserRole.analyst, login=False)
    threshold = h.settings.login_lockout_threshold

    def attempt(_: int) -> Any:
        with h.sessions() as session:
            return IAMService(session, h.settings).login(user.email, "Wrong-Password-123", META)

    results = _parallel(20, attempt)
    assert results.count("invalid_credentials") == threshold
    assert results.count("account_locked") == 20 - threshold
    with db_engine.connect() as conn:
        failed, locked = conn.execute(
            text("SELECT failed_logins, locked_until FROM users WHERE id = :u"), {"u": user.id}
        ).one()
    assert failed == threshold
    assert locked is not None and locked > datetime.now(UTC)


def _mfa_user(h: Harness) -> tuple[UserCtx, str]:
    user = h.make_user(UserRole.analyst)
    secret = h.post("/me/mfa/enroll", user).json()["secret"]
    confirm = h.post("/me/mfa/confirm", user, json={"code": totp_code(secret)})
    assert confirm.status_code == 200
    return user, secret


def test_totp_code_is_accepted_at_most_once_under_concurrency(h: Harness) -> None:
    user, secret = _mfa_user(h)
    challenges = []
    for _ in range(8):
        body = h.client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": TEST_PASSWORD}
        ).json()
        challenges.append(body["mfa_challenge"])
    code = totp_code(secret, datetime.now(UTC) + timedelta(seconds=30))  # fresh, unused step

    def attempt(i: int) -> Any:
        with h.sessions() as session:
            IAMService(session, h.settings).verify_mfa(challenges[i], META, code=code)
            return "ok"

    results = _parallel(8, attempt)
    assert results.count("ok") == 1
    # The losers are refused as replays; once they exceed the threshold the account locks.
    assert set(results) - {"ok"} <= {"mfa_invalid", "account_locked"}


class BlockingVault(FakeVault):
    """put_stream blocks until released, so a second upload can race the first."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def put_stream(
        self, key: str, reader: Readable, part_size: int, content_type: str
    ) -> PutResult:
        self.entered.set()
        assert self.release.wait(10)
        return super().put_stream(key, reader, part_size, content_type)


def _principal(user: UserCtx) -> Principal:
    return Principal(user.id, user.email, "Test", user.role)


def test_concurrent_upload_is_refused_and_only_one_version_is_stored(h: Harness) -> None:
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    vault = BlockingVault()
    eid = uuid.UUID(ev["id"])

    def upload(data: bytes) -> Any:
        with h.sessions() as session:
            svc = EvidenceService(session, h.settings, vault=vault, signer=h.signer)
            return svc.receive_upload(_principal(analyst), eid, io.BytesIO(data), meta=META).status

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(upload, b"first upload")
        assert vault.entered.wait(10)
        with pytest.raises(AppError) as second:
            upload(b"second upload")
        assert second.value.code == "upload_in_progress"
        vault.release.set()
        assert first.result(10) == "uploaded"
    with pytest.raises(AppError) as third:  # afterwards: state check
        upload(b"third upload")
    assert third.value.code == "invalid_state"
    assert len(vault.objects[h.key_of(ev)]) == 1


def test_upload_state_is_rechecked_after_taking_the_lock(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If another upload finishes between the first check and the lock, nothing is written."""
    analyst = h.make_user(UserRole.analyst)
    case = h.create_case(analyst)
    ev = h.create_evidence(analyst, case["id"])
    vault = FakeVault()
    original = EvidenceService._upload_lock

    def racing_lock(self: EvidenceService, evidence_id: uuid.UUID) -> Any:
        with h.engine.begin() as conn:  # the other request completed meanwhile
            conn.execute(
                text("UPDATE evidence SET status = 'uploaded' WHERE id = :e"), {"e": evidence_id}
            )
        return original(self, evidence_id)

    monkeypatch.setattr(EvidenceService, "_upload_lock", racing_lock)
    with h.sessions() as session:
        svc = EvidenceService(session, h.settings, vault=vault, signer=h.signer)
        with pytest.raises(AppError) as exc:
            svc.receive_upload(
                _principal(analyst), uuid.UUID(ev["id"]), io.BytesIO(b"late"), meta=META
            )
    assert exc.value.code == "invalid_state"
    assert vault.objects == {}
