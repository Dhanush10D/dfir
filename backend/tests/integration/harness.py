"""API test harness: a real app on the throwaway database, with a fake vault and test signer."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.core.signing import CustodySigner
from app.db.models import UserRole
from app.db.session import make_session_factory
from app.deps import (
    get_app_settings,
    get_custody_signer,
    get_db,
    get_job_dispatcher,
    get_trusted_keys,
    get_vault,
)
from app.main import create_app
from app.services.audit import DbAuditSink
from app.services.iam import IAMService
from app.services.processing import ProcessingService, RunResult
from tests.fakes import FakeVault

TEST_PASSWORD = "Correct-Horse-Battery-42"

API = "/api/v1"
CLIENT_IP = "198.51.100.7"  # TEST-NET-2; recorded in audit rows


@dataclass
class UserCtx:
    id: uuid.UUID
    email: str
    password: str
    role: UserRole
    headers: dict[str, str]


class Harness:
    def __init__(
        self,
        engine: Engine,
        settings: Settings,
        signer: CustodySigner | None,
        vault: FakeVault | None,
    ) -> None:
        self.engine = engine
        self.settings = settings
        self.signer = signer
        self.vault = vault
        self.sessions: sessionmaker[Session] = make_session_factory(engine)
        self.app: FastAPI = create_app(settings)
        self.app.state.audit_sink = DbAuditSink(self.sessions)
        self.app.dependency_overrides[get_app_settings] = lambda: settings
        self.app.dependency_overrides[get_db] = self._db
        self.app.dependency_overrides[get_vault] = lambda: self.vault
        self.app.dependency_overrides[get_custody_signer] = lambda: self.signer
        # Extra trusted custody keys (CUSTODY_TRUSTED_KEYS_PATH); the signer is always trusted.
        self.trusted: dict[str, Any] = {}
        self.app.dependency_overrides[get_trusted_keys] = lambda: self.trusted
        # Parse jobs are recorded instead of queued; tests run them with run_job()/run_pending().
        self.dispatched: list[uuid.UUID] = []
        self.dispatch_error: Exception | None = None
        self.app.dependency_overrides[get_job_dispatcher] = lambda: self._dispatch
        self.client = TestClient(self.app, raise_server_exceptions=False, client=(CLIENT_IP, 50000))

    def _dispatch(self, job_id: uuid.UUID) -> None:
        if self.dispatch_error is not None:
            raise self.dispatch_error
        self.dispatched.append(job_id)

    def processing(self, **overrides: Any) -> ProcessingService:
        settings = self.settings.model_copy(update=overrides) if overrides else self.settings
        return ProcessingService(
            self.sessions,
            settings,
            vault=self.vault,  # type: ignore[arg-type]
            signer=self.signer,
            trusted_keys=self.trusted,
            worker_name="test-worker",
        )

    def run_job(self, job_id: uuid.UUID | str, **kw: Any) -> RunResult:
        return self.processing().run(uuid.UUID(str(job_id)), **kw)

    def run_pending(self) -> list[RunResult]:
        pending, self.dispatched = self.dispatched, []
        return [self.run_job(job_id) for job_id in pending]

    def _db(self) -> Iterator[Session]:
        session = self.sessions()
        try:
            yield session
        finally:
            session.close()

    # ------------------------------------------------------------------ users

    def make_user(
        self,
        role: UserRole = UserRole.analyst,
        *,
        login: bool = True,
        password: str = TEST_PASSWORD,
    ) -> UserCtx:
        email = f"{role.value}-{uuid.uuid4().hex[:10]}@dfir.test"
        with self.sessions() as session:
            iam = IAMService(session, self.settings)
            user = iam._create_user(email, f"Test {role.value}", role, password)
            session.commit()
            user_id = user.id
        headers = self.login(email, password) if login else {}
        return UserCtx(user_id, email, password, role, headers)

    def login(self, email: str, password: str) -> dict[str, str]:
        r = self.client.post(f"{API}/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["tokens"], body
        return {"Authorization": f"Bearer {body['tokens']['access_token']}"}

    # ------------------------------------------------------------------ requests

    def get(self, path: str, user: UserCtx | None = None, **kw: Any) -> Response:
        return self.client.get(API + path, headers=user.headers if user else None, **kw)

    def post(self, path: str, user: UserCtx | None = None, **kw: Any) -> Response:
        return self.client.post(API + path, headers=user.headers if user else None, **kw)

    def put(self, path: str, user: UserCtx | None = None, **kw: Any) -> Response:
        headers = dict(user.headers) if user else {}
        headers.update(kw.pop("headers", {}))
        return self.client.put(API + path, headers=headers, **kw)

    def patch(self, path: str, user: UserCtx | None = None, **kw: Any) -> Response:
        return self.client.patch(API + path, headers=user.headers if user else None, **kw)

    def delete(self, path: str, user: UserCtx | None = None, **kw: Any) -> Response:
        return self.client.request(
            "DELETE", API + path, headers=user.headers if user else None, **kw
        )

    # ------------------------------------------------------------------ domain helpers

    def create_case(self, user: UserCtx, title: str = "Test incident") -> dict[str, Any]:
        r = self.post("/cases", user, json={"title": title})
        assert r.status_code == 201, r.text
        return dict(r.json())

    def add_member(self, owner: UserCtx, case_id: str, member: UserCtx, role: UserRole) -> None:
        r = self.post(
            f"/cases/{case_id}/members", owner, json={"user_id": str(member.id), "role": role.value}
        )
        assert r.status_code == 200, r.text

    def create_evidence(self, user: UserCtx, case_id: str, **fields: Any) -> dict[str, Any]:
        body = {"kind": "log", "original_name": "auth.log", **fields}
        r = self.post(f"/cases/{case_id}/evidence", user, json=body)
        assert r.status_code == 201, r.text
        return dict(r.json()["evidence"])

    def upload(self, user: UserCtx, evidence_id: str, data: bytes) -> Response:
        return self.put(
            f"/evidence/{evidence_id}/upload",
            user,
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )

    def stored_evidence(
        self, user: UserCtx, case_id: str, data: bytes = b"line1\nline2\n", **fields: Any
    ) -> dict[str, Any]:
        ev = self.create_evidence(user, case_id, **fields)
        r = self.upload(user, ev["id"], data)
        assert r.status_code == 200, r.text
        r = self.post(f"/evidence/{ev['id']}/finalize", user)
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is True, r.json()
        assert r.json()["evidence"]["sha256"] == hashlib.sha256(data).hexdigest()
        return dict(r.json()["evidence"])

    def key_of(self, evidence: dict[str, Any]) -> str:
        return str(evidence["storage_uri"]).split("/", 3)[3]
