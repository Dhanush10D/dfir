"""AuditMiddleware (guide 16.5): who, what, when, from where and result for every API request.

Pure ASGI (streaming bodies are not buffered). After the response finishes it writes one
``audit_log`` row through a sink (the database in production, a fake in unit tests) in a worker
thread. Request bodies, query strings and headers are never recorded. The user id comes from
``request.state.user_id``, set by the authentication dependency.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Protocol

import anyio
import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.services.audit import AuditRecord

log = structlog.stdlib.get_logger("dfirbench.audit")

API_PREFIX = "/api/v1"
SKIP_PATHS = frozenset(
    {
        f"{API_PREFIX}/health",
        f"{API_PREFIX}/ready",
        f"{API_PREFIX}/openapi.json",
        f"{API_PREFIX}/docs",
        f"{API_PREFIX}/docs/oauth2-redirect",
    }
)
METHOD_ACTIONS = {
    "GET": "read",
    "HEAD": "read",
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}
# Path parameter -> audited object type (most specific first).
OBJECT_PARAMS = (
    ("evidence_id", "evidence"),
    ("key_id", "api_key"),
    ("case_id", "case"),
    ("user_id", "user"),
)


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None: ...


def _object_of(scope: Scope) -> tuple[str | None, str | None]:
    params = scope.get("path_params") or {}
    for param, object_type in OBJECT_PARAMS:
        if param in params:
            return object_type, str(params[param])
    return None, None


class AuditMiddleware:
    def __init__(self, app: ASGIApp, sink_getter: Callable[[], AuditSink | None]) -> None:
        self.app = app
        self.sink_getter = sink_getter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] != "http"
            or not path.startswith(API_PREFIX)
            or path in SKIP_PATHS
            or scope.get("method") == "OPTIONS"
        ):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            with anyio.CancelScope(shield=True):  # still audit when the client disconnects
                await self._record(scope, status_code, started)

    async def _record(self, scope: Scope, status_code: int, started: float) -> None:
        sink = self.sink_getter()
        if sink is None:
            return
        state = scope.get("state") or {}
        raw_user = state.get("user_id")
        user_id = raw_user if isinstance(raw_user, uuid.UUID) else None
        object_type, object_id = _object_of(scope)
        method = str(scope.get("method", ""))
        record = AuditRecord(
            action=METHOD_ACTIONS.get(method, "request"),
            user_id=user_id,
            ip=(scope.get("client") or (None,))[0],
            method=method,
            path=str(scope.get("path", ""))[:2048],
            status=status_code,
            object_type=object_type,
            object_id=object_id,
            detail={
                "kind": "http",
                "request_id": state.get("request_id"),
                "auth": state.get("auth_method"),
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )
        try:
            await anyio.to_thread.run_sync(sink.write, record)
        except Exception as exc:  # noqa: BLE001 - never fail a response because of auditing
            log.error("audit_sink_failed", exc_type=type(exc).__name__)
