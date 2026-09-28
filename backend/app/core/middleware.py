"""ASGI middleware: request id propagation and one structured access log line per request."""

from __future__ import annotations

import time

import structlog
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.request_context import reset_request_id, sanitize_request_id, set_request_id

REQUEST_ID_HEADER = "x-request-id"

log = structlog.stdlib.get_logger("dfirbench.access")


class RequestIdMiddleware:
    """Pure ASGI middleware (no BaseHTTPMiddleware, so streaming bodies are not buffered)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        inbound: str | None = None
        for key, value in scope.get("headers", []):
            if key.decode("latin-1").lower() == REQUEST_ID_HEADER:
                inbound = value.decode("latin-1")
                break
        request_id = sanitize_request_id(inbound)

        # Also expose it on request.state for handlers that run outside this middleware.
        scope.setdefault("state", {})["request_id"] = request_id
        token = set_request_id(request_id)
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info(
                "http_request",
                method=scope.get("method"),
                path=scope.get("path"),
                status=status_code,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            structlog.contextvars.unbind_contextvars("request_id")
            reset_request_id(token)
