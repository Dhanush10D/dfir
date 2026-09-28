"""Domain errors and the uniform JSON error envelope (guide section 15.3).

```
{"error": {"code": "...", "message": "...", "details": {...}, "request_id": "..."}}
```
"""

from __future__ import annotations

from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    UnauthenticatedError,
)
from app.core.request_context import get_request_id

__all__ = [
    "AppError",
    "ConflictError",
    "ForbiddenError",
    "InvalidStateError",
    "NotFoundError",
    "UnauthenticatedError",
    "error_body",
    "register_handlers",
]

log = structlog.stdlib.get_logger("dfirbench.errors")

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


def code_for_status(status_code: int) -> str:
    return _STATUS_CODES.get(status_code, "http_error" if status_code < 500 else "internal_error")


def error_body(
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "request_id": request_id if request_id is not None else get_request_id(),
        }
    }


def request_id_of(request: Request | None) -> str | None:
    """Request id from the contextvar, falling back to ``request.state`` (set by the middleware).

    The fallback matters for unhandled exceptions: Starlette runs that handler in the outermost
    ServerErrorMiddleware, after our middleware has already reset the contextvar.
    """
    rid = get_request_id()
    if rid is None and request is not None:
        rid = getattr(request.state, "request_id", None)
    return rid


def error_response(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    request: Request | None = None,
) -> JSONResponse:
    rid = request_id_of(request)
    all_headers = dict(headers or {})
    if rid:
        all_headers.setdefault("X-Request-ID", rid)
    return JSONResponse(
        status_code=status_code,
        content=jsonable_encoder(error_body(code, message, details, request_id=rid)),
        headers=all_headers,
    )


async def _app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, AppError):  # registered only for AppError
        raise exc
    return error_response(
        exc.status_code,
        exc.code,
        exc.message,
        exc.details,
        headers=exc.headers,
        request=request,
    )


async def _http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):  # registered only for StarletteHTTPException
        raise exc
    status_code = exc.status_code
    if isinstance(exc.detail, str):
        message = exc.detail
    else:
        try:
            message = HTTPStatus(status_code).phrase
        except ValueError:
            message = "Error"
    details = exc.detail if isinstance(exc.detail, dict) else None
    return error_response(
        status_code,
        code_for_status(status_code),
        message,
        details,
        headers=exc.headers,
        request=request,
    )


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):  # registered only for RequestValidationError
        raise exc
    errors = [
        {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
        for err in exc.errors()
    ]
    return error_response(
        422, "validation_error", "Request validation failed.", {"errors": errors}, request=request
    )


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Log type and traceback server-side; never leak internals to the client.
    log.error("unhandled_exception", exc_type=type(exc).__name__, exc_info=exc)
    return error_response(500, "internal_error", "An unexpected error occurred.", request=request)


def register_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
