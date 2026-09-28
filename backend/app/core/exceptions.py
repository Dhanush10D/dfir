"""Domain exceptions (no web-framework imports, so services and workers can raise them).

The API layer maps them to the uniform JSON error envelope in ``app/core/errors.py``.
"""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base class for domain errors raised by services and mapped to HTTP by the API layer."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        self.headers = headers or {}


class NotFoundError(AppError):
    def __init__(self, message: str = "Resource not found.", **details: Any) -> None:
        super().__init__("not_found", message, 404, details)


class ConflictError(AppError):
    def __init__(self, message: str, code: str = "conflict", **details: Any) -> None:
        super().__init__(code, message, 409, details)


class UnauthenticatedError(AppError):
    def __init__(self, message: str = "Authentication required.", code: str = "unauthenticated"):
        super().__init__(code, message, 401, headers={"WWW-Authenticate": "Bearer"})


class ForbiddenError(AppError):
    def __init__(self, message: str = "You are not allowed to do this.", **details: Any) -> None:
        super().__init__("forbidden", message, 403, details)


class InvalidStateError(AppError):
    def __init__(self, message: str, **details: Any) -> None:
        super().__init__("invalid_state", message, 409, details)
