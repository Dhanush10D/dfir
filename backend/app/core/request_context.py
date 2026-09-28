"""Per-request context (request id) shared by middleware, error handlers and logging."""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

# Accept only short, boring inbound ids so a client cannot inject into logs.
_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def new_request_id() -> str:
    return uuid.uuid4().hex


def sanitize_request_id(value: str | None) -> str:
    """Return the inbound id if it is safe, otherwise a fresh one."""
    if value and _SAFE_ID.fullmatch(value):
        return value
    return new_request_id()


def get_request_id() -> str | None:
    return _request_id.get()


def set_request_id(value: str | None) -> object:
    return _request_id.set(value)


def reset_request_id(token: object) -> None:
    _request_id.reset(token)  # type: ignore[arg-type]
