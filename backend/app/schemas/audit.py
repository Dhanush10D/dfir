"""Audit log query schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class AuditEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    user_id: uuid.UUID | None
    ip: str | None
    method: str | None
    path: str | None
    status: int | None
    action: str
    object_type: str | None
    object_id: str | None
    detail: dict[str, Any]

    @field_validator("ip", mode="before")
    @classmethod
    def _ip_text(cls, value: object) -> object:
        return str(value) if value is not None else None


class AuditList(BaseModel):
    items: list[AuditEntryOut]
    next_cursor: str | None = None
    total: int
