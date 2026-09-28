"""Response schemas for health/readiness and the shared error envelope (guide 15.3)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "dfirbench-api"
    version: str
    env: str
    time: datetime = Field(description="Server time, ISO 8601 UTC")


class CheckStatus(BaseModel):
    ok: bool
    latency_ms: float
    error: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ready"] = "ready"
    checks: dict[str, CheckStatus]


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail
