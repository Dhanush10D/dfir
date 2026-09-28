"""Liveness and readiness probes (guide 21.4). HTTP only; checks live in services/health.py."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends

from app import __version__
from app.config import Settings
from app.core.errors import AppError
from app.deps import get_app_settings, get_readiness_checks
from app.schemas.health import ErrorResponse, HealthResponse, ReadinessResponse
from app.services.health import CheckResult, run_readiness

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Liveness (no dependency checks)")
def health(settings: Annotated[Settings, Depends(get_app_settings)]) -> HealthResponse:
    return HealthResponse(version=__version__, env=settings.app_env, time=datetime.now(UTC))


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ErrorResponse, "description": "A dependency is unavailable"}},
    summary="Readiness (database, redis, evidence vault)",
)
def ready(
    checks: Annotated[list[Callable[[], CheckResult]], Depends(get_readiness_checks)],
) -> ReadinessResponse:
    report = run_readiness(checks)
    if not report.ok:
        failing = [c.name for c in report.checks if not c.ok]
        raise AppError(
            "not_ready",
            "Dependencies unavailable: " + ", ".join(failing),
            status_code=503,
            details={"checks": report.as_dict()},
        )
    return ReadinessResponse.model_validate({"checks": report.as_dict()})
