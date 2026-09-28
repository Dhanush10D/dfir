"""Version 1 API routers. Later phases add auth, cases, evidence, jobs, events, alerts, ..."""

from fastapi import APIRouter

from app.api.v1 import health

router = APIRouter()
router.include_router(health.router)

__all__ = ["router"]
