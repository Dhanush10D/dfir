"""Version 1 API routers. Later phases add jobs, events, alerts, rules, reports, ..."""

from fastapi import APIRouter

from app.api.v1 import audit, auth, cases, evidence, health, users

router = APIRouter()
for module in (health, auth, users, cases, evidence, audit):
    router.include_router(module.router)

__all__ = ["router"]
