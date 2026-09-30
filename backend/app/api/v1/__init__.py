"""Version 1 API routers. Later phases add jobs, events, alerts, rules, reports, ..."""

from fastapi import APIRouter

from app.api.v1 import (
    ai,
    analysis,
    audit,
    auth,
    cases,
    collection,
    detection,
    events,
    evidence,
    health,
    jobs,
    notes,
    reports,
    search,
    users,
)

router = APIRouter()
for module in (
    health,
    auth,
    users,
    cases,
    evidence,
    jobs,
    collection,
    events,
    search,
    detection,
    notes,
    analysis,
    ai,
    reports,
    audit,
):
    router.include_router(module.router)

__all__ = ["router"]
