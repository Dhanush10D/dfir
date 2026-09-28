"""System tasks: liveness ping for the worker."""

from __future__ import annotations

from app.workers.celery_app import celery_app


@celery_app.task(name="dfirbench.system.ping", queue="default", acks_late=False)
def ping() -> str:
    """Round-trip check that a worker consumes the default queue."""
    return "pong"
