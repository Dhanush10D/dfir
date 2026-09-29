"""``dfirbench.detect_case(job_id)`` on the ``detect`` queue (guide 11.3, 14.5).

Thin wrapper around :class:`app.services.detection.DetectionService` with the same retry policy
as parse jobs: ``retry`` (transient DB trouble, re-queued under the row lock) backs off
exponentially; ``busy`` (live lease elsewhere) and unexpected exceptions retry after the lease.
Soft time limits end the run ``partial`` (alerts already flushed stay; detection is idempotent).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import structlog
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from app.config import get_settings
from app.services.detection import DetectionService
from app.workers.celery_app import celery_app
from app.workers.dispatch import DETECT_QUEUE, DETECT_TASK
from app.workers.tasks.parse import LEASE_SLACK_S, Runner, backoff_seconds

log = structlog.stdlib.get_logger("dfirbench.tasks.detect")


def build_service() -> DetectionService:
    from app.db.session import get_sessionmaker

    return DetectionService(get_sessionmaker(), get_settings())


# Tests replace this with a factory returning a service bound to the test database.
service_factory: Callable[[], Runner] = build_service


@celery_app.task(
    bind=True,
    name=DETECT_TASK,
    queue=DETECT_QUEUE,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=None,
)
def detect_case(self: Task[[str], dict[str, Any]], job_id: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        jid = uuid.UUID(str(job_id))
    except ValueError:
        log.warning("detect_task_bad_job_id")
        return {"job_id": None, "outcome": "skipped", "error": "invalid job id"}
    retries = int(self.request.retries or 0)
    can_retry = retries < settings.job_max_auto_retries
    lease_wait = settings.job_lease_s + LEASE_SLACK_S
    try:
        result = service_factory().run(
            jid, allow_retry=can_retry, stop_exceptions=(SoftTimeLimitExceeded,)
        )
    except Exception as exc:
        log.exception("detect_task_error", job_id=str(jid), retries=retries)
        if not can_retry:
            raise
        raise self.retry(
            exc=exc, countdown=lease_wait, max_retries=settings.job_max_auto_retries
        ) from exc
    if result.outcome == "retry":
        raise self.retry(
            countdown=backoff_seconds(retries), max_retries=settings.job_max_auto_retries
        )
    if result.outcome == "busy" and can_retry:
        raise self.retry(countdown=lease_wait, max_retries=settings.job_max_auto_retries)
    return result.as_dict()
