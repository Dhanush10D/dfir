"""``dfirbench.process_outbound()`` on the ``default`` queue (guide 15.6, 19.4).

Thin wrapper around :class:`app.services.outbox.OutboundService`: fan out new outbox events, then
deliver what is due. The task takes no arguments (nothing secret or case-specific travels through
the broker); each run works on whatever is pending in the database.

Retries are bounded by the database, not by Celery: every delivery row counts its attempts and
ends ``failed`` after ``OUTBOUND_MAX_ATTEMPTS``. When a run put deliveries back for a retry it
schedules one follow-up run after the shortest backoff; when it stopped at the batch limit it
schedules the next run immediately. A lost follow-up is harmless: the next event that is emitted
also processes everything that is due.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import structlog
from celery import Task

from app.config import get_settings
from app.services.outbox import OutboundService
from app.workers.celery_app import celery_app
from app.workers.dispatch import OUTBOUND_QUEUE, OUTBOUND_TASK

log = structlog.stdlib.get_logger("dfirbench.tasks.outbound")

MAX_COUNTDOWN_S = 3600


def build_service() -> OutboundService:
    from app.db.session import get_sessionmaker

    return OutboundService(get_sessionmaker(), get_settings())


# Tests replace this with a factory returning a service bound to the test database and fakes.
service_factory: Callable[[], OutboundService] = build_service


def follow_up_countdown(result: dict[str, Any]) -> int | None:
    """Seconds until the next run this one should schedule, or None."""
    if result.get("more"):
        return 0
    retry_in = result.get("retry_in_s")
    if retry_in is None:
        return None
    return int(min(max(int(retry_in), 1), MAX_COUNTDOWN_S))


@celery_app.task(
    bind=True,
    name=OUTBOUND_TASK,
    queue=OUTBOUND_QUEUE,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=3,
)
def process_outbound(self: Task[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        result = service_factory().process().as_dict()
    except Exception as exc:
        log.exception("outbound_task_error")
        raise self.retry(exc=exc, countdown=30) from exc
    countdown = follow_up_countdown(result)
    if countdown is not None:
        self.apply_async(countdown=countdown, queue=OUTBOUND_QUEUE)
    if result["events"] or result["attempted"]:
        log.info("outbound_processed", **result)
    return result
