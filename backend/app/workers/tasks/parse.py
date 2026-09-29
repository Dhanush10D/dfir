"""``dfirbench.parse_evidence(job_id)`` (guide 14.5, 10.6) on the ``parse`` queue.

The task is a thin wrapper: all state changes (claim, fencing, cancel checks, batches, run
manifest, custody) live in ``services/processing.py``. The wrapper only decides about retries:

* ``retry`` (transient I/O or database trouble, the job was re-queued under its row lock):
  retried with exponential backoff and jitter, at most ``JOB_MAX_AUTO_RETRIES`` times; the last
  attempt runs with ``allow_retry=False`` so the job ends ``failed`` instead of staying queued.
* ``busy`` (the job is ``running`` under a live lease: a duplicate delivery, or a redelivery after
  a worker crash): retried once the lease has expired, so a crashed worker's job is reclaimed.
* an unexpected exception escaping the service (e.g. the database vanished while recording the
  result): retried after the lease, when the job becomes reclaimable.

``acks_late`` + ``reject_on_worker_lost`` + prefetch 1 come from ``celery_app``. Soft time limits
end the run as ``partial`` (events already written are kept, with a visible error).
"""

from __future__ import annotations

import random
import uuid
from collections.abc import Callable
from typing import Any, Protocol

import structlog
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from app.config import get_settings
from app.services.processing import ProcessingService, RunResult
from app.workers.celery_app import celery_app
from app.workers.dispatch import PARSE_QUEUE, PARSE_TASK

log = structlog.stdlib.get_logger("dfirbench.tasks.parse")

BACKOFF_BASE_S = 10
BACKOFF_MAX_S = 600
LEASE_SLACK_S = 30


class Runner(Protocol):
    def run(
        self,
        job_id: uuid.UUID,
        *,
        allow_retry: bool = False,
        stop_exceptions: tuple[type[BaseException], ...] = (),
    ) -> RunResult: ...


def backoff_seconds(retries: int, rand: Callable[[], float] = random.random) -> int:
    """10s, 20s, 40s, ... capped at 10 min, plus up to 25% jitter."""
    base: int = min(BACKOFF_BASE_S * 2**retries, BACKOFF_MAX_S)
    return int(base + base * 0.25 * rand())


def build_service() -> ProcessingService:
    """Worker wiring: app-role sessions, vault, custody signer, trusted keys (outside the DB)."""
    from app.db.session import get_sessionmaker
    from app.deps import get_custody_signer, get_trusted_keys, get_vault

    return ProcessingService(
        get_sessionmaker(),
        get_settings(),
        vault=get_vault(),
        signer=get_custody_signer(),
        trusted_keys=get_trusted_keys(),
    )


# Tests replace this with a factory returning a service bound to the test database.
service_factory: Callable[[], Runner] = build_service


@celery_app.task(
    bind=True,
    name=PARSE_TASK,
    queue=PARSE_QUEUE,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=None,  # bounded below from settings (JOB_MAX_AUTO_RETRIES)
)
def parse_evidence(self: Task[[str], dict[str, Any]], job_id: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        jid = uuid.UUID(str(job_id))
    except ValueError:
        log.warning("parse_task_bad_job_id")
        return {"job_id": None, "outcome": "skipped", "error": "invalid job id"}
    retries = int(self.request.retries or 0)
    can_retry = retries < settings.job_max_auto_retries
    lease_wait = settings.job_lease_s + LEASE_SLACK_S
    try:
        result = service_factory().run(
            jid, allow_retry=can_retry, stop_exceptions=(SoftTimeLimitExceeded,)
        )
    except Exception as exc:
        log.exception("parse_task_error", job_id=str(jid), retries=retries)
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
