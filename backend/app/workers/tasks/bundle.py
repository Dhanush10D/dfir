"""``dfirbench.ingest_bundle(job_id)`` on the ``parse`` queue (Phase 5, guide 9.2).

Thin wrapper around :class:`app.services.bundles.BundleIngestService` with the parse-job retry
policy: ``retry`` (transient I/O or database trouble, re-queued under the row lock) backs off
exponentially; ``busy`` (live lease elsewhere) and unexpected exceptions retry after the lease.
Derived members get ordinary parse jobs, dispatched by the service after each commit.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import structlog
from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from app.config import get_settings
from app.services.bundles import BundleIngestService
from app.workers.celery_app import celery_app
from app.workers.dispatch import BUNDLE_QUEUE, BUNDLE_TASK, dispatch_parse
from app.workers.tasks.parse import LEASE_SLACK_S, Runner, backoff_seconds

log = structlog.stdlib.get_logger("dfirbench.tasks.bundle")


def build_service() -> BundleIngestService:
    """Worker wiring: app-role sessions, vault, custody signer, trusted keys (outside the DB)."""
    from app.db.session import get_sessionmaker
    from app.deps import get_custody_signer, get_trusted_keys, get_vault

    return BundleIngestService(
        get_sessionmaker(),
        get_settings(),
        vault=get_vault(),
        signer=get_custody_signer(),
        trusted_keys=get_trusted_keys(),
        parse_dispatcher=dispatch_parse,
    )


# Tests replace this with a factory returning a service bound to the test database.
service_factory: Callable[[], Runner] = build_service


@celery_app.task(
    bind=True,
    name=BUNDLE_TASK,
    queue=BUNDLE_QUEUE,
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=None,
)
def ingest_bundle(self: Task[[str], dict[str, Any]], job_id: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        jid = uuid.UUID(str(job_id))
    except ValueError:
        log.warning("bundle_task_bad_job_id")
        return {"job_id": None, "outcome": "skipped", "error": "invalid job id"}
    retries = int(self.request.retries or 0)
    can_retry = retries < settings.job_max_auto_retries
    lease_wait = settings.job_lease_s + LEASE_SLACK_S
    try:
        result = service_factory().run(
            jid, allow_retry=can_retry, stop_exceptions=(SoftTimeLimitExceeded,)
        )
    except Exception as exc:
        log.exception("bundle_task_error", job_id=str(jid), retries=retries)
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
