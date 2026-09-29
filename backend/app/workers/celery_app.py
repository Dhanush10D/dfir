"""Celery application (guide 14.5).

Queues: ``default``, ``parse`` (CPU/IO heavy), ``detect`` (rule engine), ``ai``, ``reports``.
Long forensic tasks use late
acks, reject-on-worker-lost and prefetch 1 so a crashed worker never silently drops a job.

Run: ``celery -A app.workers.celery_app worker -Q default,parse,detect,ai,reports -n worker@%h``
"""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging as celery_setup_logging
from kombu import Queue

from app.config import get_settings

QUEUES = ("default", "parse", "detect", "ai", "reports")


def make_celery() -> Celery:
    settings = get_settings()
    app = Celery(
        "dfirbench",
        broker=settings.redis_url,
        backend=settings.redis_url,
        include=[
            "app.workers.tasks.system",
            "app.workers.tasks.parse",
            "app.workers.tasks.detect",
            "app.workers.tasks.bundle",
        ],
    )
    app.conf.update(
        task_default_queue="default",
        task_queues=[Queue(name) for name in QUEUES],
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_time_limit=settings.parser_timeout_s + 300,
        task_soft_time_limit=settings.parser_timeout_s,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        result_expires=24 * 3600,
        timezone="UTC",
        enable_utc=True,
        broker_connection_retry_on_startup=True,
        worker_hijack_root_logger=False,
        task_track_started=True,
    )
    return app


@celery_setup_logging.connect
def _configure_logging(**_: object) -> None:
    from app.core.logging import setup_logging

    settings = get_settings()
    setup_logging(settings.log_level, settings.log_json)


celery_app = make_celery()
