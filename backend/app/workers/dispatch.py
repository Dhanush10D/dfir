"""Enqueue worker tasks (used by the API through an injectable dependency)."""

from __future__ import annotations

import uuid

PARSE_TASK = "dfirbench.parse_evidence"
PARSE_QUEUE = "parse"
# Fail fast when the broker is down: the API marks the job failed (retryable) and answers 503.
RETRY_POLICY = {"max_retries": 2, "interval_start": 0, "interval_step": 0.5, "interval_max": 1}


def dispatch_parse(job_id: uuid.UUID) -> None:
    from app.workers.celery_app import celery_app

    celery_app.send_task(
        PARSE_TASK,
        args=[str(job_id)],
        queue=PARSE_QUEUE,
        retry=True,
        retry_policy=RETRY_POLICY,
    )


DETECT_TASK = "dfirbench.detect_case"
DETECT_QUEUE = "detect"


def dispatch_detect(job_id: uuid.UUID) -> None:
    from app.workers.celery_app import celery_app

    celery_app.send_task(
        DETECT_TASK,
        args=[str(job_id)],
        queue=DETECT_QUEUE,
        retry=True,
        retry_policy=RETRY_POLICY,
    )
