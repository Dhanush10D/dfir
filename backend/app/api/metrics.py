"""GET /metrics: Prometheus text format (guide 21.4, Phase 10).

Mounted at the root, outside ``/api/v1``: the web container proxies only ``/api/``, and the audit
middleware does not log scrapes. Disabled (404) unless ``METRICS_TOKEN`` is set; then it needs
``Authorization: Bearer <token>`` (constant-time comparison). The data comes from
``services/metrics.py``.
"""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from app.api.dependencies import AppSettings, DbSession
from app.core.exceptions import NotFoundError, UnauthenticatedError
from app.core.metrics import render
from app.deps import get_queue_inspector
from app.services.metrics import MetricsCollector, QueueInspector

router = APIRouter(tags=["metrics"])
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


@router.get("/metrics", include_in_schema=False)
def metrics(
    request: Request,
    settings: AppSettings,
    db: DbSession,
    queues: Annotated[QueueInspector | None, Depends(get_queue_inspector)],
) -> PlainTextResponse:
    token = settings.metrics_token.get_secret_value() if settings.metrics_token else ""
    if not token:
        raise NotFoundError()
    header = request.headers.get("authorization", "")
    scheme, _, given = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        given.strip().encode("utf-8"), token.encode("utf-8")
    ):
        raise UnauthenticatedError("A valid metrics token is required.", "token_invalid")
    collector = MetricsCollector(db, queues, cache_s=settings.metrics_cache_s)
    return PlainTextResponse(render(collector.families()), media_type=CONTENT_TYPE)
