"""SIEM/EDR webhook ingest (guide 15.2 ``POST /ingest/webhook/{integration}``). HTTP only.

No user session: the delivery is authenticated by its HMAC signature (``services/ingest.py``).
The body is read here as a stream and the size cap is enforced *before* it is buffered: first
from ``Content-Length``, then while reading (a sender can lie about the length or send chunked).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Request
from starlette.concurrency import run_in_threadpool

from app.api.dependencies import AppSettings, IngestSvc
from app.core.exceptions import AppError
from app.integrations import webhooks
from app.schemas.integrations import IngestResult

router = APIRouter(tags=["ingest"])


def _too_large(limit: int) -> AppError:
    return AppError("payload_too_large", f"The body is larger than {limit} bytes.", 413)


async def read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None:
        if not declared.isdigit():
            raise AppError("bad_request", "Invalid Content-Length.", 400)
        if int(declared) > limit:
            raise _too_large(limit)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise _too_large(limit)
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/ingest/webhook/{integration_id}", response_model=IngestResult)
async def ingest_webhook(
    integration_id: Annotated[str, Path(max_length=64)],
    request: Request,
    ingest: IngestSvc,
    settings: AppSettings,
) -> IngestResult:
    """Alerts from a configured SIEM/EDR source. 401 for any authentication failure."""
    body = await read_capped(request, settings.ingest_max_body_kb * 1024)
    outcome = await run_in_threadpool(
        ingest.ingest,
        integration_id,
        timestamp=request.headers.get(webhooks.HEADER_TIMESTAMP),
        signature=request.headers.get(webhooks.HEADER_SIGNATURE),
        body=body,
        ip=request.client.host if request.client else None,
    )
    return IngestResult(
        accepted=True,
        duplicate=outcome.duplicate,
        items=outcome.items,
        created=outcome.created,
        updated=outcome.updated,
        errors=outcome.errors,
        error_reasons=outcome.error_reasons,
    )
