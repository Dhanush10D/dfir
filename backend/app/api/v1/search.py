"""Timeline search endpoints (guide 12.1, 12.2, 15.2 "Events and search").

HTTP only: parsing, case scope (404 across cases), caps, timeouts and audit live in
``services/search.py``.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.dependencies import CurrentPrincipal, Meta, Search, read_only
from app.schemas.analysis import (
    ContextOut,
    ContextRequest,
    ExportRequest,
    FacetsOut,
    FacetsRequest,
    FieldOut,
    HistogramOut,
    HistogramRequest,
    SearchRequest,
)
from app.schemas.events import EventOut, EventPage
from app.search.language import field_catalogue
from app.services.search import SearchParams

router = APIRouter(tags=["search"])


def _params(body: SearchRequest | HistogramRequest | FacetsRequest | ExportRequest) -> SearchParams:
    return SearchParams(query=body.query, start=body.start, end=body.end)


@router.get("/search/fields", response_model=list[FieldOut])
def search_fields(principal: CurrentPrincipal) -> list[FieldOut]:
    """Fields, types and operators of the search language (query bar hints)."""
    return [FieldOut.model_validate(f) for f in field_catalogue()]


@router.post("/cases/{case_id}/events/search", response_model=EventPage)
@read_only
def search_events(
    case_id: uuid.UUID, body: SearchRequest, principal: CurrentPrincipal, search: Search, meta: Meta
) -> EventPage:
    rows, next_cursor = search.search(
        principal,
        case_id,
        _params(body),
        meta,
        limit=body.limit,
        cursor=body.cursor,
        order=body.order,
    )
    return EventPage(
        items=[EventOut.model_validate(r) for r in rows], next_cursor=next_cursor, limit=body.limit
    )


@router.post("/cases/{case_id}/events/histogram", response_model=HistogramOut)
@read_only
def histogram(
    case_id: uuid.UUID, body: HistogramRequest, principal: CurrentPrincipal, search: Search
) -> HistogramOut:
    return HistogramOut.model_validate(
        search.histogram(principal, case_id, _params(body), buckets=body.buckets)
    )


@router.post("/cases/{case_id}/events/facets", response_model=FacetsOut)
@read_only
def facets(
    case_id: uuid.UUID, body: FacetsRequest, principal: CurrentPrincipal, search: Search
) -> FacetsOut:
    result = search.facets(principal, case_id, _params(body), fields=body.fields, size=body.size)
    return FacetsOut.model_validate({"fields": result})


@router.post("/cases/{case_id}/events/context", response_model=ContextOut)
@read_only
def context(
    case_id: uuid.UUID, body: ContextRequest, principal: CurrentPrincipal, search: Search
) -> ContextOut:
    anchor, rows = search.context(
        principal, case_id, body.event_id, minutes=body.minutes, limit=body.limit
    )
    return ContextOut(
        anchor=EventOut.model_validate(anchor), items=[EventOut.model_validate(r) for r in rows]
    )


@router.post(
    "/cases/{case_id}/events/export",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}, "application/json": {}}}},
)
@read_only
def export(
    case_id: uuid.UUID, body: ExportRequest, principal: CurrentPrincipal, search: Search, meta: Meta
) -> Response:
    """Capped export of the current query (audited with the SHA-256 of the file)."""
    result = search.export(
        principal, case_id, _params(body), meta, fmt=body.format, limit=body.limit
    )
    return Response(
        content=result.body,
        media_type=result.content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"',
            "X-Export-Rows": str(result.rows),
            "X-Export-Truncated": "true" if result.truncated else "false",
            "X-Export-SHA256": result.sha256,
            "Cache-Control": "no-store",
        },
    )
