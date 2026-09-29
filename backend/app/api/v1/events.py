"""Timeline API (guide 12.1, 15.2 "Events and search"): filtered, keyset-paginated events of a
case and single events with their raw record. HTTP only; logic in services/events.py."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query

from app.api.dependencies import CurrentPrincipal, Events
from app.schemas.events import EventDetail, EventOut, EventPage
from app.services.events import MAX_LIMIT, MAX_Q, EventFilter

router = APIRouter(tags=["events"])

Short = Annotated[str | None, Query(min_length=1, max_length=255)]


@router.get("/cases/{case_id}/events", response_model=EventPage)
def timeline(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    events: Events,
    start: Annotated[
        datetime | None, Query(alias="from", description="Inclusive, with zone")
    ] = None,
    end: Annotated[datetime | None, Query(alias="to", description="Inclusive, with zone")] = None,
    evidence_id: uuid.UUID | None = None,
    job_id: uuid.UUID | None = None,
    host: Short = None,
    user: Short = None,
    event_code: Short = None,
    event_category: Short = None,
    action: Short = None,
    outcome: Short = None,
    source_type: Short = None,
    ip: Annotated[str | None, Query(max_length=64, description="src_ip or dst_ip")] = None,
    q: Annotated[
        str | None, Query(max_length=MAX_Q, description="Full text (message+cmdline)")
    ] = None,
    order: Literal["asc", "desc"] = "asc",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = 100,
    cursor: Annotated[str | None, Query(max_length=256)] = None,
) -> EventPage:
    flt = EventFilter(
        start=start,
        end=end,
        evidence_id=evidence_id,
        job_id=job_id,
        host=host,
        user=user,
        event_code=event_code,
        event_category=event_category,
        action=action,
        outcome=outcome,
        source_type=source_type,
        ip=ip,
        q=q,
    )
    rows, next_cursor = events.timeline(
        principal, case_id, flt, limit=limit, cursor=cursor, order=order
    )
    return EventPage(
        items=[EventOut.model_validate(r) for r in rows], next_cursor=next_cursor, limit=limit
    )


@router.get("/cases/{case_id}/events/{event_id}", response_model=EventDetail)
def get_event(
    case_id: uuid.UUID, event_id: uuid.UUID, principal: CurrentPrincipal, events: Events
) -> EventDetail:
    return EventDetail.model_validate(events.get(principal, case_id, event_id))
