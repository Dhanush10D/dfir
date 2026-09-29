"""Notes and bookmarks (guide 15.2 "Notes, bookmarks, tags"). HTTP only; rules (versioning,
authorship, closed cases, targets in the same case) live in ``services/notes.py``."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from app.api.dependencies import Bookmarks, CurrentPrincipal, Meta, Notes
from app.schemas.analysis import (
    BookmarkCreate,
    BookmarkOut,
    NoteCreate,
    NoteDetail,
    NoteList,
    NoteOut,
    NoteRetract,
    NoteUpdate,
    NoteVersionOut,
    TargetType,
)
from app.schemas.events import EventOut
from app.services.notes import BookmarkView

router = APIRouter(tags=["notes"])


@router.get("/cases/{case_id}/notes", response_model=NoteList)
def list_notes(
    case_id: uuid.UUID,
    principal: CurrentPrincipal,
    notes: Notes,
    target_type: TargetType | None = None,
    target_id: Annotated[str | None, Query(max_length=64)] = None,
    include_retracted: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> NoteList:
    rows, total = notes.list_notes(
        principal,
        case_id,
        target_type=target_type,
        target_id=target_id,
        include_retracted=include_retracted,
        limit=limit,
        offset=offset,
    )
    return NoteList(items=[NoteOut.model_validate(n) for n in rows], total=total)


@router.post("/cases/{case_id}/notes", response_model=NoteOut, status_code=201)
def create_note(
    case_id: uuid.UUID, body: NoteCreate, principal: CurrentPrincipal, notes: Notes, meta: Meta
) -> NoteOut:
    note = notes.create(
        principal,
        case_id,
        meta,
        body_md=body.body_md,
        target_type=body.target_type,
        target_id=body.target_id,
        tags=body.tags,
    )
    return NoteOut.model_validate(note)


def _detail(note: object, versions: list[object]) -> NoteDetail:
    out = NoteOut.model_validate(note)
    return NoteDetail(
        **out.model_dump(), versions=[NoteVersionOut.model_validate(v) for v in versions]
    )


@router.get("/notes/{note_id}", response_model=NoteDetail)
def get_note(note_id: uuid.UUID, principal: CurrentPrincipal, notes: Notes) -> NoteDetail:
    note, versions = notes.get(principal, note_id)
    return _detail(note, list(versions))


@router.patch("/notes/{note_id}", response_model=NoteDetail)
def edit_note(
    note_id: uuid.UUID, body: NoteUpdate, principal: CurrentPrincipal, notes: Notes, meta: Meta
) -> NoteDetail:
    notes.edit(
        principal,
        note_id,
        meta,
        expected_version=body.expected_version,
        body_md=body.body_md,
        tags=body.tags,
        reason=body.reason,
    )
    note, versions = notes.get(principal, note_id)
    return _detail(note, list(versions))


@router.post("/notes/{note_id}/retract", response_model=NoteDetail)
def retract_note(
    note_id: uuid.UUID, body: NoteRetract, principal: CurrentPrincipal, notes: Notes, meta: Meta
) -> NoteDetail:
    notes.retract(
        principal, note_id, meta, expected_version=body.expected_version, reason=body.reason
    )
    note, versions = notes.get(principal, note_id)
    return _detail(note, list(versions))


def _bookmark(view: BookmarkView) -> BookmarkOut:
    bm = view.bookmark
    return BookmarkOut(
        id=bm.id,
        case_id=bm.case_id,
        user_id=bm.user_id,
        user_name=view.user_name,
        target_type=bm.target_type,
        target_id=bm.target_id,
        comment=bm.comment,
        created_at=bm.created_at,
        event=EventOut.model_validate(view.event) if view.event is not None else None,
    )


@router.get("/cases/{case_id}/bookmarks", response_model=list[BookmarkOut])
def list_bookmarks(
    case_id: uuid.UUID, principal: CurrentPrincipal, bookmarks: Bookmarks, mine: bool = False
) -> list[BookmarkOut]:
    return [_bookmark(v) for v in bookmarks.list_bookmarks(principal, case_id, mine=mine)]


@router.post("/cases/{case_id}/bookmarks", response_model=BookmarkOut, status_code=201)
def create_bookmark(
    case_id: uuid.UUID,
    body: BookmarkCreate,
    principal: CurrentPrincipal,
    bookmarks: Bookmarks,
    meta: Meta,
    response: Response,
) -> BookmarkOut:
    """Idempotent: 201 when created, 200 with the existing bookmark otherwise."""
    row, created = bookmarks.create(
        principal,
        case_id,
        meta,
        target_type=body.target_type,
        target_id=body.target_id,
        comment=body.comment,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return _bookmark(BookmarkView(row, principal.display_name, None))


@router.delete("/cases/{case_id}/bookmarks/{bookmark_id}", status_code=204)
def delete_bookmark(
    case_id: uuid.UUID,
    bookmark_id: uuid.UUID,
    principal: CurrentPrincipal,
    bookmarks: Bookmarks,
    meta: Meta,
) -> Response:
    bookmarks.delete(principal, case_id, bookmark_id, meta)
    return Response(status_code=204)
