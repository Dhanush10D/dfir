"""Notes and bookmarks (guide 12.1, 15.2 "Notes, bookmarks, tags").

Notes are forensic records: every version is appended to ``note_versions`` (append-only) and the
``notes`` row is the current head. Nothing is deleted; a note is *retracted* (the history stays).
Only the author edits; the author or a case manager retracts. Edits carry ``expected_version``
and are validated against the version read under ``FOR NO KEY UPDATE`` (lost race -> 409).

Writes take ``FOR SHARE`` on the case row and re-check the case is open (case close takes
``FOR UPDATE``), the same pattern as alerts and jobs; closed cases are read-only (409). Targets
must exist *in the same case*; any cross-case id is reported as not found. Every write is audited.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import (
    AppError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from app.core.permissions import Permission, Principal
from app.db.models import (
    Alert,
    Bookmark,
    Case,
    CaseStatus,
    Entity,
    Event,
    Evidence,
    Note,
    NoteVersion,
    User,
)
from app.db.models.collaboration import TARGET_TYPES
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access

MAX_BODY = 20_000
MAX_TAGS = 16
MAX_TAG_LEN = 64
MAX_COMMENT = 2000
MAX_LIST = 500
TARGET_MODELS: dict[str, Any] = {
    "event": Event,
    "alert": Alert,
    "evidence": Evidence,
    "entity": Entity,
}


@dataclass(frozen=True)
class BookmarkView:
    bookmark: Bookmark
    user_name: str | None
    event: Event | None


def clean_tags(tags: list[str] | None) -> list[str]:
    out: list[str] = []
    for tag in tags or []:
        t = tag.strip()
        if not t:
            continue
        if len(t) > MAX_TAG_LEN or any(c.isspace() and c != " " for c in t):
            raise AppError("invalid_tags", f"Tags are 1-{MAX_TAG_LEN} characters.", 422)
        if t not in out:
            out.append(t)
    if len(out) > MAX_TAGS:
        raise AppError("invalid_tags", f"At most {MAX_TAGS} tags.", 422)
    return out


def clean_body(body: str) -> str:
    if not body or not body.strip():
        raise AppError("invalid_note", "The note is empty.", 422)
    if len(body) > MAX_BODY or "\x00" in body:
        raise AppError("invalid_note", f"Notes are at most {MAX_BODY} characters.", 422)
    return body


class _CaseWrites:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.audit = AuditService(session)

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _lock_open_case(self, case_id: uuid.UUID) -> None:
        """FOR SHARE on the case row (close takes FOR UPDATE) and re-check it is open."""
        status = self.session.execute(
            select(Case.status).where(Case.id == case_id).with_for_update(read=True)
        ).scalar_one()
        if status is CaseStatus.closed:
            self.session.rollback()
            raise InvalidStateError("The case is closed.")

    def _check_target(
        self, case_id: uuid.UUID, target_type: str | None, target_id: str | None
    ) -> tuple[str | None, str | None]:
        if target_type is None:
            if target_id is not None:
                raise AppError("invalid_target", "'target_id' needs a 'target_type'.", 422)
            return None, None
        if target_type not in TARGET_TYPES:
            raise AppError("invalid_target", "Unknown target type.", 422, {"allowed": TARGET_TYPES})
        if target_type == "case":
            if target_id not in (None, str(case_id)):
                raise NotFoundError("Target not found in this case.")
            return "case", str(case_id)
        try:
            tid = uuid.UUID(str(target_id))
        except ValueError as exc:
            raise AppError("invalid_target", "'target_id' must be a UUID.", 422) from exc
        model = TARGET_MODELS[target_type]
        found = self.session.execute(
            select(model.id).where(model.case_id == case_id, model.id == tid).limit(1)
        ).scalar_one_or_none()
        if found is None:
            raise NotFoundError("Target not found in this case.")
        return target_type, str(tid)


class NoteService(_CaseWrites):
    def list_notes(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        include_retracted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[Note], int]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        if not 1 <= limit <= MAX_LIST or offset < 0:
            raise AppError("invalid_filter", f"'limit' must be 1-{MAX_LIST}.", 422)
        conds = [Note.case_id == case_id]
        if target_type is not None:
            conds.append(Note.target_type == target_type)
        if target_id is not None:
            conds.append(Note.target_id == target_id)
        if not include_retracted:
            conds.append(Note.retracted_at.is_(None))
        total = self.session.execute(
            select(func.count()).select_from(Note).where(*conds)
        ).scalar_one()
        rows = list(
            self.session.execute(
                select(Note)
                .where(*conds)
                .order_by(Note.created_at.desc(), Note.id)
                .limit(limit)
                .offset(offset)
            ).scalars()
        )
        self.session.commit()
        return rows, int(total)

    def _load(self, principal: Principal, note_id: uuid.UUID) -> tuple[Note, CaseAccess]:
        note = self.session.get(Note, note_id)
        if note is None:
            raise NotFoundError("Note not found.")
        try:
            access = self._access(principal, note.case_id)
        except NotFoundError as exc:
            raise NotFoundError("Note not found.") from exc
        return note, access

    def get(self, principal: Principal, note_id: uuid.UUID) -> tuple[Note, list[NoteVersion]]:
        note, access = self._load(principal, note_id)
        access.require(Permission.CASE_READ)
        versions = list(
            self.session.execute(
                select(NoteVersion)
                .where(NoteVersion.note_id == note_id)
                .order_by(NoteVersion.version)
            ).scalars()
        )
        self.session.commit()
        return note, versions

    def create(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        body_md: str,
        target_type: str | None = None,
        target_id: str | None = None,
        tags: list[str] | None = None,
    ) -> Note:
        access = self._access(principal, case_id)
        access.require(Permission.INVESTIGATE)
        body = clean_body(body_md)
        tag_list = clean_tags(tags)
        self._lock_open_case(case_id)
        try:
            ttype, tid = self._check_target(case_id, target_type, target_id)
        except AppError:
            self.session.rollback()
            raise
        note = Note(
            case_id=case_id,
            author_id=principal.user_id,
            target_type=ttype,
            target_id=tid,
            body_md=body,
            tags=tag_list,
            version=1,
        )
        self.session.add(note)
        self.session.flush()
        self.session.add(
            NoteVersion(
                note_id=note.id,
                version=1,
                action="created",
                body_md=body,
                tags=tag_list,
                user_id=principal.user_id,
            )
        )
        self.audit.record(
            "note.created",
            user_id=principal.user_id,
            meta=meta,
            object_type="note",
            object_id=note.id,
            detail={"case_id": str(case_id), "target_type": ttype, "target_id": tid},
        )
        self.session.commit()
        self.session.refresh(note)
        return note

    def _lock_note(self, note_id: uuid.UUID) -> Note:
        return self.session.execute(
            select(Note)
            .where(Note.id == note_id)
            .with_for_update(key_share=True)
            .execution_options(populate_existing=True)
        ).scalar_one()

    def edit(
        self,
        principal: Principal,
        note_id: uuid.UUID,
        meta: RequestMeta,
        *,
        expected_version: int,
        body_md: str | None = None,
        tags: list[str] | None = None,
        reason: str | None = None,
    ) -> Note:
        note, access = self._load(principal, note_id)
        access.require(Permission.INVESTIGATE)
        if body_md is None and tags is None:
            raise AppError("nothing_to_update", "Give 'body_md' and/or 'tags'.", 422)
        body = clean_body(body_md) if body_md is not None else None
        tag_list = clean_tags(tags) if tags is not None else None
        self._lock_open_case(note.case_id)
        locked = self._lock_note(note_id)
        problem: AppError | None = None
        if locked.author_id != principal.user_id:
            problem = ForbiddenError("Only the author can edit a note.")
        elif locked.retracted_at is not None:
            problem = InvalidStateError("The note was retracted.")
        elif locked.version != expected_version:
            problem = ConflictError(
                "The note changed since you read it.", "stale_version", version=locked.version
            )
        if problem is not None:
            self.session.rollback()  # release the case and note row locks
            raise problem
        new_version = locked.version + 1
        if body is not None:
            locked.body_md = body
        if tag_list is not None:
            locked.tags = tag_list
        locked.version = new_version
        locked.updated_at = func.now()
        locked.updated_by = principal.user_id
        self.session.add(
            NoteVersion(
                note_id=note_id,
                version=new_version,
                action="edited",
                body_md=locked.body_md,
                tags=list(locked.tags),
                user_id=principal.user_id,
                reason=reason,
            )
        )
        self.audit.record(
            "note.edited",
            user_id=principal.user_id,
            meta=meta,
            object_type="note",
            object_id=note_id,
            detail={"case_id": str(locked.case_id), "version": new_version},
        )
        self.session.commit()
        self.session.refresh(locked)
        return locked

    def retract(
        self,
        principal: Principal,
        note_id: uuid.UUID,
        meta: RequestMeta,
        *,
        expected_version: int,
        reason: str | None = None,
    ) -> Note:
        note, access = self._load(principal, note_id)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(note.case_id)
        locked = self._lock_note(note_id)
        problem: AppError | None = None
        if (
            locked.author_id != principal.user_id
            and Permission.CASE_MANAGE not in access.permissions
        ):
            problem = ForbiddenError("Only the author or a case manager can retract a note.")
        elif locked.retracted_at is not None:
            problem = InvalidStateError("The note is already retracted.")
        elif locked.version != expected_version:
            problem = ConflictError(
                "The note changed since you read it.", "stale_version", version=locked.version
            )
        if problem is not None:
            self.session.rollback()
            raise problem
        new_version = locked.version + 1
        locked.version = new_version
        locked.retracted_at = func.now()
        locked.retracted_by = principal.user_id
        locked.updated_at = func.now()
        locked.updated_by = principal.user_id
        self.session.add(
            NoteVersion(
                note_id=note_id,
                version=new_version,
                action="retracted",
                body_md=locked.body_md,
                tags=list(locked.tags),
                user_id=principal.user_id,
                reason=reason,
            )
        )
        self.audit.record(
            "note.retracted",
            user_id=principal.user_id,
            meta=meta,
            object_type="note",
            object_id=note_id,
            detail={"case_id": str(locked.case_id), "version": new_version, "reason": reason},
        )
        self.session.commit()
        self.session.refresh(locked)
        return locked


class BookmarkService(_CaseWrites):
    def list_bookmarks(
        self, principal: Principal, case_id: uuid.UUID, *, mine: bool = False
    ) -> list[BookmarkView]:
        self._access(principal, case_id).require(Permission.INVESTIGATE)
        conds = [Bookmark.case_id == case_id]
        if mine:
            conds.append(Bookmark.user_id == principal.user_id)
        rows = self.session.execute(
            select(Bookmark, User.display_name)
            .join(User, User.id == Bookmark.user_id)
            .where(*conds)
            .order_by(Bookmark.created_at.desc(), Bookmark.id)
            .limit(MAX_LIST)
        ).all()
        event_ids = []
        for bm, _ in rows:
            if bm.target_type == "event":
                try:
                    event_ids.append(uuid.UUID(bm.target_id))
                except ValueError:
                    continue
        events = (
            {
                e.id: e
                for e in self.session.execute(
                    select(Event).where(Event.case_id == case_id, Event.id.in_(event_ids))
                ).scalars()
            }
            if event_ids
            else {}
        )
        self.session.commit()
        out = []
        for bm, name in rows:
            ev = None
            if bm.target_type == "event":
                try:
                    ev = events.get(uuid.UUID(bm.target_id))
                except ValueError:
                    ev = None
            out.append(BookmarkView(bm, name, ev))
        return out

    def create(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        meta: RequestMeta,
        *,
        target_type: str,
        target_id: str | None,
        comment: str | None = None,
    ) -> tuple[Bookmark, bool]:
        self._access(principal, case_id).require(Permission.INVESTIGATE)
        if comment is not None and len(comment) > MAX_COMMENT:
            raise AppError(
                "invalid_comment", f"Comments are at most {MAX_COMMENT} characters.", 422
            )
        self._lock_open_case(case_id)
        try:
            ttype, tid = self._check_target(case_id, target_type, target_id)
        except AppError:
            self.session.rollback()
            raise
        if ttype is None or tid is None:  # target_type is required by the schema
            self.session.rollback()
            raise AppError("invalid_target", "A bookmark needs a target.", 422)
        new_id = self.session.execute(
            pg_insert(Bookmark)
            .values(
                case_id=case_id,
                user_id=principal.user_id,
                target_type=ttype,
                target_id=tid,
                comment=comment,
            )
            .on_conflict_do_nothing(
                index_elements=["case_id", "user_id", "target_type", "target_id"]
            )
            .returning(Bookmark.id)
        ).scalar_one_or_none()
        created = new_id is not None
        if created:
            self.audit.record(
                "bookmark.created",
                user_id=principal.user_id,
                meta=meta,
                object_type="bookmark",
                object_id=new_id,
                detail={"case_id": str(case_id), "target_type": ttype, "target_id": tid},
            )
        self.session.commit()
        row = self.session.execute(
            select(Bookmark).where(
                Bookmark.case_id == case_id,
                Bookmark.user_id == principal.user_id,
                Bookmark.target_type == ttype,
                Bookmark.target_id == tid,
            )
        ).scalar_one()
        self.session.commit()
        return row, created

    def delete(
        self, principal: Principal, case_id: uuid.UUID, bookmark_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        access = self._access(principal, case_id)
        access.require(Permission.INVESTIGATE)
        self._lock_open_case(case_id)
        row = self.session.execute(
            select(Bookmark).where(Bookmark.id == bookmark_id, Bookmark.case_id == case_id)
        ).scalar_one_or_none()
        if row is None:
            self.session.rollback()
            raise NotFoundError("Bookmark not found.")
        if row.user_id != principal.user_id and Permission.CASE_MANAGE not in access.permissions:
            self.session.rollback()
            raise ForbiddenError("Only the owner or a case manager can remove a bookmark.")
        # The app role has no UPDATE on bookmarks (so no FOR UPDATE): the DELETE re-checks the
        # row atomically instead; a concurrent delete leaves nothing to return (404).
        deleted = self.session.execute(
            delete(Bookmark)
            .where(
                Bookmark.id == bookmark_id,
                Bookmark.case_id == case_id,
                Bookmark.user_id == row.user_id,
            )
            .returning(Bookmark.id)
        ).scalar_one_or_none()
        if deleted is None:
            self.session.rollback()
            raise NotFoundError("Bookmark not found.")
        self.audit.record(
            "bookmark.deleted",
            user_id=principal.user_id,
            meta=meta,
            object_type="bookmark",
            object_id=bookmark_id,
            detail={
                "case_id": str(case_id),
                "target_type": row.target_type,
                "target_id": row.target_id,
                "owner_id": str(row.user_id),
            },
        )
        self.session.commit()
