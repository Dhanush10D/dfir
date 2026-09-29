"""Timeline queries over ``events`` (guide 12.1, 15.2 "Events and search"), read-only.

Same object-level rule as every case resource: a case the caller cannot read is 404. Pagination is
keyset on ``(ts, id)`` (stable under concurrent inserts, no OFFSET scans); the cursor is an opaque
base64url JSON ``{"ts", "id", "o"}`` that is validated strictly. Filters are validated here too
(timezone-aware bounds, IP syntax, bounded lengths), so bad input is a 422, never a 500.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import ColumnElement, Select, func, literal_column, or_, select, tuple_
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Event
from app.services.authz import load_case_access

MAX_LIMIT = 500
MAX_Q = 200
Order = Literal["asc", "desc"]
# Same expression as the ix_events_fts GIN index, written literally so the planner can use it.
FTS: ColumnElement[Any] = literal_column(
    "to_tsvector('simple'::regconfig, (COALESCE(events.message, ''::text) || ' '::text) "
    "|| COALESCE(events.cmdline, ''::text))"
)


def _bad(message: str, **details: Any) -> AppError:
    return AppError("invalid_filter", message, 422, details=details)


@dataclass(frozen=True)
class EventFilter:
    start: datetime | None = None
    end: datetime | None = None
    evidence_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    host: str | None = None
    user: str | None = None
    event_code: str | None = None
    event_category: str | None = None
    action: str | None = None
    outcome: str | None = None
    source_type: str | None = None
    ip: str | None = None
    q: str | None = None

    def validate(self) -> EventFilter:
        for name in ("start", "end"):
            value = getattr(self, name)
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise _bad(f"'{name}' needs a timezone (e.g. 2026-09-14T08:00:00Z).", field=name)
        if self.start and self.end and self.start > self.end:
            raise _bad("'from' must not be after 'to'.")
        if self.ip is not None:
            try:
                ipaddress.ip_address(self.ip)
            except ValueError as exc:
                raise _bad("'ip' is not a valid IP address.", field="ip") from exc
        if self.q is not None and (not self.q.strip() or len(self.q) > MAX_Q):
            raise _bad(f"'q' must be 1-{MAX_Q} characters.", field="q")
        return self


def encode_cursor(ts: datetime, event_id: uuid.UUID, order: Order) -> str:
    body = json.dumps({"ts": ts.isoformat(), "id": str(event_id), "o": order}).encode()
    return base64.urlsafe_b64encode(body).decode().rstrip("=")


def decode_cursor(cursor: str, order: Order) -> tuple[datetime, uuid.UUID]:
    try:
        if len(cursor) > 256:
            raise ValueError("cursor too long")
        padded = cursor + "=" * (-len(cursor) % 4)
        body = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
        if not isinstance(body, dict) or set(body) != {"ts", "id", "o"}:
            raise ValueError("cursor fields")
        ts = datetime.fromisoformat(body["ts"])
        if ts.tzinfo is None:
            raise ValueError("naive cursor")
        event_id = uuid.UUID(body["id"])
        if body["o"] != order:
            raise ValueError("order changed")
    except (ValueError, TypeError, binascii.Error, UnicodeEncodeError) as exc:
        raise _bad("Invalid or mismatched cursor.", field="cursor") from exc
    return ts, event_id


class EventService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def _read_access(self, principal: Principal, case_id: uuid.UUID) -> None:
        access = load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )
        access.require(Permission.CASE_READ)

    def timeline(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        flt: EventFilter,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order: Order = "asc",
    ) -> tuple[list[Event], str | None]:
        self._read_access(principal, case_id)
        flt.validate()
        if not 1 <= limit <= MAX_LIMIT:
            raise _bad(f"'limit' must be 1-{MAX_LIMIT}.", field="limit")
        stmt = self._filtered(select(Event).where(Event.case_id == case_id), flt)
        key = tuple_(Event.ts, Event.id)
        if cursor:
            ts, event_id = decode_cursor(cursor, order)
            after = tuple_(ts, event_id)
            stmt = stmt.where(key > after if order == "asc" else key < after)
        if order == "asc":
            stmt = stmt.order_by(Event.ts.asc(), Event.id.asc())
        else:
            stmt = stmt.order_by(Event.ts.desc(), Event.id.desc())
        rows = list(self.session.execute(stmt.limit(limit + 1)).scalars())
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            last = rows[-1]
            next_cursor = encode_cursor(last.ts, last.id, order)
        self.session.commit()
        return rows, next_cursor

    @staticmethod
    def _filtered(stmt: Select[Event], flt: EventFilter) -> Select[Event]:
        if flt.start is not None:
            stmt = stmt.where(Event.ts >= flt.start)
        if flt.end is not None:
            stmt = stmt.where(Event.ts <= flt.end)
        exact = {
            Event.evidence_id: flt.evidence_id,
            Event.job_id: flt.job_id,
            Event.host: flt.host,
            Event.user: flt.user,
            Event.event_code: flt.event_code,
            Event.event_category: flt.event_category,
            Event.action: flt.action,
            Event.outcome: flt.outcome,
            Event.source_type: flt.source_type,
        }
        for column, value in exact.items():
            if value is not None:
                stmt = stmt.where(column == value)
        if flt.ip is not None:
            stmt = stmt.where(or_(Event.src_ip == flt.ip, Event.dst_ip == flt.ip))
        if flt.q is not None:
            query = func.plainto_tsquery(literal_column("'simple'::regconfig"), flt.q)
            stmt = stmt.where(FTS.op("@@")(query))
        return stmt

    def get(self, principal: Principal, case_id: uuid.UUID, event_id: uuid.UUID) -> Event:
        self._read_access(principal, case_id)
        row = self.session.execute(
            select(Event).where(Event.case_id == case_id, Event.id == event_id)
        ).scalar_one_or_none()
        self.session.commit()
        if row is None:
            raise NotFoundError("Event not found.")
        return row
