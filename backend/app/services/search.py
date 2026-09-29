"""Timeline search (guide 12.1, 12.2, 15.2 "Events and search"): search, histogram, facets,
context and export over ``events``, read-only and case scoped.

* The query string is parsed by ``app.search.language`` (strict grammar, caps, field allow-list)
  and compiled by ``app.search.compile`` to bound parameters; a bad query is a 422
  ``invalid_query`` with the character position.
* Every statement runs under ``SET LOCAL statement_timeout`` (``SEARCH_TIMEOUT_MS``); a timeout is
  a 422 ``query_timeout`` (narrow the time range or the query).
* Facets and histograms are bounded (fields, values per field, buckets, series); the histogram
  interval comes from a fixed ladder so buckets are aligned and predictable.
* Searches and exports are written to the audit trail (guide 12.2: "log queries").
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import ColumnElement, func, literal, select, true, tuple_
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.config import Settings
from app.core.exceptions import AppError, NotFoundError
from app.core.permissions import Permission, Principal
from app.db.models import Event
from app.search.compile import to_sql
from app.search.language import QueryError, parse
from app.services.audit import AuditService, RequestMeta
from app.services.authz import CaseAccess, load_case_access
from app.services.events import MAX_LIMIT, decode_cursor, encode_cursor

Order = Literal["asc", "desc"]
FACET_FIELDS: dict[str, Any] = {
    "host": Event.host,
    "user": Event.user,
    "source_type": Event.source_type,
    "event_code": Event.event_code,
    "event_category": Event.event_category,
    "action": Event.action,
    "outcome": Event.outcome,
    "process_name": Event.process_name,
    "src_ip": Event.src_ip,
    "dst_ip": Event.dst_ip,
    "dst_port": Event.dst_port,
    "protocol": Event.protocol,
    "parser_name": Event.parser_name,
    "file_hash": Event.file_hash,
    "attack_tags": Event.attack_tags,
    "tags": Event.tags,
}
ARRAY_FACETS = frozenset({"attack_tags", "tags"})
MAX_FACET_FIELDS = 8
MAX_FACET_SIZE = 50
MIN_BUCKETS, MAX_BUCKETS = 10, 200
MAX_SERIES = 12
# Histogram intervals (seconds): 1s ... 1 year.
LADDER = (
    1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 10800, 21600, 43200,
    86400, 604800, 2592000, 7776000, 31536000,
)  # fmt: skip
ORIGIN = datetime(2000, 1, 3, tzinfo=UTC)  # a Monday: weekly buckets start on Mondays
EXPORT_COLUMNS = (
    "id", "ts", "ts_original", "source_type", "source_file", "source_record_id", "host", "user",
    "event_code", "event_category", "action", "outcome", "process_name", "pid", "ppid", "cmdline",
    "file_path", "file_hash", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "registry_key", "message", "attack_tags", "tags", "evidence_id", "parser_name",
    "parser_version",
)  # fmt: skip
# Full-width forms too: some spreadsheets treat them as formula starts.
FULLWIDTH_FORMULA_PREFIXES = tuple(chr(c) for c in (0xFF1D, 0xFF0B, 0xFF0D, 0xFF20))
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", *FULLWIDTH_FORMULA_PREFIXES)
MAX_CONTEXT_MINUTES = 1440


def _bad(code: str, message: str, **details: Any) -> AppError:
    return AppError(code, message, 422, details=details)


@dataclass(frozen=True)
class SearchParams:
    query: str | None = None
    start: datetime | None = None
    end: datetime | None = None

    def validate(self) -> SearchParams:
        for name in ("start", "end"):
            value = getattr(self, name)
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise _bad(
                    "invalid_filter",
                    f"'{'from' if name == 'start' else 'to'}' needs a timezone.",
                    field=name,
                )
        if self.start and self.end and self.start > self.end:
            raise _bad("invalid_filter", "'from' must not be after 'to'.")
        return self


@dataclass(frozen=True)
class ExportResult:
    filename: str
    content_type: str
    body: bytes
    rows: int
    truncated: bool
    sha256: str


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def csv_cell(value: Any) -> str:
    """Text for a CSV cell; neutralises spreadsheet formulas (CSV injection)."""
    if value is None:
        return ""
    if isinstance(value, list):
        text = ";".join(str(v) for v in value)
    elif isinstance(value, datetime):
        text = _iso(value) or ""
    else:
        text = str(value)
    if text.startswith(FORMULA_PREFIXES) or text.lstrip().startswith(FORMULA_PREFIXES):
        text = "'" + text
    return text


def pick_interval(span_s: float, buckets: int) -> int:
    for step in LADDER:
        if span_s / step <= buckets:
            return step
    return math.ceil(span_s / buckets / 86400.0) * 86400


def event_dict(row: Event) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in EXPORT_COLUMNS:
        value = getattr(row, name)
        if isinstance(value, datetime):
            value = _iso(value)
        elif isinstance(value, uuid.UUID) or (value is not None and name in ("src_ip", "dst_ip")):
            value = str(value)
        out[name] = value
    return out


class SearchService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings
        self.audit = AuditService(session)

    # ------------------------------------------------------------------ helpers

    def _access(self, principal: Principal, case_id: uuid.UUID) -> CaseAccess:
        return load_case_access(
            self.session, principal, case_id, auditor_all_cases=self.settings.auditor_all_cases
        )

    def _conditions(self, case_id: uuid.UUID, params: SearchParams) -> list[ColumnElement[bool]]:
        params.validate()
        try:
            node = parse(params.query)
        except QueryError as exc:
            raise _bad("invalid_query", exc.message, position=exc.position) from exc
        conds: list[ColumnElement[bool]] = [Event.case_id == case_id]
        if params.start is not None:
            conds.append(Event.ts >= params.start)
        if params.end is not None:
            conds.append(Event.ts <= params.end)
        if node is not None:
            conds.append(to_sql(node))
        return conds

    def _set_timeout(self) -> None:
        self.session.execute(
            select(func.set_config("statement_timeout", str(self.settings.search_timeout_ms), True))
        )

    def _execute(self, stmt: Any) -> Any:
        try:
            return self.session.execute(stmt)
        except OperationalError as exc:
            self.session.rollback()
            if getattr(exc.orig, "sqlstate", None) == "57014":
                raise _bad(
                    "query_timeout",
                    "The search took too long; narrow the time range or the query.",
                    timeout_ms=self.settings.search_timeout_ms,
                ) from exc
            raise

    # ------------------------------------------------------------------ search

    def search(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        params: SearchParams,
        meta: RequestMeta | None = None,
        *,
        limit: int = 100,
        cursor: str | None = None,
        order: Order = "asc",
    ) -> tuple[list[Event], str | None]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        if not 1 <= limit <= MAX_LIMIT:
            raise _bad("invalid_filter", f"'limit' must be 1-{MAX_LIMIT}.", field="limit")
        conds = self._conditions(case_id, params)
        key = tuple_(Event.ts, Event.id)
        if cursor:
            ts, event_id = decode_cursor(cursor, order)
            conds.append(
                key > tuple_(ts, event_id) if order == "asc" else key < tuple_(ts, event_id)
            )
        stmt = select(Event).where(*conds)
        if order == "asc":
            stmt = stmt.order_by(Event.ts.asc(), Event.id.asc())
        else:
            stmt = stmt.order_by(Event.ts.desc(), Event.id.desc())
        self._set_timeout()
        rows = list(self._execute(stmt.limit(limit + 1)).scalars())
        next_cursor = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = encode_cursor(rows[-1].ts, rows[-1].id, order)
        self.audit.record(
            "events.search",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={
                "query": (params.query or "")[:2000],
                "from": _iso(params.start),
                "to": _iso(params.end),
                "page": bool(cursor),
                "returned": len(rows),
            },
        )
        self.session.commit()
        return rows, next_cursor

    # ------------------------------------------------------------------ histogram

    def histogram(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        params: SearchParams,
        *,
        buckets: int = 60,
    ) -> dict[str, Any]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        if not MIN_BUCKETS <= buckets <= MAX_BUCKETS:
            raise _bad("invalid_filter", f"'buckets' must be {MIN_BUCKETS}-{MAX_BUCKETS}.")
        conds = self._conditions(case_id, params)
        self._set_timeout()
        start, end = params.start, params.end
        if start is None or end is None:
            lo, hi = self._execute(
                select(func.min(Event.ts), func.max(Event.ts)).where(*conds)
            ).one()
            start = start or lo
            end = end or hi
        empty: dict[str, Any] = {
            "interval_seconds": 0,
            "from": _iso(start),
            "to": _iso(end),
            "buckets": [],
        }
        if start is None or end is None or start > end:
            self.session.commit()
            return {**empty, "series": [], "total": 0}
        span = max((end - start).total_seconds(), 1.0)
        step = pick_interval(span, buckets)
        stride = timedelta(seconds=step)
        bucket = func.date_bin(literal(stride), Event.ts, literal(ORIGIN)).label("bucket")
        stmt = (
            select(bucket, Event.source_type, func.count().label("n"))
            .where(*conds, Event.ts >= start, Event.ts <= end)
            .group_by(bucket, Event.source_type)
            .order_by(bucket)
            .limit((buckets + 2) * 64)
        )
        rows = self._execute(stmt).all()
        self.session.commit()
        totals: dict[str, int] = {}
        for r in rows:
            totals[r.source_type] = totals.get(r.source_type, 0) + int(r.n)
        top = sorted(totals, key=lambda s: (-totals[s], s))[:MAX_SERIES]
        series = [*top, "other"] if len(totals) > MAX_SERIES else top
        first = ORIGIN + stride * ((start - ORIGIN) // stride)
        count = int((end - first) // stride) + 1
        slots: dict[datetime, dict[str, int]] = {first + stride * i: {} for i in range(count)}
        for r in rows:
            name = r.source_type if r.source_type in top else "other"
            slot = slots.setdefault(r.bucket, {})
            slot[name] = slot.get(name, 0) + int(r.n)
        out = [
            {"ts": _iso(ts), "count": sum(by.values()), "by": by}
            for ts, by in sorted(slots.items())
        ]
        return {
            "interval_seconds": step,
            "from": _iso(start),
            "to": _iso(end),
            "buckets": out,
            "series": series,
            "total": sum(totals.values()),
        }

    # ------------------------------------------------------------------ facets

    def facets(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        params: SearchParams,
        *,
        fields: list[str],
        size: int = 10,
    ) -> dict[str, list[dict[str, Any]]]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        wanted = list(dict.fromkeys(fields))
        if not 1 <= len(wanted) <= MAX_FACET_FIELDS:
            raise _bad("invalid_filter", f"Give 1-{MAX_FACET_FIELDS} facet fields.")
        unknown = [f for f in wanted if f not in FACET_FIELDS]
        if unknown:
            raise _bad(
                "invalid_filter",
                "Unknown facet fields.",
                fields=unknown,
                allowed=list(FACET_FIELDS),
            )
        if not 1 <= size <= MAX_FACET_SIZE:
            raise _bad("invalid_filter", f"'size' must be 1-{MAX_FACET_SIZE}.")
        conds = self._conditions(case_id, params)
        self._set_timeout()
        result: dict[str, list[dict[str, Any]]] = {}
        for name in wanted:
            column = FACET_FIELDS[name]
            if name in ARRAY_FACETS:
                tv = func.unnest(column).table_valued("value").render_derived(name="fv")
                value = tv.c.value
                stmt = select(value, func.count().label("n")).select_from(Event).join(tv, true())
            else:
                value = column
                stmt = select(value, func.count().label("n")).where(column.is_not(None))
            stmt = (
                stmt.where(*conds).group_by(value).order_by(func.count().desc(), value).limit(size)
            )
            rows = self._execute(stmt).all()
            result[name] = [{"value": str(r[0]), "count": int(r.n)} for r in rows]
        self.session.commit()
        return result

    # ------------------------------------------------------------------ context

    def context(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        event_id: uuid.UUID,
        *,
        minutes: int = 5,
        limit: int = 200,
    ) -> tuple[Event, list[Event]]:
        self._access(principal, case_id).require(Permission.CASE_READ)
        if not 1 <= minutes <= MAX_CONTEXT_MINUTES or not 1 <= limit <= MAX_LIMIT:
            raise _bad("invalid_filter", "'minutes' 1-1440 and 'limit' 1-500.")
        anchor = self.session.execute(
            select(Event).where(Event.case_id == case_id, Event.id == event_id)
        ).scalar_one_or_none()
        if anchor is None:
            self.session.commit()
            raise NotFoundError("Event not found.")
        window = timedelta(minutes=minutes)
        conds: list[ColumnElement[bool]] = [
            Event.case_id == case_id,
            Event.ts >= anchor.ts - window,
            Event.ts <= anchor.ts + window,
        ]
        if anchor.host is not None:
            conds.append(func.lower(Event.host) == func.lower(literal(anchor.host)))
        elif anchor.evidence_id is not None:
            conds.append(Event.evidence_id == anchor.evidence_id)
        self._set_timeout()
        rows = list(
            self._execute(
                select(Event).where(*conds).order_by(Event.ts, Event.id).limit(limit)
            ).scalars()
        )
        self.session.commit()
        return anchor, rows

    # ------------------------------------------------------------------ export

    def export(
        self,
        principal: Principal,
        case_id: uuid.UUID,
        params: SearchParams,
        meta: RequestMeta | None = None,
        *,
        fmt: Literal["csv", "json"] = "csv",
        limit: int | None = None,
    ) -> ExportResult:
        access = self._access(principal, case_id)
        access.require(Permission.INVESTIGATE)
        cap = self.settings.export_max_rows
        limit = cap if limit is None else limit
        if not 1 <= limit <= cap:
            raise _bad("invalid_filter", f"'limit' must be 1-{cap}.", field="limit")
        conds = self._conditions(case_id, params)
        self._set_timeout()
        rows = list(
            self._execute(
                select(Event).where(*conds).order_by(Event.ts, Event.id).limit(limit + 1)
            ).scalars()
        )
        truncated = len(rows) > limit
        rows = rows[:limit]
        records = [event_dict(r) for r in rows]
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\r\n")
            writer.writerow(EXPORT_COLUMNS)
            for rec in records:
                writer.writerow([csv_cell(rec[c]) for c in EXPORT_COLUMNS])
            body = buf.getvalue().encode("utf-8")
            content_type = "text/csv; charset=utf-8"
        else:
            body = json.dumps(records, ensure_ascii=False, indent=1).encode("utf-8")
            content_type = "application/json"
        digest = hashlib.sha256(body).hexdigest()
        filename = f"{access.case.case_number}-events.{fmt}"
        self.audit.record(
            "events.exported",
            user_id=principal.user_id,
            meta=meta,
            object_type="case",
            object_id=case_id,
            detail={
                "query": (params.query or "")[:2000],
                "from": _iso(params.start),
                "to": _iso(params.end),
                "format": fmt,
                "rows": len(records),
                "truncated": truncated,
                "sha256": digest,
            },
        )
        self.session.commit()
        return ExportResult(filename, content_type, body, len(records), truncated, digest)
