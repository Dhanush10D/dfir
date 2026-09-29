"""Compile a search AST to a SQLAlchemy boolean expression over ``events`` (guide 12.2).

Every value becomes a bound parameter; column names come only from the :data:`FIELDS`
allow-list mapping below. ``NOT`` is null-safe (``NOT coalesce(x, false)``) so ``NOT user:SYSTEM``
also returns events without a user.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    INTEGER,
    ColumnElement,
    and_,
    any_,
    cast,
    exists,
    false,
    func,
    literal,
    literal_column,
    not_,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, UUID

from app.db.models import Event
from app.search.language import FIELDS, And, FreeText, Node, Not, Or, Term

COLUMNS: dict[str, Any] = {
    name: getattr(Event, name) for name in FIELDS if name not in ("ip",) and hasattr(Event, name)
}
# Same expression as the ix_events_fts GIN index, written literally so the planner can use it.
FTS: ColumnElement[Any] = literal_column(
    "to_tsvector('simple'::regconfig, (COALESCE(events.message, ''::text) || ' '::text) "
    "|| COALESCE(events.cmdline, ''::text))"
)
SIMPLE: ColumnElement[Any] = literal_column("'simple'::regconfig")


def like_pattern(value: str) -> str:
    """Wildcard value -> ILIKE pattern with ``\\``, ``%`` and ``_`` escaped; ``*`` -> ``%``."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


def _text(term: Term, column: Any) -> ColumnElement[bool]:
    if term.op == "exists":
        return column.is_not(None)  # type: ignore[no-any-return]
    assert term.value is not None
    if term.op == "wildcard":
        return column.ilike(like_pattern(term.value), escape="\\")  # type: ignore[no-any-return]
    return func.lower(column) == func.lower(literal(term.value))


def _int(term: Term, column: Any) -> ColumnElement[bool]:
    if term.op == "exists":
        return column.is_not(None)  # type: ignore[no-any-return]
    if term.op == "range":
        conds = []
        if term.low is not None:
            conds.append(column >= literal(int(term.low), INTEGER))
        if term.high is not None:
            conds.append(column <= literal(int(term.high), INTEGER))
        return and_(*conds)
    assert term.value is not None
    return column == literal(int(term.value), INTEGER)  # type: ignore[no-any-return]


def _ip_one(term: Term, column: Any) -> ColumnElement[bool]:
    if term.op == "exists":
        return column.is_not(None)  # type: ignore[no-any-return]
    if term.op == "cidr":
        return column.op("<<=")(cast(literal(term.value), CIDR))  # type: ignore[no-any-return]
    return column == cast(literal(term.value), INET)  # type: ignore[no-any-return]


def _array(term: Term, column: Any) -> ColumnElement[bool]:
    if term.op == "exists":
        return func.cardinality(column) > 0
    assert term.value is not None
    if term.op == "wildcard":
        tag = func.unnest(column).table_valued("tag").render_derived(name="t")
        return exists(
            select(literal(1))
            .select_from(tag)
            .where(tag.c.tag.ilike(like_pattern(term.value), escape="\\"))
        )
    return literal(term.value) == any_(column)


def _term(term: Term) -> ColumnElement[bool]:
    kind = FIELDS[term.field]
    if term.field == "ip":
        return or_(_ip_one(term, Event.src_ip), _ip_one(term, Event.dst_ip))
    column = COLUMNS[term.field]
    if kind == "text":
        return _text(term, column)
    if kind == "int":
        return _int(term, column)
    if kind == "ip":
        return _ip_one(term, column)
    if kind == "array":
        return _array(term, column)
    if kind == "uuid":
        return column == cast(literal(term.value), UUID(as_uuid=True))  # type: ignore[no-any-return]
    # ts: range only (the parser guarantees it)
    conds = []
    if term.low is not None:
        conds.append(Event.ts >= literal(datetime.fromisoformat(term.low)))
    if term.high is not None:
        conds.append(Event.ts <= literal(datetime.fromisoformat(term.high)))
    return and_(*conds)


def to_sql(node: Node) -> ColumnElement[bool]:
    if isinstance(node, Term):
        return _term(node)
    if isinstance(node, FreeText):
        fn = func.phraseto_tsquery if node.phrase else func.plainto_tsquery
        return FTS.op("@@")(fn(SIMPLE, literal(node.text)))
    if isinstance(node, Not):
        return not_(func.coalesce(to_sql(node.child), false()))
    if isinstance(node, And):
        return and_(*(to_sql(c) for c in node.children))
    if isinstance(node, Or):
        return or_(*(to_sql(c) for c in node.children))
    raise TypeError(f"unknown node {type(node).__name__}")  # pragma: no cover
