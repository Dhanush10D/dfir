"""Search language (guide 12.2): grammar, caps, field allow-list, errors, SQL compilation."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app.core.exceptions import AppError
from app.search.compile import like_pattern, to_sql
from app.search.language import (
    MAX_DEPTH,
    MAX_TERMS,
    And,
    FreeText,
    Not,
    Or,
    QueryError,
    Term,
    field_catalogue,
    parse,
    quote_value,
)
from app.services.search import SearchService, csv_cell, pick_interval


def sql(query: str) -> tuple[str, dict[str, Any]]:
    node = parse(query)
    assert node is not None
    compiled = to_sql(node).compile(dialect=postgresql.dialect())
    return str(compiled), dict(compiled.params)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("event_code:4625", Term("event_code", "eq", "4625")),
        ("host:WS-042", Term("host", "eq", "WS-042")),
        ('cmdline:"a b"', Term("cmdline", "eq", "a b")),
        ("cmdline:*-enc*", Term("cmdline", "wildcard", "*-enc*")),
        ("user:*", Term("user", "exists")),
        ('user:"*"', Term("user", "eq", "*")),
        ("src_ip:203.0.113.0/24", Term("src_ip", "cidr", "203.0.113.0/24")),
        ("ip:2001:db8::1", Term("ip", "eq", "2001:db8::1")),
        ("pid:4", Term("pid", "eq", "4")),
        ("pid:[1 TO *]", Term("pid", "range", low="1")),
        (
            "ts:[2026-09-01T00:00:00Z TO 2026-09-02T00:00:00+02:00]",
            Term("ts", "range", low="2026-09-01T00:00:00+00:00", high="2026-09-02T00:00:00+02:00"),
        ),
        ("attack_tags:t1059.001", Term("attack_tags", "eq", "T1059.001")),
        ("attack_tags:t1059*", Term("attack_tags", "wildcard", "T1059*")),
        ("HOST:x", Term("host", "eq", "x")),
        ("mimikatz", FreeText("mimikatz")),
        ('"failed password"', FreeText("failed password", phrase=True)),
        ('file_path:"C:\\\\Windows\\\\x \\"q\\""', Term("file_path", "eq", 'C:\\Windows\\x "q"')),
    ],
)
def test_terms(query: str, expected: Any) -> None:
    assert parse(query) == expected


def test_boolean_structure_and_precedence() -> None:
    a, b, c = (Term("host", "eq", x) for x in "abc")
    assert parse("host:a host:b") == And((a, b))
    assert parse("host:a AND host:b OR host:c") == Or((And((a, b)), c))
    assert parse("host:a AND (host:b OR host:c)") == And((a, Or((b, c))))
    assert parse("NOT host:a") == Not(a)
    assert parse("NOT NOT host:a") == Not(Not(a))
    assert parse("host:a and") == And((a, FreeText("and")))  # lower-case words are text
    assert parse("") is None and parse("   ") is None and parse(None) is None


@pytest.mark.parametrize(
    ("query", "position"),
    [
        ("host:", 5),
        ("host: ", 5),
        ("nosuch:x", 0),
        ("host:a AND", 10),
        ("AND host:a", 0),
        ("host:a OR OR host:b", 10),
        ("(host:a", 0),
        ("host:a)", 6),
        ('"unterminated', 0),
        ("cmdline:*ab", 8),
        ("cmdline:**", 8),
        ("cmdline:*a*b*c*d*e*", 8),
        ("pid:abc", 4),
        ("pid:99999999999", 4),
        ("pid:*x", 4),
        ("src_ip:300.1.1.1", 7),
        ("src_ip:10.0.0.0/99", 7),
        ("src_ip:10.*", 7),
        ("ts:2026-01-01", 3),
        ("ts:[2026-01-01T00:00:00 TO *]", 3),
        ("ts:[bad TO *]", 3),
        ("ts:[* TO *]", 3),
        ("ts:[2026-02-01T00:00:00Z TO 2026-01-01T00:00:00Z]", 3),
        ("pid:[5 TO 1]", 4),
        ("host:[a TO b]", 5),
        ("host:[a b]", 5),
        ("pid:[1 TO", 4),
        ("evidence_id:nope", 12),
        ("attack_tags:X1", 12),
        ("mimi*", 0),
        ("TO", 0),
        ("host:a\x00", 5),
    ],
)
def test_errors_have_positions(query: str, position: int) -> None:
    with pytest.raises(QueryError) as info:
        parse(query)
    assert info.value.position == position, info.value.message


def test_caps() -> None:
    with pytest.raises(QueryError, match="too long"):
        parse("a" * 2001)
    with pytest.raises(QueryError, match="nested too deeply"):
        parse("(" * (MAX_DEPTH + 1) + "a" + ")" * (MAX_DEPTH + 1))
    with pytest.raises(QueryError, match="nested too deeply"):
        parse("NOT " * (MAX_DEPTH + 1) + "a")
    assert parse("(" * (MAX_DEPTH - 1) + "a" + ")" * (MAX_DEPTH - 1)) == FreeText("a")
    with pytest.raises(QueryError, match="Too many terms"):
        parse(" ".join(["a"] * (MAX_TERMS + 1)))
    with pytest.raises(QueryError, match="Value too long"):
        parse("host:" + "x" * 513)


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=300))
def test_parser_only_raises_query_error(query: str) -> None:
    try:
        node = parse(query)
    except QueryError:
        return
    if node is not None:
        to_sql(node).compile(dialect=postgresql.dialect())


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=st.characters(blacklist_characters="\x00"), min_size=1, max_size=100))
def test_quoted_values_round_trip_as_bound_parameters(value: str) -> None:
    node = parse(f"host:{quote_value(value)}")
    assert node == Term("host", "eq", value)
    text, params = sql(f"host:{quote_value(value)}")
    assert list(params.values()) == [value]
    assert text == sql('host:"x"')[0]  # the SQL text never depends on the value


def test_compiled_sql_uses_bound_parameters_only() -> None:
    text, params = sql(
        'host:"x\' OR 1=1 --" AND cmdline:*%_\\* AND NOT user:SYSTEM AND src_ip:10.0.0.0/8 '
        'AND attack_tags:T1059* AND pid:[1 TO 5] AND "drop table"'
    )
    assert "OR 1=1" not in text and "drop table" not in text
    assert "x' OR 1=1 --" in params.values()
    assert "%\\%\\_\\\\%" in params.values()  # wildcard escaping
    assert "NOT coalesce(" in text and "<<=" in text and "unnest(events.attack_tags)" in text
    assert "phraseto_tsquery" in text


def test_like_pattern_escaping() -> None:
    assert like_pattern("*a%b_c\\d*") == "%a\\%b\\_c\\\\d%"


def test_field_catalogue_and_quote() -> None:
    names = {f["name"] for f in field_catalogue()}
    assert {"host", "ts", "ip", "attack_tags"} <= names and "raw" not in names
    assert quote_value('a"b\\c') == '"a\\"b\\\\c"'


def test_csv_cell_neutralises_formulas() -> None:
    assert csv_cell("=1+1") == "'=1+1"
    assert csv_cell("+1") == "'+1" and csv_cell("-1") == "'-1" and csv_cell("@x") == "'@x"
    assert csv_cell("\tx") == "'\tx" and csv_cell("ok") == "ok" and csv_cell(None) == ""
    assert csv_cell(["T1", "T2"]) == "T1;T2"
    assert csv_cell("\n=1") == "'\n=1" and csv_cell("  =1") == "'  =1"
    fullwidth_eq = chr(0xFF1D) + "1"
    assert csv_cell(fullwidth_eq) == "'" + fullwidth_eq and csv_cell(" ok") == " ok"


def test_histogram_interval_ladder() -> None:
    assert pick_interval(3600, 60) == 60
    assert pick_interval(59, 60) == 1
    assert pick_interval(86400 * 365 * 13, 20) == 31536000
    assert pick_interval(86400 * 365 * 1000, 10) % 86400 == 0


def test_statement_timeout_maps_to_422() -> None:
    class Session:
        rolled_back = False

        def execute(self, stmt: Any) -> Any:
            raise OperationalError("SELECT", {}, SimpleNamespace(sqlstate="57014"))  # type: ignore[arg-type]

        def rollback(self) -> None:
            self.rolled_back = True

    session = Session()
    svc = SearchService(session, Settings(_env_file=None))  # type: ignore[arg-type,call-arg]
    with pytest.raises(AppError) as info:
        svc._execute("x")
    assert info.value.code == "query_timeout" and info.value.status_code == 422
    assert session.rolled_back


def test_bare_hash_pivot_matches_sysmon_prefixed_values() -> None:
    _, params = sql('file_hash:"' + "ab" * 32 + '"')
    assert "sha256:" + "ab" * 32 in str(params) and "ab" * 32 in str(params)
