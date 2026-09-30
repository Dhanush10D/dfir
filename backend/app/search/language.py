"""Search language parser (guide 12.2). Hand-written recursive descent with hard caps.

Grammar (keywords are upper case; adjacency means AND)::

    query  := or
    or     := and ("OR" and)*
    and    := unary (["AND"] unary)*
    unary  := "NOT" unary | "(" or ")" | field ":" value | field ":" "[" bound "TO" bound "]" | text
    value  := quoted | word          -- "*" is a wildcard in words; field:* means "field exists"
    bound  := quoted | word | "*"    -- "*" is an open end

Only fields from :data:`FIELDS` are accepted. The parser only builds an AST; SQL is produced by
``app.search.compile`` with bound parameters. Every failure is a :class:`QueryError` carrying the
character position, so the API can answer 422 and the UI can point at the problem.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

MAX_QUERY = 2000
MAX_DEPTH = 12
MAX_TERMS = 40
MAX_VALUE = 512
MAX_WILDCARDS = 4
MIN_LEADING_LITERAL = 3
INT4_MIN, INT4_MAX = -(2**31), 2**31 - 1

FieldKind = Literal["text", "int", "ip", "ts", "array", "uuid"]

FIELDS: dict[str, FieldKind] = {
    "host": "text",
    "user": "text",
    "event_code": "text",
    "event_category": "text",
    "action": "text",
    "outcome": "text",
    "source_type": "text",
    "source_file": "text",
    "source_record_id": "text",
    "process_name": "text",
    "cmdline": "text",
    "file_path": "text",
    "file_hash": "text",
    "protocol": "text",
    "registry_key": "text",
    "message": "text",
    "parser_name": "text",
    "pid": "int",
    "ppid": "int",
    "src_port": "int",
    "dst_port": "int",
    "src_ip": "ip",
    "dst_ip": "ip",
    "ip": "ip",
    "ts": "ts",
    "attack_tags": "array",
    "tags": "array",
    "id": "uuid",
    "evidence_id": "uuid",
    "job_id": "uuid",
}
OPS: dict[FieldKind, tuple[str, ...]] = {
    "text": ("eq", "wildcard", "exists"),
    "int": ("eq", "range", "exists"),
    "ip": ("eq", "cidr", "exists"),
    "ts": ("range",),
    "array": ("eq", "wildcard", "exists"),
    "uuid": ("eq",),
}
KEYWORDS = frozenset({"AND", "OR", "NOT", "TO"})
FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SPECIAL = frozenset('()[]"')
TECHNIQUE_RE = re.compile(r"^[Tt][0-9]{4}(?:\.[0-9]{3})?$")


class QueryError(ValueError):
    """Invalid query. ``position`` is the 0-based character offset of the problem."""

    def __init__(self, message: str, position: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.position = position


# ---------------------------------------------------------------------------------------- AST


@dataclass(frozen=True)
class Term:
    field: str
    op: Literal["eq", "wildcard", "range", "exists", "cidr"]
    value: str | None = None
    low: str | None = None  # range bounds; None = open end
    high: str | None = None


@dataclass(frozen=True)
class FreeText:
    text: str
    phrase: bool = False


@dataclass(frozen=True)
class Not:
    child: Node


@dataclass(frozen=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    children: tuple[Node, ...]


Node = Term | FreeText | Not | And | Or


# ----------------------------------------------------------------------------------- tokenizer


@dataclass(frozen=True)
class Token:
    kind: Literal["word", "quoted", "field", "lparen", "rparen", "lbrack", "rbrack", "kw"]
    text: str
    pos: int
    end: int
    rest: str = ""  # field tokens: the value glued to "field:" (may be empty)


def tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(query)
    singles = {"(": "lparen", ")": "rparen", "[": "lbrack", "]": "rbrack"}
    while i < n:
        ch = query[i]
        if ch.isspace():
            i += 1
            continue
        if ch in singles:
            tokens.append(Token(singles[ch], ch, i, i + 1))  # type: ignore[arg-type]
            i += 1
            continue
        if ch == '"':
            start, i = i, i + 1
            buf: list[str] = []
            while True:
                if i >= n:
                    raise QueryError("Unterminated quoted string.", start)
                c = query[i]
                if c == "\\" and i + 1 < n and query[i + 1] in '"\\':
                    buf.append(query[i + 1])
                    i += 2
                    continue
                if c == '"':
                    i += 1
                    break
                buf.append(c)
                i += 1
            tokens.append(Token("quoted", "".join(buf), start, i))
            continue
        start = i
        while i < n and not query[i].isspace() and query[i] not in SPECIAL:
            i += 1
        word = query[start:i]
        if word in KEYWORDS:
            tokens.append(Token("kw", word, start, i))
            continue
        name, sep, rest = word.partition(":")
        if sep and FIELD_RE.match(name):
            tokens.append(Token("field", name, start, i, rest))
        else:
            tokens.append(Token("word", word, start, i))
    return tokens


# -------------------------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, query: str) -> None:
        self.query = query
        self.tokens = tokenize(query)
        self.i = 0
        self.terms = 0

    def peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def end_pos(self) -> int:
        return len(self.query)

    def count_term(self, pos: int) -> None:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError(f"Too many terms (at most {MAX_TERMS}).", pos)

    def parse(self) -> Node:
        node = self.parse_or(0)
        tok = self.peek()
        if tok is not None:
            if tok.kind == "rparen":
                raise QueryError("Unbalanced ')'.", tok.pos)
            raise QueryError(f"Unexpected {tok.text!r}.", tok.pos)
        return node

    def parse_or(self, depth: int) -> Node:
        items = [self.parse_and(depth)]
        while (tok := self.peek()) is not None and tok.kind == "kw" and tok.text == "OR":
            self.take()
            items.append(self.parse_and(depth))
        return items[0] if len(items) == 1 else Or(tuple(items))

    def parse_and(self, depth: int) -> Node:
        items = [self.parse_unary(depth)]
        while (tok := self.peek()) is not None and tok.kind != "rparen":
            if tok.kind == "kw" and tok.text == "OR":
                break
            if tok.kind == "kw" and tok.text == "AND":
                self.take()
            items.append(self.parse_unary(depth))
        return items[0] if len(items) == 1 else And(tuple(items))

    def parse_unary(self, depth: int) -> Node:
        tok = self.peek()
        if tok is None:
            raise QueryError("Unexpected end of query: a term is missing.", self.end_pos())
        if depth >= MAX_DEPTH:
            raise QueryError(f"Query nested too deeply (at most {MAX_DEPTH}).", tok.pos)
        if tok.kind == "kw":
            if tok.text == "NOT":
                self.take()
                return Not(self.parse_unary(depth + 1))
            if tok.text == "TO":
                raise QueryError("'TO' is only valid inside a range: field:[a TO b].", tok.pos)
            raise QueryError(f"'{tok.text}' needs a term on both sides.", tok.pos)
        if tok.kind == "lparen":
            self.take()
            node = self.parse_or(depth + 1)
            close = self.peek()
            if close is None or close.kind != "rparen":
                raise QueryError("Missing ')'.", tok.pos)
            self.take()
            return node
        if tok.kind == "field":
            return self.parse_field(self.take())
        if tok.kind in ("word", "quoted"):
            self.take()
            self.count_term(tok.pos)
            return self.free_text(tok)
        raise QueryError(f"Unexpected {tok.text!r}.", tok.pos)

    def free_text(self, tok: Token) -> FreeText:
        text = tok.text
        check_value(text, tok.pos)
        if tok.kind == "word" and "*" in text:
            raise QueryError(
                "Wildcards need a field, e.g. cmdline:*mimikatz* or message:*text*.", tok.pos
            )
        if not text.strip():
            raise QueryError("Empty search text.", tok.pos)
        return FreeText(text, phrase=tok.kind == "quoted")

    def parse_field(self, tok: Token) -> Term:
        name = tok.text.lower()
        kind = FIELDS.get(name)
        if kind is None:
            raise QueryError(
                f"Unknown field '{tok.text}'. Quote values that contain ':' (e.g. \"C:\\x\").",
                tok.pos,
            )
        self.count_term(tok.pos)
        if tok.rest:
            return build_term(name, kind, tok.rest, quoted=False, pos=tok.end - len(tok.rest))
        nxt = self.peek()
        if nxt is None:
            raise QueryError(f"Missing value after '{tok.text}:'.", tok.end)
        if nxt.kind == "lbrack":
            self.take()
            return self.parse_range(name, kind, nxt)
        if nxt.kind == "quoted":
            self.take()
            return build_term(name, kind, nxt.text, quoted=True, pos=nxt.pos)
        if nxt.kind == "word":
            self.take()
            return build_term(name, kind, nxt.text, quoted=False, pos=nxt.pos)
        raise QueryError(f"Missing value after '{tok.text}:'.", nxt.pos)

    def parse_range(self, name: str, kind: FieldKind, open_tok: Token) -> Term:
        if "range" not in OPS[kind]:
            raise QueryError(f"Field '{name}' does not support ranges.", open_tok.pos)
        low = self.bound(open_tok)
        to = self.peek()
        if to is None or to.kind != "kw" or to.text != "TO":
            raise QueryError("Expected 'TO' in range [a TO b].", to.pos if to else self.end_pos())
        self.take()
        high = self.bound(open_tok)
        close = self.peek()
        if close is None or close.kind != "rbrack":
            raise QueryError("Missing ']' to close the range.", open_tok.pos)
        self.take()
        if low is None and high is None:
            raise QueryError("A range needs at least one bound.", open_tok.pos)
        low_v = check_bound(kind, low, open_tok.pos)
        high_v = check_bound(kind, high, open_tok.pos)
        if kind == "int" and low_v is not None and high_v is not None and int(low_v) > int(high_v):
            raise QueryError("Range lower bound is above the upper bound.", open_tok.pos)
        if (
            kind == "ts"
            and low_v is not None
            and high_v is not None
            and datetime.fromisoformat(low_v) > datetime.fromisoformat(high_v)
        ):
            raise QueryError("Range start is after its end.", open_tok.pos)
        return Term(name, "range", low=low_v, high=high_v)

    def bound(self, open_tok: Token) -> str | None:
        tok = self.peek()
        if tok is None:
            raise QueryError("Unterminated range.", open_tok.pos)
        if tok.kind == "quoted" or (tok.kind == "word" and tok.text != "*"):
            self.take()
            check_value(tok.text, tok.pos)
            return tok.text
        if tok.kind == "word":  # "*"
            self.take()
            return None
        if tok.kind == "field":  # a timestamp such as 2026-01-01T00:00:00Z tokenizes as field-ish
            self.take()
            text = f"{tok.text}:{tok.rest}"
            check_value(text, tok.pos)
            return text
        raise QueryError("Expected a range bound.", tok.pos)


def check_value(value: str, pos: int) -> None:
    if len(value) > MAX_VALUE:
        raise QueryError(f"Value too long (at most {MAX_VALUE} characters).", pos)
    if "\x00" in value:
        raise QueryError("NUL characters are not allowed.", pos)


def check_bound(kind: FieldKind, value: str | None, pos: int) -> str | None:
    if value is None:
        return None
    if kind == "int":
        return str(parse_int(value, pos))
    if kind == "ts":
        return parse_ts(value, pos).isoformat()
    raise QueryError("Ranges are only supported on numbers and ts.", pos)  # pragma: no cover


def parse_int(value: str, pos: int) -> int:
    if not re.fullmatch(r"-?[0-9]{1,10}", value):
        raise QueryError(f"'{value[:40]}' is not a whole number.", pos)
    number = int(value)
    if not INT4_MIN <= number <= INT4_MAX:
        raise QueryError("Number out of range.", pos)
    return number


def parse_ts(value: str, pos: int) -> datetime:
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        ts = datetime.fromisoformat(text)
    except ValueError as exc:
        raise QueryError(
            f"'{value[:40]}' is not an ISO-8601 time (e.g. 2026-09-14T08:00:00Z).", pos
        ) from exc
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise QueryError("Times need a zone (e.g. ...Z or +02:00).", pos)
    return ts


def build_term(name: str, kind: FieldKind, value: str, *, quoted: bool, pos: int) -> Term:
    check_value(value, pos)
    ops = OPS[kind]
    if value == "*" and not quoted:
        if "exists" not in ops:
            raise QueryError(f"Field '{name}' does not support '*'.", pos)
        return Term(name, "exists")
    if not value:
        raise QueryError(f"Empty value for '{name}'.", pos)
    if kind == "ts":
        raise QueryError("Use a range for time: ts:[2026-01-01T00:00:00Z TO *].", pos)
    stars = 0 if quoted else value.count("*")
    if stars:
        if "wildcard" not in ops:
            raise QueryError(f"Field '{name}' does not support wildcards.", pos)
        if stars > MAX_WILDCARDS:
            raise QueryError(f"At most {MAX_WILDCARDS} wildcards per value.", pos)
        literal = value.replace("*", "")
        if value.startswith("*") and len(literal) < MIN_LEADING_LITERAL:
            raise QueryError(
                f"A leading wildcard needs at least {MIN_LEADING_LITERAL} other characters.", pos
            )
        if name == "attack_tags":
            value = value.upper()
        return Term(name, "wildcard", value=value)
    if kind == "int":
        return Term(name, "eq", value=str(parse_int(value, pos)))
    if kind == "uuid":
        try:
            return Term(name, "eq", value=str(uuid.UUID(value)))
        except ValueError as exc:
            raise QueryError(f"'{value[:40]}' is not a UUID.", pos) from exc
    if kind == "ip":
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise QueryError(f"'{value[:40]}' is not a valid CIDR range.", pos) from exc
            return Term(name, "cidr", value=str(net))
        try:
            return Term(name, "eq", value=str(ipaddress.ip_address(value)))
        except ValueError as exc:
            raise QueryError(f"'{value[:40]}' is not a valid IP address.", pos) from exc
    if name == "attack_tags":
        if not TECHNIQUE_RE.match(value):
            raise QueryError("ATT&CK ids look like T1059 or T1059.001.", pos)
        value = value.upper()
    return Term(name, "eq", value=value)


def parse(query: str | None) -> Node | None:
    """Parse ``query``. Empty or whitespace-only -> ``None`` (match everything)."""
    if query is None:
        return None
    if len(query) > MAX_QUERY:
        raise QueryError(f"Query too long (at most {MAX_QUERY} characters).", MAX_QUERY)
    if not query.strip():
        return None
    return _Parser(query).parse()


def quote_value(value: str) -> str:
    """Quote a literal value for use in a query (pivots built by the server)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def field_catalogue() -> list[dict[str, object]]:
    return [{"name": k, "type": v, "ops": list(OPS[v])} for k, v in FIELDS.items()]
