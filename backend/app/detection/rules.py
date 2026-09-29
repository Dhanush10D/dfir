"""Rule format (guide 11.2), strict validation, and compilation to an evaluable AST (guide 11.3).

A rule is YAML loaded with :func:`app.detection.yamlsafe.safe_yaml` and validated by pydantic
models that forbid unknown keys. ``detection`` has reserved keys; every other key is a *named
selection* (a mapping, or a list of mappings meaning OR). Selection keys are ``field`` or
``field|modifier[|all|any]``:

=============  ==========================================================================
modifier       meaning (strings compare case-insensitively, after ``str.casefold``)
=============  ==========================================================================
(none)         equality (``null`` = field absent/empty); integers/IPs compare by value
contains       substring
startswith     prefix
endswith       suffix
re             RE2 regular expression (linear time, no backreferences/lookaround), searched;
               case-sensitive unless the pattern starts with ``(?i)``
cidr           IP inside the network(s)
gt gte lt lte  numeric comparison
exists         ``true``/``false``: the field has a non-empty value
all / any      with a list value: every / at least one value must match (default ``any``)
=============  ==========================================================================

Kinds: ``single`` (``condition``), ``threshold`` (``condition`` + ``threshold`` + optional
``group_by``), ``sequence`` (``sequence`` steps + ``join_on`` + ``within``), ``detector`` (a
built-in Python detector with validated ``params``). Every limit (pattern length, list sizes,
windows, counts) is enforced here so the engine's memory and CPU stay bounded.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

import re2
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.detection import fields as F  # noqa: N812
from app.detection.attack import Level, is_technique
from app.detection.yamlsafe import YamlInputError, safe_yaml

RULE_ID = re.compile(r"^[A-Z][A-Z0-9]{1,15}(?:-[A-Z0-9]{1,16}){1,4}$")
SELECTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
OPERATORS = frozenset(
    {"eq", "contains", "startswith", "endswith", "re", "cidr", "gt", "gte", "lt", "lte", "exists"}
)
MAX_PATTERN = 512
MAX_VALUES = 256
MAX_VALUE_CHARS = 4096
MAX_SELECTIONS = 32
MAX_FIELDS_PER_SELECTION = 32
MAX_CONDITION = 2048
MAX_CONDITION_DEPTH = 32
MAX_STEPS = 8
RESERVED = frozenset(
    {"condition", "group_by", "threshold", "sequence", "join_on", "within", "detector", "params"}
)
DEFAULT_CONFIDENCE = {"stable": 0.8, "test": 0.6, "experimental": 0.4, "deprecated": 0.2}
Kind = Literal["single", "threshold", "sequence", "detector"]


class RuleError(ValueError):
    """A rule failed validation; ``errors`` lists every problem found."""

    def __init__(self, message: str, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or [message]


# --------------------------------------------------------------------------- schema


class LogSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str | list[str] | None = None
    channel: str | None = Field(default=None, max_length=256)
    provider: str | None = Field(default=None, max_length=256)
    event_category: str | None = Field(default=None, max_length=64)
    action: str | None = Field(default=None, max_length=64)

    @field_validator("source_type")
    @classmethod
    def _types(cls, value: str | list[str] | None) -> str | list[str] | None:
        items = [value] if isinstance(value, str) else (value or [])
        if len(items) > 16 or any(not 1 <= len(v) <= 64 for v in items):
            raise ValueError("source_type: 1-16 names of 1-64 characters")
        return value


class Response(BaseModel):
    model_config = ConfigDict(extra="forbid")

    playbook: str | None = Field(default=None, max_length=128)


class RuleModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(max_length=64)
    title: str = Field(min_length=1, max_length=200)
    status: Literal["stable", "test", "experimental", "deprecated"] = "experimental"
    level: Level
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    attack: list[str] = Field(default_factory=list, max_length=20)
    description: str | None = Field(default=None, max_length=4000)
    author: str | None = Field(default=None, max_length=200)
    references: list[str] = Field(default_factory=list, max_length=20)
    false_positives: list[str] = Field(default_factory=list, max_length=20)
    logsource: LogSource = Field(default_factory=LogSource)
    detection: dict[str, Any]
    dedup_window: str = "1d"
    response: Response | None = None
    origin_ref: str | None = Field(default=None, max_length=256)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not RULE_ID.fullmatch(value):
            raise ValueError("id must look like DFIR-WIN-0001 (upper-case letters/digits, dashes)")
        return value

    @field_validator("attack")
    @classmethod
    def _attack(cls, value: list[str]) -> list[str]:
        bad = [v for v in value if not is_technique(v)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique ids {bad!r} (expected T1234 or T1234.001)")
        return sorted(dict.fromkeys(value))

    @field_validator("references", "false_positives")
    @classmethod
    def _short_list(cls, value: list[str]) -> list[str]:
        if any(not isinstance(v, str) or len(v) > 500 for v in value):
            raise ValueError("entries must be strings of at most 500 characters")
        return value


# --------------------------------------------------------------------------- matchers


class EventView:
    """Per-event lookup cache (casefolded text is computed once per field)."""

    __slots__ = ("_folded", "event")

    def __init__(self, event: Mapping[str, Any]) -> None:
        self.event = event
        self._folded: dict[str, str | None] = {}

    def value(self, name: str) -> Any:
        return F.get_value(self.event, name)

    def text(self, name: str) -> str | None:
        return F.as_text(self.value(name))

    def folded(self, name: str) -> str | None:
        if name not in self._folded:
            text = self.text(name)
            self._folded[name] = text.casefold() if text is not None else None
        return self._folded[name]


@dataclass(frozen=True)
class Matcher:
    field: str
    op: str
    values: tuple[Any, ...]
    quantifier: Literal["any", "all"] = "any"

    def match(self, ev: EventView) -> bool:
        test = self._test
        if self.quantifier == "all":
            return all(test(ev, v) for v in self.values)
        return any(test(ev, v) for v in self.values)

    def _test(self, ev: EventView, value: Any) -> bool:
        op = self.op
        name = self.field
        if op == "exists":
            text = ev.text(name)
            present = text is not None and text != ""
            return present is bool(value)
        if op == "eq":
            if value is None:
                text = ev.text(name)
                return text is None or text == ""
            if name in F.IP_FIELDS:
                return bool(F.as_ip(ev.value(name)) == value)
            if name in F.INT_FIELDS:
                return bool(F.as_number(ev.value(name)) == value)
            return bool(ev.folded(name) == value)
        if op in ("contains", "startswith", "endswith"):
            folded = ev.folded(name)
            if folded is None:
                return False
            if op == "contains":
                return value in folded
            if op == "startswith":
                return bool(folded.startswith(value))
            return bool(folded.endswith(value))
        if op == "re":
            text = ev.text(name)
            return text is not None and value.search(text) is not None
        if op == "cidr":
            addr = F.as_ip(ev.value(name))
            return addr is not None and addr.version == value.version and addr in value
        number = F.as_number(ev.value(name))
        if number is None:
            return False
        if op == "gt":
            return bool(number > value)
        if op == "gte":
            return bool(number >= value)
        if op == "lt":
            return bool(number < value)
        return bool(number <= value)


@dataclass(frozen=True)
class Selection:
    """AND of matchers; a selection given as a list of mappings is an OR of such groups."""

    groups: tuple[tuple[Matcher, ...], ...]

    def match(self, ev: EventView) -> bool:
        return any(all(m.match(ev) for m in group) for group in self.groups)

    @property
    def fields(self) -> set[str]:
        return {m.field for group in self.groups for m in group}


def _compile_value(name: str, op: str, value: Any, where: str) -> Any:
    if op == "exists":
        if not isinstance(value, bool):
            raise RuleError(f"{where}: 'exists' takes true or false")
        return value
    if op == "eq":
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            raise RuleError(f"{where}: values must be strings or numbers")
        if name in F.IP_FIELDS:
            addr = F.as_ip(str(value))
            if addr is None:
                raise RuleError(f"{where}: {value!r} is not an IP address")
            return addr
        if name in F.INT_FIELDS:
            number = F.as_number(value)
            if number is None:
                raise RuleError(f"{where}: {value!r} is not a number")
            return number
        text = str(value)
        if len(text) > MAX_VALUE_CHARS:
            raise RuleError(f"{where}: value longer than {MAX_VALUE_CHARS} characters")
        return text.casefold()
    if op in ("contains", "startswith", "endswith"):
        if isinstance(value, bool) or not isinstance(value, str | int) or str(value) == "":
            raise RuleError(f"{where}: '{op}' needs a non-empty string")
        text = str(value)
        if len(text) > MAX_VALUE_CHARS:
            raise RuleError(f"{where}: value longer than {MAX_VALUE_CHARS} characters")
        return text.casefold()
    if op == "re":
        if not isinstance(value, str) or not value:
            raise RuleError(f"{where}: 're' needs a non-empty pattern string")
        if len(value) > MAX_PATTERN:
            raise RuleError(f"{where}: pattern longer than {MAX_PATTERN} characters")
        try:
            return re2.compile(value)
        except re2.error as exc:
            detail = exc.args[0].decode() if exc.args and isinstance(exc.args[0], bytes) else exc
            raise RuleError(
                f"{where}: pattern not supported by RE2 ({detail}); backreferences and "
                "lookaround are not available"
            ) from exc
    if op == "cidr":
        if not isinstance(value, str):
            raise RuleError(f"{where}: 'cidr' needs a network like 10.0.0.0/8")
        try:
            return ipaddress.ip_network(value.strip(), strict=False)
        except ValueError as exc:
            raise RuleError(f"{where}: {value!r} is not a network") from exc
    number = F.as_number(value)
    if number is None:
        raise RuleError(f"{where}: '{op}' needs a number")
    return number


def compile_matcher(spec: str, raw_value: Any, where: str) -> Matcher:
    parts = spec.split("|")
    name, mods = parts[0], parts[1:]
    if not F.is_field(name):
        raise RuleError(
            f"{where}: unknown field {name!r} (use an event column or raw.<path>, max 4 levels)"
        )
    op = "eq"
    quantifier: Literal["any", "all"] = "any"
    seen_op = False
    for mod in mods:
        if mod in ("all", "any"):
            quantifier = "all" if mod == "all" else "any"
        elif mod in OPERATORS and mod != "eq":
            if seen_op:
                raise RuleError(f"{where}: only one operator modifier per field")
            op, seen_op = mod, True
        else:
            raise RuleError(f"{where}: unsupported modifier {mod!r}")
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not values:
        raise RuleError(f"{where}: empty value list")
    if len(values) > MAX_VALUES:
        raise RuleError(f"{where}: more than {MAX_VALUES} values")
    if op == "exists" and len(values) != 1:
        raise RuleError(f"{where}: 'exists' takes a single true/false")
    compiled = tuple(_compile_value(name, op, v, where) for v in values)
    return Matcher(name, op, compiled, quantifier)


def compile_selection(name: str, spec: Any) -> Selection:
    where = f"selection {name!r}"
    items = spec if isinstance(spec, list) else [spec]
    if not items or len(items) > MAX_SELECTIONS:
        raise RuleError(f"{where}: needs 1-{MAX_SELECTIONS} mappings")
    groups = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping) or not item:
            raise RuleError(
                f"{where}: must be a non-empty mapping of field: value (keyword lists are not "
                "supported)"
            )
        if len(item) > MAX_FIELDS_PER_SELECTION:
            raise RuleError(f"{where}: more than {MAX_FIELDS_PER_SELECTION} fields")
        label = where if len(items) == 1 else f"{where}[{index}]"
        groups.append(
            tuple(
                compile_matcher(str(key), value, f"{label} {key!r}") for key, value in item.items()
            )
        )
    return Selection(tuple(groups))


# --------------------------------------------------------------------------- conditions


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    node: Node


@dataclass(frozen=True)
class And:
    nodes: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    nodes: tuple[Node, ...]


Node = Ref | Not | And | Or
TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_*][A-Za-z0-9_*]*|[0-9]+|\S)")


def _tokens(text: str) -> list[str]:
    out: list[str] = []
    pos = 0
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if m is None:
            break
        out.append(m.group(1))
        pos = m.end()
        if len(out) > 512:
            raise RuleError("condition has too many tokens")
    return out


class _ConditionParser:
    def __init__(self, text: str, names: list[str]) -> None:
        if not isinstance(text, str) or not text.strip():
            raise RuleError("condition must be a non-empty string")
        if len(text) > MAX_CONDITION:
            raise RuleError(f"condition longer than {MAX_CONDITION} characters")
        if "|" in text:
            raise RuleError("condition: aggregations ('| count() ...') are not supported")
        self.toks = _tokens(text)
        self.pos = 0
        self.names = names
        self.depth = 0

    def parse(self) -> Node:
        node = self._or()
        if self.pos != len(self.toks):
            raise RuleError(f"condition: unexpected {self.toks[self.pos]!r}")
        return node

    def _peek(self) -> str | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def _take(self) -> str:
        tok = self._peek()
        if tok is None:
            raise RuleError("condition: unexpected end")
        self.pos += 1
        return tok

    def _or(self) -> Node:
        nodes = [self._and()]
        while (self._peek() or "").lower() == "or":
            self._take()
            nodes.append(self._and())
        return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))

    def _and(self) -> Node:
        nodes = [self._not()]
        while (self._peek() or "").lower() == "and":
            self._take()
            nodes.append(self._not())
        return nodes[0] if len(nodes) == 1 else And(tuple(nodes))

    def _not(self) -> Node:
        if (self._peek() or "").lower() == "not":
            self._take()
            self.depth += 1
            if self.depth > MAX_CONDITION_DEPTH:
                raise RuleError("condition nested too deeply")
            node = Not(self._not())
            self.depth -= 1
            return node
        return self._atom()

    def _atom(self) -> Node:
        tok = self._take()
        if tok == "(":
            self.depth += 1
            if self.depth > MAX_CONDITION_DEPTH:
                raise RuleError("condition nested too deeply")
            node = self._or()
            if self._take() != ")":
                raise RuleError("condition: missing ')'")
            self.depth -= 1
            return node
        low = tok.lower()
        if low in ("1", "all", "any") and (self._peek() or "").lower() == "of":
            self._take()
            target = self._take()
            if target.lower() == "them":
                chosen = list(self.names)
            else:
                pattern = re.compile("^" + re.escape(target).replace(r"\*", "[A-Za-z0-9_]*") + "$")
                chosen = [n for n in self.names if pattern.fullmatch(n)]
            if not chosen:
                raise RuleError(f"condition: {target!r} matches no selection")
            refs = tuple(Ref(n) for n in chosen)
            if len(refs) == 1:
                return refs[0]
            return And(refs) if low == "all" else Or(refs)
        if low in ("and", "or", "not", "of", ")"):
            raise RuleError(f"condition: unexpected {tok!r}")
        if tok not in self.names:
            raise RuleError(f"condition: unknown selection {tok!r}")
        return Ref(tok)


def parse_condition(text: str, names: list[str]) -> Node:
    return _ConditionParser(text, names).parse()


def evaluate(node: Node, results: Callable[[str], bool]) -> bool:
    if isinstance(node, Ref):
        return results(node.name)
    if isinstance(node, Not):
        return not evaluate(node.node, results)
    if isinstance(node, And):
        return all(evaluate(n, results) for n in node.nodes)
    return any(evaluate(n, results) for n in node.nodes)


# --------------------------------------------------------------------------- compiled rules


@dataclass(frozen=True)
class Threshold:
    count: int
    window_s: int
    distinct: str | None = None


@dataclass(frozen=True)
class Step:
    name: str
    selection: Selection
    min_count: int = 1


@dataclass(frozen=True)
class SequenceSpec:
    steps: tuple[Step, ...]
    join_on: tuple[str, ...]
    within_s: int


@dataclass(frozen=True)
class LogSourceFilter:
    source_types: frozenset[str] = frozenset()
    channel: str | None = None
    provider: str | None = None
    event_category: str | None = None
    action: str | None = None

    def match(self, ev: EventView) -> bool:
        if self.source_types and (ev.folded("source_type") or "") not in self.source_types:
            return False
        if self.channel is not None and ev.folded("raw.system.channel") != self.channel:
            return False
        if self.provider is not None and ev.folded("raw.system.provider") != self.provider:
            return False
        if self.event_category is not None and ev.folded("event_category") != self.event_category:
            return False
        return self.action is None or ev.folded("action") == self.action

    @property
    def fields(self) -> set[str]:
        out = {"source_type"}
        if self.channel is not None:
            out.add("raw.system.channel")
        if self.provider is not None:
            out.add("raw.system.provider")
        if self.event_category is not None:
            out.add("event_category")
        if self.action is not None:
            out.add("action")
        return out


@dataclass(frozen=True)
class CompiledRule:
    id: str
    title: str
    level: Level
    status: str
    confidence: float
    attack: tuple[str, ...]
    kind: Kind
    logsource: LogSourceFilter
    dedup_window_s: int
    sha256: str
    raw_yaml: str
    model: RuleModel
    selections: Mapping[str, Selection] = field(default_factory=dict)
    condition: Node | None = None
    group_by: tuple[str, ...] = ()
    threshold: Threshold | None = None
    sequence: SequenceSpec | None = None
    detector: str | None = None
    params: BaseModel | None = None
    version: int = 1

    def matches(self, ev: EventView) -> bool:
        """Logsource + condition (single/threshold rules)."""
        if self.condition is None or not self.logsource.match(ev):
            return False
        cache: dict[str, bool] = {}

        def result(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].match(ev)
            return cache[name]

        return evaluate(self.condition, result)

    @property
    def fields(self) -> set[str]:
        """Every event field the rule reads (the worker selects exactly these)."""
        out = set(self.logsource.fields) | set(self.group_by)
        for selection in self.selections.values():
            out |= selection.fields
        if self.threshold and self.threshold.distinct:
            out.add(self.threshold.distinct)
        if self.sequence:
            out |= set(self.sequence.join_on)
            for step in self.sequence.steps:
                out |= step.selection.fields
        return out

    def with_version(self, version: int) -> CompiledRule:
        from dataclasses import replace

        return replace(self, version=version)


def _field_list(value: Any, what: str, maximum: int = 4) -> tuple[str, ...]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not 1 <= len(items) <= maximum:
        raise RuleError(f"{what}: 1-{maximum} field names")
    for item in items:
        if not isinstance(item, str) or not F.is_field(item):
            raise RuleError(f"{what}: unknown field {item!r}")
    return tuple(dict.fromkeys(items))


def _kind_of(det: Mapping[str, Any]) -> Kind:
    if "detector" in det:
        return "detector"
    if "sequence" in det:
        return "sequence"
    if "threshold" in det:
        return "threshold"
    return "single"


def _compile_detection(model: RuleModel) -> dict[str, Any]:
    det = model.detection
    kind = _kind_of(det)
    out: dict[str, Any] = {"kind": kind}
    allowed = {
        "detector": {"detector", "params"},
        "sequence": {"sequence", "join_on", "within"},
        "threshold": {"condition", "threshold", "group_by"},
        "single": {"condition", "group_by"},
    }[kind]
    misplaced = sorted(k for k in det if k in RESERVED and k not in allowed)
    if misplaced:
        raise RuleError(f"detection: {misplaced} not allowed in a {kind} rule")
    names = [k for k in det if k not in RESERVED]
    if kind in ("detector", "sequence") and names:
        raise RuleError(f"detection: named selections are not used by {kind} rules: {names}")
    if kind == "detector":
        from app.detection.detectors import DETECTORS  # registry of built-in detectors

        name = det.get("detector")
        if not isinstance(name, str) or name not in DETECTORS:
            raise RuleError(f"detection.detector: unknown detector {name!r}")
        params_model = DETECTORS[name].params_model
        try:
            out["params"] = params_model.model_validate(det.get("params") or {})
        except ValidationError as exc:
            raise RuleError("detection.params invalid", _pydantic_errors(exc)) from exc
        out["detector"] = name
        return out
    if kind == "sequence":
        steps_raw = det.get("sequence")
        if not isinstance(steps_raw, list) or not 2 <= len(steps_raw) <= MAX_STEPS:
            raise RuleError(f"detection.sequence: 2-{MAX_STEPS} steps")
        steps = []
        seen: set[str] = set()
        for index, step in enumerate(steps_raw):
            if not isinstance(step, Mapping) or set(step) - {"name", "match", "min_count"}:
                raise RuleError(f"detection.sequence[{index}]: keys are name, match, min_count")
            name = step.get("name", f"step{index + 1}")
            if not isinstance(name, str) or not SELECTION_NAME.fullmatch(name) or name in seen:
                raise RuleError(f"detection.sequence[{index}]: invalid or duplicate name")
            seen.add(name)
            min_count = step.get("min_count", 1)
            if isinstance(min_count, bool) or not isinstance(min_count, int):
                raise RuleError(f"detection.sequence[{index}].min_count must be an integer")
            if not 1 <= min_count <= 1000:
                raise RuleError(f"detection.sequence[{index}].min_count must be 1-1000")
            if "match" not in step:
                raise RuleError(f"detection.sequence[{index}]: 'match' is required")
            steps.append(Step(name, compile_selection(name, step["match"]), min_count))
        if "join_on" not in det or "within" not in det:
            raise RuleError("detection: sequence rules need join_on and within")
        try:
            within = F.parse_duration(det["within"], maximum=7 * 86400)
        except ValueError as exc:
            raise RuleError(f"detection.within: {exc}") from exc
        out["sequence"] = SequenceSpec(
            tuple(steps), _field_list(det["join_on"], "detection.join_on"), within
        )
        return out
    if not names:
        raise RuleError("detection: at least one named selection is required")
    if len(names) > MAX_SELECTIONS:
        raise RuleError(f"detection: more than {MAX_SELECTIONS} selections")
    bad = [n for n in names if not SELECTION_NAME.fullmatch(n)]
    if bad:
        raise RuleError(f"detection: invalid selection names {bad!r}")
    out["selections"] = {n: compile_selection(n, det[n]) for n in names}
    if "condition" not in det:
        raise RuleError("detection.condition is required")
    out["condition"] = parse_condition(det["condition"], names)
    if "group_by" in det:
        out["group_by"] = _field_list(det["group_by"], "detection.group_by")
    if kind == "threshold":
        spec = det["threshold"]
        if not isinstance(spec, Mapping) or set(spec) - {"count", "window", "distinct"}:
            raise RuleError("detection.threshold: keys are count, window, distinct")
        count = spec.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or not 2 <= count <= 100_000:
            raise RuleError("detection.threshold.count must be an integer 2-100000")
        try:
            window = F.parse_duration(spec.get("window", ""), maximum=86400)
        except ValueError as exc:
            raise RuleError(f"detection.threshold.window: {exc}") from exc
        distinct = spec.get("distinct")
        if distinct is not None:
            distinct = _field_list(distinct, "detection.threshold.distinct", 1)[0]
        out["threshold"] = Threshold(count, window, distinct)
    return out


def _pydantic_errors(exc: ValidationError) -> list[str]:
    return [
        f"{'.'.join(str(p) for p in err['loc']) or 'rule'}: {err['msg']}" for err in exc.errors()
    ]


def compile_rule(data: Any, raw_yaml: str) -> CompiledRule:
    if not isinstance(data, Mapping):
        raise RuleError("a rule must be a YAML mapping")
    try:
        model = RuleModel.model_validate(dict(data))
    except ValidationError as exc:
        errors = _pydantic_errors(exc)
        raise RuleError("rule validation failed: " + "; ".join(errors[:5]), errors) from exc
    try:
        dedup = F.parse_duration(model.dedup_window, minimum=60, maximum=30 * 86400)
    except ValueError as exc:
        raise RuleError(f"dedup_window: {exc}") from exc
    parts = _compile_detection(model)
    ls = model.logsource
    types = [ls.source_type] if isinstance(ls.source_type, str) else (ls.source_type or [])
    logsource = LogSourceFilter(
        frozenset(t.casefold() for t in types),
        ls.channel.casefold() if ls.channel else None,
        ls.provider.casefold() if ls.provider else None,
        ls.event_category.casefold() if ls.event_category else None,
        ls.action.casefold() if ls.action else None,
    )
    rule = CompiledRule(
        id=model.id,
        title=model.title,
        level=model.level,
        status=model.status,
        confidence=model.confidence
        if model.confidence is not None
        else DEFAULT_CONFIDENCE[model.status],
        attack=tuple(model.attack),
        kind=parts["kind"],
        logsource=logsource,
        dedup_window_s=dedup,
        sha256=hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest(),
        raw_yaml=raw_yaml,
        model=model,
        selections=parts.get("selections", {}),
        condition=parts.get("condition"),
        group_by=parts.get("group_by", ()),
        threshold=parts.get("threshold"),
        sequence=parts.get("sequence"),
        detector=parts.get("detector"),
        params=parts.get("params"),
    )
    raw_fields = {f for f in rule.fields if f.startswith("raw.")}
    if len(raw_fields) > F.MAX_RAW_PATHS:
        raise RuleError(f"rule references more than {F.MAX_RAW_PATHS} raw paths")
    return rule


def load_rule(text: str) -> CompiledRule:
    """Parse, validate and compile one rule from YAML text (raises :class:`RuleError`)."""
    try:
        data = safe_yaml(text, max_bytes=64 * 1024)
    except YamlInputError as exc:
        raise RuleError(str(exc)) from exc
    return compile_rule(data, text)
