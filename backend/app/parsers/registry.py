"""Parser registry (guide 10.2). Built-in parsers register themselves on import."""

from __future__ import annotations

import importlib
from pathlib import Path

from app.parsers.base import Parser

REGISTRY: dict[str, Parser] = {}
BUILTIN_MODULES = ("app.parsers.evtx", "app.parsers.linux_auth")
AUTO_THRESHOLD = 0.5


class UnknownParserError(KeyError):
    pass


def register[P](cls: type[P]) -> type[P]:
    inst = cls()
    name = inst.name  # type: ignore[attr-defined]
    existing = REGISTRY.get(name)
    if existing is not None and type(existing) is not cls:
        raise ValueError(f"parser {name!r} is already registered")
    REGISTRY[name] = inst  # type: ignore[assignment]
    return cls


def load_builtin() -> None:
    for module in BUILTIN_MODULES:
        importlib.import_module(module)


def all_parsers() -> dict[str, Parser]:
    load_builtin()
    return dict(sorted(REGISTRY.items()))


def get_parser(name: str) -> Parser:
    load_builtin()
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise UnknownParserError(name) from exc


def detect(head: bytes, filename: str, path: Path | None = None) -> list[tuple[str, float]]:
    """Parsers whose confidence reaches AUTO_THRESHOLD, best first."""
    scores = [(name, p.can_parse(path, head, filename)) for name, p in all_parsers().items()]
    return sorted(
        [(n, s) for n, s in scores if s >= AUTO_THRESHOLD], key=lambda item: (-item[1], item[0])
    )
