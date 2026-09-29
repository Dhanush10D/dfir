"""Hostile-input-safe YAML loading for rules, Sigma imports and IOC lists.

* ``yaml.safe_load`` only (no Python object tags); one document per text.
* Size, node-count and nesting caps are checked on the event stream *before* anything is built.
* Anchors and aliases are rejected: aliases share objects, so a few bytes can describe an
  exponentially large tree ("billion laughs") that validation or JSON encoding would expand.
"""

from __future__ import annotations

from typing import Any

import yaml

MAX_YAML_BYTES = 256 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 32


class YamlInputError(ValueError):
    """The text is not acceptable YAML (syntax, size, aliases, depth)."""


def safe_yaml(text: str, *, max_bytes: int = MAX_YAML_BYTES, max_nodes: int = MAX_NODES) -> Any:
    if not isinstance(text, str):
        raise YamlInputError("YAML input must be text")
    if len(text.encode("utf-8", errors="replace")) > max_bytes:
        raise YamlInputError(f"YAML input is larger than {max_bytes} bytes")
    nodes = 0
    depth = 0
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent):
                raise YamlInputError("YAML aliases (*name) are not allowed")
            if getattr(event, "anchor", None):
                raise YamlInputError("YAML anchors (&name) are not allowed")
            if isinstance(event, yaml.MappingStartEvent | yaml.SequenceStartEvent):
                depth += 1
                if depth > MAX_DEPTH:
                    raise YamlInputError(f"YAML nesting deeper than {MAX_DEPTH}")
            elif isinstance(event, yaml.MappingEndEvent | yaml.SequenceEndEvent):
                depth -= 1
            if isinstance(event, yaml.NodeEvent):
                nodes += 1
                if nodes > max_nodes:
                    raise YamlInputError(f"YAML has more than {max_nodes} nodes")
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        problem = getattr(exc, "problem", None) or type(exc).__name__
        raise YamlInputError(f"invalid YAML: {problem}{where}") from exc
