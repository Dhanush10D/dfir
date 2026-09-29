"""Archive member name rules shared by the bundle reader and the manifest schema.

A name is only ever compared and displayed, never used as a filesystem path (extraction writes
fixed names), but a name that *could* escape a directory marks the bundle as hostile, so it is
refused: absolute paths, drive letters, backslashes, ``.``/``..`` or empty components, control
characters, and over-long or over-deep names.
"""

from __future__ import annotations

import re

MAX_NAME_CHARS = 512
MAX_COMPONENTS = 32
MAX_COMPONENT_CHARS = 255
_DRIVE = re.compile(r"^[A-Za-z]:")


def unsafe_name_reason(name: str, *, directory: bool = False) -> str | None:
    """Why ``name`` is not an acceptable member path, or ``None`` if it is.

    ``directory`` allows (exactly one) trailing ``/`` as ZIP directory entries have.
    """
    if not isinstance(name, str) or not name:
        return "empty_name"
    if len(name) > MAX_NAME_CHARS:
        return "name_too_long"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        return "control_character"
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in name):
        return "invalid_unicode"
    if "\\" in name:
        return "backslash"
    if name.startswith("/"):
        return "absolute_path"
    if _DRIVE.match(name):
        return "drive_letter"
    body = name[:-1] if directory and name.endswith("/") else name
    parts = body.split("/")
    if len(parts) > MAX_COMPONENTS:
        return "too_deep"
    for part in parts:
        if part == "":
            return "empty_component"
        if part in (".", ".."):
            return "dot_component"
        if len(part) > MAX_COMPONENT_CHARS:
            return "component_too_long"
    return None
