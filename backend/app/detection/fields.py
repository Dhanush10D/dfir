"""Event fields rules may reference (Appendix A columns plus bounded ``raw.*`` paths).

Events reach the engine as mappings: the column names below, ``id``/``ts``/``evidence_id``, and
either a nested ``raw`` dict (rule tests, unit tests) or pre-extracted ``"raw.a.b"`` keys (the
worker selects only the raw paths the loaded rules use, never whole ``raw`` documents).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

TEXT_FIELDS = frozenset(
    {
        "host",
        "user",
        "event_code",
        "event_category",
        "action",
        "outcome",
        "process_name",
        "cmdline",
        "file_path",
        "file_hash",
        "protocol",
        "registry_key",
        "message",
        "source_type",
        "source_file",
        "source_record_id",
        "parser_name",
    }
)
INT_FIELDS = frozenset({"pid", "ppid", "src_port", "dst_port"})
IP_FIELDS = frozenset({"src_ip", "dst_ip"})
COLUMNS = TEXT_FIELDS | INT_FIELDS | IP_FIELDS
RAW_FIELD = re.compile(r"^raw(?:\.[A-Za-z0-9_]{1,64}){1,4}$")
MAX_RAW_PATHS = 64
MAX_MATCH_CHARS = 64 * 1024  # longest value a matcher looks at (columns are <= 32 KiB anyway)

DURATION = re.compile(r"^([1-9][0-9]{0,5})([smhd])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def is_field(name: str) -> bool:
    return name in COLUMNS or bool(RAW_FIELD.fullmatch(name))


def raw_path(name: str) -> tuple[str, ...] | None:
    if not name.startswith("raw."):
        return None
    return tuple(name.split(".")[1:])


def get_value(event: Mapping[str, Any], name: str) -> Any:
    """Value of ``name`` in ``event`` (None when absent)."""
    if name in event:
        return event[name]
    path = raw_path(name)
    if path is None:
        return None
    node: Any = event.get("raw")
    for part in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(part)
    return node


def as_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, int | float | ipaddress.IPv4Address | ipaddress.IPv6Address):
        text = str(value)
    else:  # lists/dicts inside raw: never matched as text
        return None
    return text[:MAX_MATCH_CHARS]


def as_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str) and len(value) <= 32:
        try:
            return float(int(value.strip(), 0))
        except ValueError:
            try:
                return float(value.strip())
            except ValueError:
                return None
    return None


def as_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if value is None:
        return None
    if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return value
    if isinstance(value, str) and len(value) <= 64:
        try:
            addr = ipaddress.ip_address(value.strip().strip("[]"))
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        return addr
    return None


def parse_duration(value: str, *, minimum: int = 1, maximum: int = 30 * 86400) -> int:
    """``"90s"``, ``"5m"``, ``"12h"``, ``"7d"`` -> seconds, within ``[minimum, maximum]``."""
    if not isinstance(value, str):
        raise ValueError("duration must be a string like '5m', '12h' or '7d'")
    m = DURATION.fullmatch(value.strip())
    if m is None:
        raise ValueError(f"invalid duration {value!r} (use e.g. '30s', '5m', '12h', '7d')")
    seconds = int(m.group(1)) * UNIT_SECONDS[m.group(2)]
    if not minimum <= seconds <= maximum:
        raise ValueError(
            f"duration {value!r} out of range ({minimum}s to {timedelta(seconds=maximum)})"
        )
    return seconds


def epoch(ts: datetime) -> float:
    return ts.timestamp()
