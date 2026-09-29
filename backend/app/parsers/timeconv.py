"""Binary timestamp conversions (guide 10.5). Pure; every result is timezone-aware UTC.

Each converter returns ``None`` when the value means "not set" (zero), raises ``TimestampError``
when it cannot be a real time (negative, beyond year 9999), and otherwise returns ``Converted``
with the UTC datetime and ``original``: the raw value tagged with its epoch (``filetime:<int>``),
which parsers store in ``ts_original`` so the source value is never lost.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=UTC)
EPOCH_1970 = datetime(1970, 1, 1, tzinfo=UTC)


class TimestampError(ValueError):
    """The value is present but cannot be converted to a real time."""


@dataclass(frozen=True)
class Converted:
    ts: datetime
    original: str


def _add(epoch: datetime, microseconds: int, tag: str, raw: object) -> Converted:
    try:
        return Converted(epoch + timedelta(microseconds=microseconds), f"{tag}:{raw}")
    except OverflowError as exc:
        raise TimestampError(f"{tag} value out of range: {raw}") from exc


def filetime(value: int) -> Converted | None:
    """Windows FILETIME: 100 ns ticks since 1601-01-01 UTC (registry, NTFS, LNK, Prefetch)."""
    if value == 0:
        return None
    if value < 0 or value > 0x7FFF_FFFF_FFFF_FFFF:
        raise TimestampError(f"filetime value out of range: {value}")
    return _add(EPOCH_1601, value // 10, "filetime", value)


def webkit(value: int) -> Converted | None:
    """WebKit/Chrome time: microseconds since 1601-01-01 UTC."""
    if value == 0:
        return None
    if value < 0:
        raise TimestampError(f"webkit value out of range: {value}")
    return _add(EPOCH_1601, value, "webkit", value)


def prtime(value: int) -> Converted | None:
    """Mozilla PRTime: microseconds since 1970-01-01 UTC (Firefox places.sqlite)."""
    if value == 0:
        return None
    if value < 0:
        raise TimestampError(f"prtime value out of range: {value}")
    return _add(EPOCH_1970, value, "prtime", value)


def unix_seconds(value: object, *, tag: str = "unix") -> Converted | None:
    """Unix time in seconds (int or float, e.g. Zeek/pcap ``ts``)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TimestampError(f"{tag} value is not a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise TimestampError(f"{tag} value is not finite")
    if value == 0:
        return None
    if value < 0:
        raise TimestampError(f"{tag} value out of range: {value}")
    micros = value * 1_000_000 if isinstance(value, int) else round(value * 1_000_000)
    return _add(EPOCH_1970, micros, tag, value)


def unix_micros(value: int, *, tag: str = "unix_us") -> Converted | None:
    """Unix time in microseconds (journald ``__REALTIME_TIMESTAMP``)."""
    if value == 0:
        return None
    if value < 0:
        raise TimestampError(f"{tag} value out of range: {value}")
    return _add(EPOCH_1970, value, tag, value)


def iso_utc(value: str) -> Converted:
    """ISO-8601 string with an offset (or ``Z``) -> UTC; naive strings are rejected."""
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimestampError(f"not an ISO-8601 time: {text[:64]!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TimestampError("ISO-8601 time without an offset")
    return Converted(parsed.astimezone(UTC), value)
