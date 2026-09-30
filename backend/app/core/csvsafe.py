"""CSV formula-injection guard shared by every CSV export (timeline search export, reports).

A cell that a spreadsheet would treat as a formula (``= + - @``, tab/CR/LF, their full-width forms,
also after leading spaces) is prefixed with ``'`` so it is shown as text.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Full-width forms too: some spreadsheets treat them as formula starts.
FULLWIDTH_FORMULA_PREFIXES = tuple(chr(c) for c in (0xFF1D, 0xFF0B, 0xFF0D, 0xFF20))
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n", *FULLWIDTH_FORMULA_PREFIXES)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def csv_cell(value: Any) -> str:
    """Text for a CSV cell; neutralises spreadsheet formulas (CSV injection)."""
    if value is None:
        return ""
    if isinstance(value, list):
        text = ";".join(str(v) for v in value)
    elif isinstance(value, datetime):
        text = _iso(value)
    else:
        text = str(value)
    if text.startswith(FORMULA_PREFIXES) or text.lstrip().startswith(FORMULA_PREFIXES):
        text = "'" + text
    return text
