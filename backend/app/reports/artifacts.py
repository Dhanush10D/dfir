"""Which artifacts each report kind produces, rendered from the stored inputs only."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from app.reports.exports import custody_json, iocs_csv, report_json, stix_json, timeline_csv
from app.reports.render_html import render_html
from app.reports.render_pdf import DEFAULT_TIME_BUDGET_S, render_pdf
from app.reports.seal import Artifact

# name -> (format, content type)
ARTIFACT_TYPES: dict[str, tuple[str, str]] = {
    "report.html": ("html", "text/html; charset=utf-8"),
    "report.pdf": ("pdf", "application/pdf"),
    "report.json": ("json", "application/json"),
    "iocs.stix.json": ("stix", "application/json"),
    "iocs.csv": ("csv", "text/csv; charset=utf-8"),
    "timeline.csv": ("timeline", "text/csv; charset=utf-8"),
    "custody.json": ("custody", "application/json"),
}

KIND_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "technical": (
        "report.html",
        "report.pdf",
        "report.json",
        "iocs.stix.json",
        "iocs.csv",
        "timeline.csv",
    ),
    "executive": ("report.html", "report.pdf", "report.json"),
    "custody": ("report.html", "report.pdf", "report.json", "custody.json"),
    "ioc": ("report.html", "report.json", "iocs.stix.json", "iocs.csv"),
}
FORMAT_TO_NAME = {fmt: name for name, (fmt, _) in ARTIFACT_TYPES.items()}


def _renderers(time_budget_s: float | None) -> dict[str, Callable[..., bytes]]:
    return {
        "report.html": lambda m, c, s, f: render_html(m, c, s, f),
        "report.pdf": lambda m, c, s, f: render_pdf(m, c, s, f, time_budget_s=time_budget_s),
        "report.json": lambda m, c, s, f: report_json(m, c, s, f),
        "iocs.stix.json": lambda m, c, s, f: stix_json(c, m),
        "iocs.csv": lambda m, c, s, f: iocs_csv(c),
        "timeline.csv": lambda m, c, s, f: timeline_csv(c),
        "custody.json": lambda m, c, s, f: custody_json(c),
    }


def render_one(
    name: str,
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    *,
    time_budget_s: float | None = DEFAULT_TIME_BUDGET_S,
) -> Artifact:
    """Render one artifact. Raises ``RenderLimitError`` past the PDF page cap or time budget."""
    fmt, content_type = ARTIFACT_TYPES[name]
    data = _renderers(time_budget_s)[name](meta, context, sections, findings)
    return Artifact(name=name, format=fmt, content_type=content_type, data=data)


def render_all(
    kind: str,
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
    *,
    time_budget_s: float | None = DEFAULT_TIME_BUDGET_S,
) -> list[Artifact]:
    return [
        render_one(n, meta, context, sections, findings, time_budget_s=time_budget_s)
        for n in KIND_ARTIFACTS[kind]
    ]
