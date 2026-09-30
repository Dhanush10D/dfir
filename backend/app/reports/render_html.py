"""HTML renderer: Jinja2 (autoescape, StrictUndefined) over :func:`app.reports.model.build_view`.

Every evidence-derived value is escaped by the template engine; section and finding text goes
through the safe Markdown filter. The page references nothing external (inline CSS only) and
carries its own restrictive Content-Security-Policy meta tag in addition to the HTTP header the
API sends with previews and downloads.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from app.reports.markdown import md_to_html
from app.reports.model import build_view

# Sent with every HTML preview/download (and repeated as a meta tag inside the document).
HTML_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'self'; sandbox"
)


@lru_cache(maxsize=1)
def _env() -> Environment:
    env = Environment(
        loader=PackageLoader("app.reports", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    env.filters["md"] = md_to_html
    return env


def render_html(
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> bytes:
    view = build_view(meta, context, sections, findings)
    return _env().get_template("report.html.j2").render(**view).encode("utf-8")
