"""Report rendering: safe Markdown, HTML escaping/CSP, deterministic PDF without active content."""

from __future__ import annotations

import base64
import re
import zlib
from typing import Any

import pytest

from app.reports.artifacts import KIND_ARTIFACTS, render_all, render_one
from app.reports.markdown import md_blocks, md_to_html
from app.reports.model import SECTIONS, build_view, content_sha256, default_sections
from app.reports.render_html import render_html
from app.reports.render_pdf import RenderLimitError, render_pdf
from tests.unit.report_fixtures import (
    sample_context,
    sample_findings,
    sample_meta,
    sample_sections,
)


def pdf_text(pdf: bytes) -> bytes:
    out = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        raw = m.group(1).strip()
        if raw.endswith(b"~>"):
            raw = raw[:-2]
        out += zlib.decompress(base64.a85decode(raw))
    return out


# ------------------------------------------------------------------ Markdown


@pytest.mark.parametrize(
    "text",
    [
        "<script>alert(1)</script>",
        '<img src=x onerror="alert(1)">',
        "<iframe src=//evil></iframe>",
        "<a href='javascript:alert(1)'>x</a>",
    ],
)
def test_markdown_escapes_raw_html(text: str) -> None:
    html = str(md_to_html(text))
    assert "<script" not in html and "<img" not in html and "<iframe" not in html
    assert "<a " not in html
    assert "&lt;" in html


@pytest.mark.parametrize(
    "link",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "vbscript:x",
        "data:text/html;base64,PHNjcmlwdD4=",
        "file:///etc/passwd",
        "//evil.example/x",
    ],
)
def test_markdown_drops_unsafe_links(link: str) -> None:
    html = str(md_to_html(f"[click]({link})"))
    assert "href" not in html


def test_markdown_keeps_safe_links_and_disables_images() -> None:
    html = str(
        md_to_html("[a](https://example.org) [m](mailto:x@example.org) ![i](https://e/x.png)")
    )
    assert 'href="https://example.org"' in html and 'rel="noopener noreferrer nofollow"' in html
    assert 'href="mailto:x@example.org"' in html
    assert "<img" not in html


def test_markdown_blocks_for_pdf() -> None:
    blocks = md_blocks("# Title\n\npara [l](https://x.y)\n\n- a\n- b\n\n1. one\n\n```\n<code>\n```")
    kinds = [(b.kind, b.text) for b in blocks]
    assert kinds == [
        ("heading", "Title"),
        ("paragraph", "para l (https://x.y)"),
        ("bullet", "a"),
        ("bullet", "b"),
        ("ordered", "one"),
        ("code", "<code>"),
    ]


def test_markdown_is_capped() -> None:
    assert len(str(md_to_html("a" * 200_000))) < 60_000


# ------------------------------------------------------------------ view


def test_view_numbers_parts_in_layout_order_and_labels_ai() -> None:
    sections = sample_sections()
    sections["executive_summary"] = {
        "text": "AI text",
        "origin": "ai_approved",
        "ai": {
            "interaction_id": "i-1",
            "reviewed_by_label": "Lee Lead",
            "reviewed_at": "2026-09-30T10:30:00Z",
            "model": "fake-strong",
            "prompt_version": "report_draft/1",
            "output_sha256": "9" * 64,
        },
    }
    view = build_view(sample_meta(), sample_context(), sections, sample_findings())
    numbers = [p["number"] for p in view["parts"]]
    assert numbers == list(range(1, len(numbers) + 1))
    first = view["parts"][0]
    assert first["name"] == "executive_summary"
    assert first["ai_label"].startswith("AI-drafted, approved by Lee Lead")
    assert view["ai_used"][0]["interaction_id"] == "i-1"
    sections["executive_summary"]["origin"] = "ai_edited"
    edited = build_view(sample_meta(), sample_context(), sections, [])
    assert "edited by an analyst" in edited["parts"][0]["ai_label"]


def test_default_sections_and_content_hash() -> None:
    for kind in SECTIONS:
        defaults = default_sections(kind)
        assert set(defaults) == {sd.name for sd in SECTIONS[kind]}
    a = content_sha256("t", {"s": {"text": "x"}}, [])
    assert a == content_sha256("t", {"s": {"text": "x"}}, [])
    assert a != content_sha256("t", {"s": {"text": "y"}}, [])


# ------------------------------------------------------------------ HTML


@pytest.mark.parametrize("kind", sorted(KIND_ARTIFACTS))
def test_html_escapes_every_hostile_string(kind: str) -> None:
    html = render_html(
        sample_meta(kind), sample_context(), sample_sections(kind), sample_findings()
    ).decode()
    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "javascript:" not in html.lower().replace("[link](javascript:alert(1))", "")
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "http://evil.example" not in html.split("&lt;img", 1)[0]  # never as a live reference
    assert not re.search(r"<(link|iframe|object|embed|form|base)\b", html, re.I)
    assert not re.search(r"\s(src|href)=\"(?!https?://|mailto:|#)", html)


def test_html_is_deterministic_and_marks_drafts() -> None:
    args: tuple[Any, ...] = (sample_context(), sample_sections(), sample_findings())
    a = render_html(sample_meta(), *args)
    assert a == render_html(sample_meta(), *args)
    draft = render_html(
        sample_meta(status="draft", status_label="DRAFT - not approved", signed_by=None), *args
    ).decode()
    assert "DRAFT - not approved" in draft and "not signed" in draft


# ------------------------------------------------------------------ PDF


def test_pdf_is_deterministic_and_has_no_active_content() -> None:
    args: tuple[Any, ...] = (sample_meta(), sample_context(), sample_sections(), sample_findings())
    a = render_pdf(*args)
    assert a == render_pdf(*args)
    assert a.startswith(b"%PDF-")
    for marker in (
        b"/JavaScript",
        b"/JS",
        b"/URI",
        b"/Launch",
        b"/EmbeddedFile",
        b"/OpenAction",
        b"/AA",
        b"/XObject",
        b"/AcroForm",
        b"/GoToR",
    ):
        assert marker not in a, marker
    text = pdf_text(a)
    assert b"IR-2026-0001" in text and b"evil.example" in text
    assert b"(script)" in text  # hostile markup shown as text, not interpreted


def test_pdf_replaces_non_latin1_and_says_so() -> None:
    ctx = sample_context()
    ctx["evidence"][0]["original_name"] = "файл-\U0001f600.evtx"
    pdf = render_pdf(sample_meta(), ctx, sample_sections(), sample_findings())
    text = pdf_text(pdf)
    assert b"characters outside the PDF" in text
    html = render_html(sample_meta(), ctx, sample_sections(), sample_findings()).decode()
    assert "файл" in html


def test_pdf_survives_huge_unbroken_values() -> None:
    ctx = sample_context()
    ctx["key_events"][0]["summary"] = "X" * 50_000
    ctx["evidence"][0]["original_name"] = "Y" * 20_000
    findings = sample_findings()
    findings[0]["body"] = "Z" * 40_000
    pdf = render_pdf(sample_meta(), ctx, sample_sections(), findings)
    assert pdf.startswith(b"%PDF-")


def test_pdf_page_cap_and_time_budget() -> None:
    args: tuple[Any, ...] = (sample_meta(), sample_context(), sample_sections(), sample_findings())
    unlimited = render_pdf(*args, time_budget_s=None)
    assert unlimited == render_pdf(*args)  # the budget check never changes the bytes
    with pytest.raises(RenderLimitError, match="pages"):
        render_pdf(*args, max_pages=1)
    with pytest.raises(RenderLimitError, match="seconds"):
        render_pdf(*args, time_budget_s=0)
    with pytest.raises(RenderLimitError):
        render_one("report.pdf", *args, time_budget_s=0)
    # formats without pages ignore the budget
    assert render_one("report.html", *args, time_budget_s=0).data


def test_every_kind_renders_all_its_artifacts() -> None:
    for kind, names in KIND_ARTIFACTS.items():
        arts = render_all(
            kind, sample_meta(kind), sample_context(), sample_sections(kind), sample_findings()
        )
        assert [a.name for a in arts] == list(names)
        assert all(a.data for a in arts)
    one = render_one(
        "report.json", sample_meta(), sample_context(), sample_sections(), sample_findings()
    )
    assert one.content_type == "application/json" and len(one.sha256) == 64
