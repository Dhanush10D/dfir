"""PDF renderer: ReportLab platypus over the same view as the HTML renderer.

* Deterministic: ``invariant=1`` fixes the creation date and document id, all dates come from the
  snapshot/meta, so the same inputs give the same bytes (the verifier relies on this).
* No active content: no JavaScript, no links, no forms, no images, no embedded files. Every text
  value is XML-escaped before it reaches ReportLab's paragraph markup, so evidence text cannot add
  ``<img>``, ``<a>`` or ``<font>`` tags; ReportLab's trusted schemes/hosts are emptied as defence
  in depth, so nothing can be fetched from a URL or read from a local path.
* Built-in Helvetica/Courier fonts (no font files are read). Characters outside Windows-1252 are
  replaced with ``?`` and the PDF says how many; the HTML and JSON artifacts keep the exact text.
* Size: table cells and long unbroken tokens are shortened/broken so a hostile value cannot make a
  row taller than a page.
"""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from typing import Any
from xml.sax.saxutils import escape

from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import Flowable

from app.reports.markdown import md_blocks
from app.reports.model import build_view

# Defence in depth: nothing in a report may be fetched or read from a URL/path.
rl_config.trustedSchemes = []
rl_config.trustedHosts = []

MAX_CELL_CHARS = 400
MAX_TOKEN = 60
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LONG_TOKEN = re.compile(r"\S{" + str(MAX_TOKEN + 1) + ",}")


class _Text:
    """Converts untrusted text into safe ReportLab paragraph markup, counting replacements."""

    def __init__(self) -> None:
        self.replaced = 0

    def plain(self, value: Any, limit: int | None = None) -> str:
        """Cleaned text without markup escaping (for canvas strings and document info)."""
        text = "" if value is None else str(value)
        if limit is not None and len(text) > limit:
            text = text[: limit - 3] + "..."
        text = _CONTROL.sub(" ", text).replace("\r", "")
        out = []
        for ch in text:
            try:
                ch.encode("cp1252")
                out.append(ch)
            except UnicodeEncodeError:
                self.replaced += 1
                out.append("?")
        text = "".join(out)
        text = _LONG_TOKEN.sub(
            lambda m: " ".join(
                m.group(0)[i : i + MAX_TOKEN] for i in range(0, len(m.group(0)), MAX_TOKEN)
            ),
            text,
        )
        return text

    def clean(self, value: Any, limit: int | None = None) -> str:
        """Paragraph markup: cleaned, then XML-escaped (evidence text cannot add tags)."""
        return escape(self.plain(value, limit)).replace("\n", "<br/>")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5)
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold"),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold"),
        "body": body,
        "muted": ParagraphStyle("muted", parent=body, fontSize=8, textColor=colors.grey),
        "ai": ParagraphStyle(
            "ai", parent=body, fontSize=8, backColor=colors.HexColor("#fde7c2"), borderPadding=2
        ),
        "warn": ParagraphStyle("warn", parent=body, textColor=colors.HexColor("#8a4b00")),
        "bad": ParagraphStyle("bad", parent=body, textColor=colors.HexColor("#aa0000")),
        "cell": ParagraphStyle(
            "cell", parent=body, fontSize=7.5, leading=9, alignment=TA_LEFT, wordWrap="CJK"
        ),
        "mono": ParagraphStyle(
            "mono", parent=body, fontName="Courier", fontSize=7, leading=8.5, wordWrap="CJK"
        ),
        "code": ParagraphStyle(
            "code",
            parent=body,
            fontName="Courier",
            fontSize=7.5,
            leading=9,
            wordWrap="CJK",
            backColor=colors.HexColor("#f3f3f3"),
        ),
    }


class _Builder:
    def __init__(self, view: Mapping[str, Any]) -> None:
        self.view = view
        self.t = _Text()
        self.s = _styles()
        self.story: list[Flowable] = []
        self.width = A4[0] - 36 * mm

    def p(self, text: Any, style: str = "body", limit: int | None = None) -> Paragraph:
        return Paragraph(self.t.clean(text, limit), self.s[style])

    def add(self, text: Any, style: str = "body") -> None:
        self.story.append(self.p(text, style))

    def markdown(self, text: str) -> None:
        blocks = md_blocks(text)
        if not blocks:
            self.add("(empty)", "muted")
            return
        for b in blocks:
            if b.kind == "heading":
                self.story.append(self.p(b.text, "h3"))
            elif b.kind == "bullet":
                self.story.append(
                    Paragraph(
                        "&bull; " + self.t.clean(b.text),
                        ParagraphStyle("li", parent=self.s["body"], leftIndent=8 * b.level),
                    )
                )
            elif b.kind == "ordered":
                self.story.append(
                    Paragraph(
                        f"{b.number}. " + self.t.clean(b.text),
                        ParagraphStyle("oli", parent=self.s["body"], leftIndent=8 * b.level),
                    )
                )
            elif b.kind == "code":
                self.story.append(self.p(b.text, "code"))
            elif b.kind == "quote":
                self.story.append(
                    Paragraph(
                        self.t.clean(b.text),
                        ParagraphStyle("q", parent=self.s["body"], leftIndent=12),
                    )
                )
            else:
                self.add(b.text)

    def table(
        self, header: Sequence[str], rows: Sequence[Sequence[Any]], widths: Sequence[float]
    ) -> None:
        mono_cols = {i for i, h in enumerate(header) if h.startswith("~")}
        head = [self.p(h.lstrip("~"), "cell") for h in header]
        data: list[list[Any]] = [head]
        for row in rows:
            data.append(
                [
                    self.p(v, "mono" if i in mono_cols else "cell", MAX_CELL_CHARS)
                    for i, v in enumerate(row)
                ]
            )
        total = sum(widths)
        table = Table(
            data, colWidths=[self.width * w / total for w in widths], repeatRows=1, hAlign="LEFT"
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        self.story.append(table)
        self.story.append(Spacer(1, 4))

    # ------------------------------------------------------------------ document parts

    def cover(self) -> None:
        v, meta, case = self.view, self.view["meta"], self.view["case"]
        self.add(f"{v['org']} - {(case.get('classification') or 'unclassified').upper()}", "muted")
        self.story.append(self.p(meta.get("title") or case.get("title"), "title"))
        self.add(f"{v['kind_title']} - Case {case.get('case_number')}: {case.get('title')}")
        approved = (
            f"{meta['approved_by']} at {meta['approved_at']}"
            if meta.get("approved_by")
            else "not approved"
        )
        signed = (
            f"{meta['signed_by']} at {meta['signed_at']} (key {meta['key_id']})"
            if meta.get("signed_by")
            else "not signed"
        )
        self.table(
            ["Field", "Value"],
            [
                [
                    "Report",
                    f"{meta['report_id']} (family {meta['family_id']}), version {meta['version']}",
                ],
                ["Status", meta["status_label"]],
                ["Author", meta["author"]],
                ["Data snapshot", f"{v['generated_at']} by {v['generated_by']}"],
                ["Approved", approved],
                ["Signed", signed],
                [
                    "Case",
                    f"severity {case.get('severity')}, status {case.get('status')}, "
                    f"opened {case.get('opened_at')}",
                ],
            ],
            [1, 4],
        )

    def part(self, part: Mapping[str, Any]) -> None:
        v = self.view
        self.story.append(self.p(f"{part['number']}. {part['title']}", "h2"))
        name = part["name"]
        if part["type"] == "section":
            if part.get("ai_label"):
                self.add(part["ai_label"], "ai")
            self.markdown(part["text"])
            return
        if name == "runs":
            if not v["runs"]:
                self.add("No processing runs.", "muted")
            else:
                self.table(
                    ["Evidence", "Kind", "Parser / version", "Outcome", "Read / events", "~Tools"],
                    [
                        [
                            r["evidence_label"],
                            r["kind"],
                            f"{r['parser']} {r['parser_version']}",
                            r["outcome"],
                            f"{r['records_read']} / {r['events_emitted']}",
                            r["tools"],
                        ]
                        for r in v["runs"]
                    ],
                    [1, 0.8, 1.4, 0.8, 0.9, 2.5],
                )
        elif name == "evidence":
            if not v["evidence"]:
                self.add("No evidence.", "muted")
            else:
                self.table(
                    ["ID", "Name / kind", "Source", "~Hashes", "Size", "Acquired", "Custody"],
                    [
                        [
                            e["label"],
                            f"{e['original_name']} ({e['kind']})",
                            e["source_host"],
                            f"SHA-256 {e['sha256'] or 'missing'} MD5 {e['md5'] or '-'}",
                            e["size_bytes"],
                            f"{e['acquired_at'] or '-'} {e['acquired_by'] or ''}",
                            "verified" if e["custody_ok"] else "NOT VERIFIED",
                        ]
                        for e in v["evidence"]
                    ],
                    [0.7, 1.3, 0.9, 2.2, 0.7, 1.1, 0.8],
                )
        elif name == "key_events":
            if not v["key_events"]:
                self.add("No bookmarked or alert-linked events.", "muted")
            else:
                self.table(
                    ["~Time (UTC)", "Host / user", "Source", "Event", "Evidence"],
                    [
                        [
                            ev["ts"],
                            f"{ev['host'] or ''} {ev['user'] or ''}",
                            f"{ev['source_type']} {ev['event_code'] or ''}",
                            f"{ev['summary']} [event {ev['id']}]",
                            ev["evidence_label"],
                        ]
                        for ev in v["key_events"]
                    ],
                    [1.2, 1.1, 0.9, 3.2, 0.7],
                )
            if v["truncated"].get("key_events"):
                self.add("Key events were truncated to the snapshot cap.", "warn")
        elif name == "findings":
            if not v["findings"]:
                self.add("No findings.", "muted")
            for f in v["findings"]:
                block: list[Flowable] = [
                    self.p(f"{part['number']}.{f['number']} {f['title']}", "h3")
                ]
                self.story.extend(block)
                if f.get("ai_label"):
                    self.add(f["ai_label"], "ai")
                self.markdown(f.get("body") or "")
                self.add(
                    f"Confidence: {f.get('confidence')} - Source of statement: {f['source']}"
                    + (f" - ATT&CK: {', '.join(f.get('attack') or [])}" if f.get("attack") else ""),
                    "muted",
                )
                self.table(
                    ["Evidence reference", "~Time (UTC)", "Summary"],
                    [
                        [f"{r['type']} {r['label']} ({r['id']})", r.get("ts") or "-", r["summary"]]
                        for r in f.get("refs") or []
                    ],
                    [2, 1.2, 3],
                )
        elif name == "iocs":
            if not v["iocs"]:
                self.add("No active indicators.", "muted")
            else:
                self.table(
                    ["Type", "~Value", "TLP", "Confidence", "Source"],
                    [
                        [i["type"], i["value"], i["tlp"], i["confidence"], i["source"]]
                        for i in v["iocs"]
                    ],
                    [0.8, 3, 0.6, 0.8, 1.2],
                )
        elif name == "attack":
            if not v["attack"]:
                self.add("No ATT&CK techniques observed.", "muted")
            else:
                self.table(
                    ["Technique", "Alerts", "Events"],
                    [[a["technique"], a["alerts"], a["events"]] for a in v["attack"]],
                    [2, 1, 1],
                )
        elif name == "custody":
            self.table(
                ["Evidence", "Entries", "Verification", "~Head hash"],
                [
                    [
                        c["label"],
                        c["entries_total"],
                        "verified"
                        if c["ok"]
                        else "FAILED: "
                        + "; ".join(f"{p['code']} at seq {p['seq']}" for p in c["problems"]),
                        c["head_hash"],
                    ]
                    for c in v["custody"]
                ],
                [1, 0.6, 2, 2.4],
            )
        elif name == "custody_full":
            if not v["custody"]:
                self.add("No evidence.", "muted")
            for c in v["custody"]:
                status = "verified" if c["ok"] else "verification FAILED"
                self.story.append(self.p(f"{c['label']}: {status}", "h3" if c["ok"] else "bad"))
                for p in c["problems"]:
                    self.add(f"seq {p['seq']}: {p['code']} - {p['message']}", "bad")
                self.table(
                    ["Seq", "~Time (UTC)", "Actor", "Action", "~Detail", "~Entry hash / key"],
                    [
                        [
                            e["seq"],
                            e["ts"],
                            e["actor"],
                            e["action"],
                            e["detail"],
                            f"{e['entry_hash']} {e['key_id']}",
                        ]
                        for e in c["entries"]
                    ],
                    [0.4, 1.2, 1.3, 0.8, 2, 2],
                )
                if c["entries_truncated"]:
                    self.add("Custody entries were truncated to the snapshot cap.", "warn")
        elif name == "alerts":
            if not v["alerts"]:
                self.add("No alerts.", "muted")
            else:
                self.table(
                    ["Severity", "Title", "Status", "Host / user", "~First / last seen", "Events"],
                    [
                        [
                            a["severity"],
                            a["title"],
                            a["status"],
                            f"{a['host'] or ''} {a['user'] or ''}",
                            f"{a['first_seen']} {a['last_seen']}",
                            a["event_count"],
                        ]
                        for a in v["alerts"]
                    ],
                    [0.7, 2.2, 0.8, 1.2, 1.5, 0.6],
                )
        elif name == "overview":
            counts = v["counts"]
            sev = ", ".join(
                f"{k} {n}" for k, n in sorted((counts.get("alerts_by_severity") or {}).items())
            )
            self.table(
                ["Figure", "Value"],
                [
                    ["Evidence items", counts.get("evidence")],
                    ["Events in the timeline", counts.get("events")],
                    ["Alerts", f"{counts.get('alerts')} ({sev})" if sev else counts.get("alerts")],
                    ["Active indicators", counts.get("iocs")],
                    [
                        "Custody chains verified",
                        f"{counts.get('custody_ok')} of {counts.get('evidence')}",
                    ],
                ],
                [2, 3],
            )
        elif name == "provenance":
            self.add(
                "This report was rendered from an immutable data snapshot. Re-rendering the "
                "snapshot gives the same bytes; the signed manifest lists the SHA-256 of every "
                "artifact."
            )
            rows = [
                ["Snapshot SHA-256", v["context_sha256"]],
                ["Content SHA-256", v["content_sha256"]],
            ] + [[f"Included {k} SHA-256", h] for k, h in sorted(v["input_hashes"].items())]
            self.table(["Item", "~SHA-256"], rows, [1.5, 3])
            if v["ai_used"]:
                self.add(
                    "Parts of this report were drafted by an AI model and accepted by a named "
                    "person before they were included. They are labelled where they appear."
                )
                self.table(
                    ["Where", "Approved by", "Model / prompt", "~Interaction / output SHA-256"],
                    [
                        [
                            a.get("where"),
                            f"{a.get('reviewed_by_label')} at {a.get('reviewed_at')}",
                            f"{a.get('model')} / {a.get('prompt_version')}",
                            f"{a.get('interaction_id')} {a.get('output_sha256')}",
                        ]
                        for a in v["ai_used"]
                    ],
                    [1.2, 1.5, 1.3, 2.5],
                )
            else:
                self.add("No AI-drafted text is included in this report.", "muted")

    def build(self) -> list[Flowable]:
        self.cover()
        for part in self.view["parts"]:
            self.part(part)
        if self.t.replaced:
            self.add(
                f"Note: {self.t.replaced} characters outside the PDF's built-in font were "
                "replaced with '?'. The HTML and JSON artifacts contain the exact text.",
                "warn",
            )
        return self.story


def render_pdf(
    meta: Mapping[str, Any],
    context: Mapping[str, Any],
    sections: Mapping[str, Any],
    findings: Sequence[Mapping[str, Any]],
) -> bytes:
    view = build_view(meta, context, sections, findings)
    builder = _Builder(view)
    story = builder.build()
    case = view["case"]
    clean = _Text()
    footer = (
        f"{case.get('case_number')} - {view['kind_title']} v{meta['version']} - "
        f"{meta['status_label']} - {(case.get('classification') or '').upper()}"
    )
    footer_text = clean.plain(footer, 150)

    def on_page(canvas: Canvas, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(18 * mm, 10 * mm, footer_text)
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=clean.plain(f"{case.get('case_number')} {view['kind_title']} v{meta['version']}"),
        author=clean.plain(meta.get("author"), 200),
        subject=clean.plain(view["kind_title"]),
        creator="dfirbench",
        producer="dfirbench",
        invariant=1,
    )
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()
