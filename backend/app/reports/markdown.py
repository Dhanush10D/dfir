"""Safe Markdown for report sections and findings (analyst text and approved AI drafts).

CommonMark via markdown-it-py with raw HTML disabled (it is shown as escaped text), images disabled
(a report never fetches anything) and links limited to ``http``, ``https`` and ``mailto``. The
HTML goes into autoescaped Jinja templates as :class:`~markupsafe.Markup`; the PDF renderer uses
:func:`md_blocks`, a plain-text reduction (paragraphs, headings, list items, code blocks).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from markdown_it import MarkdownIt
from markdown_it.token import Token
from markupsafe import Markup

MAX_MARKDOWN_CHARS = 50_000
ALLOWED_SCHEMES = ("http://", "https://", "mailto:")


def _valid_link(url: str) -> bool:
    lowered = url.strip().lower()
    return lowered.startswith(ALLOWED_SCHEMES)


def _parser() -> MarkdownIt:
    md = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})
    md.disable(["image", "html_block", "html_inline"])
    md.validateLink = _valid_link  # type: ignore[method-assign]

    def link_open(self: Any, tokens: list[Token], idx: int, options: Any, env: Any) -> str:
        tokens[idx].attrSet("rel", "noopener noreferrer nofollow")
        return str(self.renderToken(tokens, idx, options, env))

    md.add_render_rule("link_open", link_open)
    return md


_MD = _parser()


def _clip(text: str | None) -> str:
    value = (text or "").replace("\x00", "")
    return value[:MAX_MARKDOWN_CHARS]


def md_to_html(text: str | None) -> Markup:
    """Sanitised HTML for untrusted Markdown (raw HTML escaped, unsafe links left as text)."""
    return Markup(_MD.render(_clip(text)))  # noqa: S704 - markdown-it output with html disabled


@dataclass(frozen=True)
class MdBlock:
    kind: str  # paragraph | heading | bullet | ordered | code | quote
    text: str
    level: int = 0  # heading level, or list nesting depth
    number: int | None = None  # ordered list item number


def _inline_text(token: Token) -> str:
    parts: list[str] = []
    href: str | None = None
    for child in token.children or []:
        if child.type in ("text", "code_inline"):
            parts.append(child.content)
        elif child.type in ("softbreak", "hardbreak"):
            parts.append(" " if child.type == "softbreak" else "\n")
        elif child.type == "link_open":
            href = str(child.attrGet("href") or "")
        elif child.type == "link_close":
            if href:
                parts.append(f" ({href})")
            href = None
    return "".join(parts)


def md_blocks(text: str | None) -> list[MdBlock]:
    """Plain-text blocks for renderers that cannot take HTML (the PDF)."""
    tokens = _MD.parse(_clip(text))
    blocks: list[MdBlock] = []
    list_stack: list[list[int]] = []  # [kind(0 bullet/1 ordered), next number]
    heading: int | None = None
    quote = 0
    for tok in tokens:
        if tok.type == "bullet_list_open":
            list_stack.append([0, 0])
        elif tok.type == "ordered_list_open":
            start = tok.attrGet("start")
            list_stack.append([1, int(start) if isinstance(start, int | str) else 1])
        elif tok.type in ("bullet_list_close", "ordered_list_close"):
            if list_stack:
                list_stack.pop()
        elif tok.type == "heading_open":
            heading = int(tok.tag[1:]) if tok.tag[1:].isdigit() else 1
        elif tok.type == "heading_close":
            heading = None
        elif tok.type == "blockquote_open":
            quote += 1
        elif tok.type == "blockquote_close":
            quote = max(0, quote - 1)
        elif tok.type in ("fence", "code_block"):
            blocks.append(MdBlock("code", tok.content.rstrip("\n")))
        elif tok.type == "inline":
            content = _inline_text(tok)
            if heading is not None:
                blocks.append(MdBlock("heading", content, level=heading))
            elif list_stack:
                kind, number = list_stack[-1]
                if kind == 1:
                    blocks.append(MdBlock("ordered", content, len(list_stack), number))
                    list_stack[-1][1] = number + 1
                else:
                    blocks.append(MdBlock("bullet", content, len(list_stack)))
            elif quote:
                blocks.append(MdBlock("quote", content))
            else:
                blocks.append(MdBlock("paragraph", content))
    return blocks
