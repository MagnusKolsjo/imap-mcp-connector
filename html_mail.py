# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Formatted (HTML) mail: sanitising, Markdown from the AI, quotations.

Replies follow the format of the message they answer: HTML for HTML mail,
plain text for plain-text mail. Every HTML part that leaves the connector
is a multipart/alternative with a plain-text version, and every piece of
HTML, whether typed in the panel's editor, converted from the AI's
Markdown or quoted from the original, passes through `sanitise()`.

The allowlist is ordinary text formatting only: paragraphs, line breaks,
bold, italic, underline, strike-through, headings, lists, links, block
quotes, preformatted text and simple tables. Scripts, styles, forms,
frames, images and every attribute except a link's address are removed.
Images are dropped from quotations too: remote images in mail are a
common way of tracking when, and whether, a message is read.

The quotation in a reply is wrapped in a marked element so that a reply
draft can be split again into the writer's text and the quotation, like
plain-text drafts are (see mail_parse.split_quote).

Entry points:
    sanitise(html) -> str
    markdown_to_html(text) -> str
    text_to_html(text) -> str
    quote_html(original_html_or_none, original_text, header_line) -> str
    forward_html(header_lines, original_html_or_none, original_text) -> str
    split_html_quote(html) -> (own_html, quote_html)
    to_plain(html) -> str
"""

from __future__ import annotations

import html as html_lib
import re

import markdown as markdown_lib
import nh3

import mail_parse

QUOTE_ATTRIBUTE = "data-imap-mcp-quote"

_TAGS = {
    "p", "br", "div", "span", "strong", "b", "em", "i", "u", "s", "strike", "del",
    "h1", "h2", "h3", "h4", "ul", "ol", "li", "a", "blockquote", "pre", "code",
    "hr", "table", "thead", "tbody", "tr", "th", "td", "sub", "sup",
}
_ATTRIBUTES = {
    "a": {"href", "title"},
    "div": {QUOTE_ATTRIBUTE},
    "blockquote": {"type"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
    "ol": {"start"},
}
_URL_SCHEMES = {"http", "https", "mailto"}


def _drop_invisible(text: str) -> str:
    # Same rule as plain text: characters that render as nothing for a
    # reader but are visible to a model are removed (see mail_parse).
    return "".join(ch for ch in text if ch in "\n\t" or not mail_parse._is_invisible(ch))


def sanitise(html: str) -> str:
    """Reduce HTML to the text-formatting allowlist described above."""
    return _drop_invisible(nh3.clean(
        html or "",
        tags=_TAGS,
        attributes=_ATTRIBUTES,
        url_schemes=_URL_SCHEMES,
        # Content of these elements is dropped with them, not kept as text.
        clean_content_tags={"script", "style", "template", "noscript", "title", "head"},
        link_rel="noopener noreferrer",
        strip_comments=True,
    ))


def markdown_to_html(text: str) -> str:
    """The AI writes simple Markdown; mail gets sanitised HTML.

    Only the basic syntax is enabled (paragraphs, lists, emphasis, links,
    quotes), matching the formatting the panel's editor offers. Raw HTML in
    the Markdown is escaped rather than passed through.
    """
    escaped = _drop_invisible(text).replace("<", "&lt;").replace(">", "&gt;")
    rendered = markdown_lib.markdown(escaped, extensions=["sane_lists", "nl2br"], output_format="html")
    return sanitise(rendered)


def text_to_html(text: str) -> str:
    """Plain text as HTML paragraphs, for quoting a plain-text original in HTML."""
    blocks = [b for b in re.split(r"\n\s*\n", text.strip()) if b.strip()]
    return "".join("<p>" + html_lib.escape(b).replace("\n", "<br>") + "</p>" for b in blocks)


def quote_html(original_html: str | None, original_text: str, header_line: str) -> str:
    """The quotation part of an HTML reply, marked so it can be split off again."""
    body = sanitise(original_html) if original_html else text_to_html(original_text)
    return (f'<div {QUOTE_ATTRIBUTE}="1"><p>{html_lib.escape(header_line)}</p>'
            f'<blockquote type="cite">{body}</blockquote></div>')


def forward_html(header_lines: list[str], original_html: str | None, original_text: str) -> str:
    """The forwarded message as HTML, with its headers on top."""
    head = "<br>".join(html_lib.escape(line) for line in header_lines)
    body = sanitise(original_html) if original_html else text_to_html(original_text)
    return f'<div {QUOTE_ATTRIBUTE}="1"><p>{head}</p>{body}</div>'


_QUOTE_START = re.compile(rf'<div\s+{QUOTE_ATTRIBUTE}="1"\s*>', re.IGNORECASE)


def split_html_quote(html: str) -> tuple[str, str]:
    """Split an HTML draft into (writer's HTML, quotation HTML).

    Only the marker this connector writes is recognised; anything else
    stays in the writer's part, so nothing is hidden or lost.
    """
    match = None
    for match in _QUOTE_START.finditer(html or ""):
        pass
    if not match:
        return html or "", ""
    return html[: match.start()].rstrip(), html[match.start():]


def to_plain(html: str) -> str:
    """The plain-text alternative of an HTML part."""
    return mail_parse.html_to_text(html or "")
