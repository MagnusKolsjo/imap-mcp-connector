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
from html.parser import HTMLParser

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


class _HiddenRemover(HTMLParser):
    """Re-emits HTML without the elements a reader would not see.

    Uses the same rules as the reading view (mail_parse): hidden attributes,
    aria-hidden and the usual CSS ways of hiding text, inline or through a
    simple rule in the message's style sheet. Removing the style
    attribute alone, as the sanitiser does, would make such text visible in
    a quotation instead of leaving it out.
    """

    def __init__(self, hidden_classes: frozenset[str] = frozenset(), hidden_ids: frozenset[str] = frozenset()) -> None:
        super().__init__(convert_charrefs=False)
        self.hidden_classes, self.hidden_ids = hidden_classes, hidden_ids
        self.out: list[str] = []
        self.stack: list[tuple[str, bool]] = []
        self.skip = 0

    def _hidden(self, tag: str, attrs: dict) -> bool:
        if tag in mail_parse._SKIP_TAGS or "hidden" in attrs or attrs.get("aria-hidden") == "true":
            return True
        if mail_parse.hidden_by_stylesheet(attrs, self.hidden_classes, self.hidden_ids):
            return True
        return bool(mail_parse._HIDDEN_STYLE.search(attrs.get("style") or ""))

    def _emit_start(self, tag, attrs, closed=False):
        rendered = "".join(f' {k}="{html_lib.escape(v or "", quote=True)}"' for k, v in attrs)
        self.out.append(f"<{tag}{rendered}{' /' if closed else ''}>")

    def handle_starttag(self, tag, attrs):
        attr = {k.lower(): v for k, v in attrs}
        if tag in mail_parse._VOID_TAGS:
            if not self.skip:
                self._emit_start(tag, attrs)
            return
        hidden = self._hidden(tag, attr)
        self.stack.append((tag, hidden))
        if hidden:
            self.skip += 1
        elif not self.skip:
            self._emit_start(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        if tag in mail_parse._VOID_TAGS:
            if not self.skip:
                self._emit_start(tag, attrs)
            return
        # HTML5 ignores "/>" on non-void elements: <div style="display:none"/>
        # opens a hidden element like <div ...> does, and browsers and the
        # sanitiser treat it so; this parser must agree.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag in mail_parse._VOID_TAGS or all(t != tag for t, _ in self.stack):
            return
        while self.stack:
            open_tag, hidden = self.stack.pop()
            if hidden:
                self.skip -= 1
            elif not self.skip:
                self.out.append(f"</{open_tag}>")
            if open_tag == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)

    def handle_entityref(self, name):
        if not self.skip:
            self.out.append(f"&{name};")

    def handle_charref(self, name):
        if not self.skip:
            self.out.append(f"&#{name};")


def _drop_hidden(html: str) -> str:
    parser = _HiddenRemover(*mail_parse.hidden_selectors(html or ""))
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:  # noqa: BLE001 - malformed HTML: keep what was parsed
        pass
    return "".join(parser.out)


def sanitise(html: str, keep_quote_marker: bool = False) -> str:
    """Reduce HTML to the text-formatting allowlist described above.

    The quote marker is stripped by default, so that no received mail and
    nothing typed or written by the AI can carry it. Only HTML this
    connector assembled itself (a stored draft) is cleaned with
    keep_quote_marker=True.
    """
    attributes = dict(_ATTRIBUTES)
    if keep_quote_marker:
        attributes["div"] = {QUOTE_ATTRIBUTE}
    return _drop_invisible(nh3.clean(
        _drop_hidden(html or ""),
        tags=_TAGS,
        attributes=attributes,
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
    # The first marker is the connector's own: quoted content never carries
    # one, because sanitise() strips it from everything that comes from
    # outside.
    match = _QUOTE_START.search(html or "")
    if not match:
        return html or "", ""
    return html[: match.start()].rstrip(), html[match.start():]


def to_plain(html: str) -> str:
    """The plain-text alternative of an HTML part."""
    return mail_parse.html_to_text(html or "")


# -----------------------------------------------------------------------------
# Reading in the panel: images and, for trusted content, layout
# -----------------------------------------------------------------------------

# Layout that keeps newsletters readable without loading anything: no
# url(), no positioning, no fonts from elsewhere (property names only;
# values that would load resources are refused by the panel's sandbox).
_SAFE_STYLE_PROPERTIES = {
    "color", "background-color", "text-align", "vertical-align", "font-weight", "font-style",
    "font-size", "line-height", "text-decoration", "width", "max-width", "min-width", "height",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "border", "border-top", "border-right", "border-bottom", "border-left", "border-collapse",
    "border-color", "border-width", "border-style", "border-radius", "display",
}
_STYLED_TAGS = {"p", "div", "span", "table", "thead", "tbody", "tr", "td", "th", "h1", "h2", "h3", "h4",
                "a", "ul", "ol", "li", "blockquote", "img", "strong", "em", "b", "i", "u", "center", "font"}
_IMG = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_SRC = re.compile(r'\ssrc="([^"]*)"', re.IGNORECASE)


def image_sources(html: str) -> list[str]:
    """The src of every image in (sanitised or raw) HTML."""
    return [html_lib.unescape(m.group(1)) for tag in _IMG.findall(html or "") for m in [_SRC.search(tag)] if m]


def remote_image_sources(html: str) -> list[str]:
    """http(s) image addresses a reader would see.

    Images inside hidden elements are left out: they are never shown, so
    fetching them would only tell the sender the message was opened.
    """
    return [u for u in image_sources(_drop_hidden(html or "")) if u.lower().startswith(("http://", "https://"))]


def sanitise_for_reading(
    html: str,
    cid_images: dict[str, str] | None = None,
    remote_images: dict[str, str] | None = None,
    allow_styles: bool = False,
) -> tuple[str, int]:
    """HTML for the reading pane; returns (html, number of images left out).

    Images whose src is a cid: reference to a part of the message, or a
    remote address present in `remote_images`, get that data: URI as src;
    every other image is removed. With allow_styles a safe subset of inline
    CSS is kept (trusted senders), otherwise all styles are removed.
    """
    attributes = {tag: set(attrs) for tag, attrs in _ATTRIBUTES.items()}
    attributes["img"] = {"src", "alt", "width", "height"}
    if allow_styles:
        for tag in _STYLED_TAGS:
            attributes.setdefault(tag, set()).add("style")
        for tag in ("td", "th", "table", "img"):
            attributes[tag].update({"width", "height", "align", "valign", "bgcolor"})
    cleaned = _drop_invisible(nh3.clean(
        _drop_hidden(html or ""),
        tags=_TAGS | {"img", "center", "font"},
        attributes=attributes,
        url_schemes=_URL_SCHEMES | {"cid"},
        clean_content_tags={"script", "style", "template", "noscript", "title", "head"},
        link_rel="noopener noreferrer",
        strip_comments=True,
        filter_style_properties=_SAFE_STYLE_PROPERTIES if allow_styles else None,
    ))
    cid_images = {k.lower(): v for k, v in (cid_images or {}).items()}
    remote_images = remote_images or {}
    left_out = 0

    def replace(match: re.Match) -> str:
        nonlocal left_out
        tag = match.group(0)
        src_match = _SRC.search(tag)
        src = html_lib.unescape(src_match.group(1)) if src_match else ""
        if src.lower().startswith("cid:"):
            data = cid_images.get(src[4:].strip("<>").lower())
        else:
            data = remote_images.get(src)
        if not data:
            left_out += 1
            return ""
        return _SRC.sub(f' src="{data}"', tag, count=1)

    return _IMG.sub(replace, cleaned), left_out
