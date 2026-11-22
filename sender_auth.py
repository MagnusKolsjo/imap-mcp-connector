# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Whether the receiving mail server verified a message's From domain.

The From address of a message is chosen by whoever sends it. Before a
sender's or domain's trust list is honoured, the connector therefore asks
whether the user's own mail server checked the message on arrival, as it
records in the Authentication-Results header (RFC 8601):

  * DMARC pass for the From domain (header.from must name it), or
  * DKIM pass with a signing domain (d=) aligned with the From domain, or
  * SPF pass with an envelope sender domain aligned with the From domain.

Aligned means the same domain or one a subdomain of the other, the
relaxed alignment DMARC uses.

A result's values can quote text the sender chose, such as the envelope
sender. Quoted strings are therefore taken out before the header is split
into results, so a ";" inside one cannot start a result of its own, and a
header with an unfinished quotation is not trusted at all.

Only the topmost Authentication-Results header is read. The receiving
server adds its own header above the ones already in the message, so a
header written by the sender ends up further down. A server that adds no
such header at all gives the sender's header the top place; this is the
one case the check cannot tell apart, and why the README asks for a mail
provider that records its checks. Without a header, or with a message
that names several From addresses, the sender counts as not verified.

Entry point:
    verify(message, from_domain) -> Verification
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message


@dataclass(frozen=True)
class Verification:
    verified: bool
    # "dmarc", "dkim" or "spf" when verified; otherwise why not:
    # "no_header", "no_from_domain", "failed".
    how: str


_COMMENT = re.compile(r"\([^()]*\)")
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
# What a quoted value may hold and still be read as a plain value: a domain
# or an address, nothing that could look like another result or property.
_PLAIN_VALUE = re.compile(r"[A-Za-z0-9.@_+-]*")
_PLACEHOLDER = "quoted"
_RESULT = re.compile(r"^\s*([a-z0-9-]+)\s*=\s*([a-z]+)\b(.*)$", re.IGNORECASE | re.DOTALL)
_PROPERTY = re.compile(r"\b([a-z]+\.[a-z0-9-]+)\s*=\s*\"?([^\s\";]+)", re.IGNORECASE)


def _strip_comments(text: str) -> str:
    # Comments may nest: remove the innermost until none are left.
    previous = None
    while previous != text:
        previous, text = text, _COMMENT.sub(" ", text)
    return text


def _unquote(text: str) -> str | None:
    """Replace quoted strings by their value, or a placeholder; None if a quote never ends."""
    def value(match: re.Match) -> str:
        inner = match.group(1)
        return inner if _PLAIN_VALUE.fullmatch(inner) else _PLACEHOLDER

    text = _QUOTED.sub(value, text)
    return None if '"' in text else text


def _aligned(domain: str, from_domain: str) -> bool:
    domain = domain.strip().lower().rstrip(".")
    if "@" in domain:
        domain = domain.rsplit("@", 1)[-1]
    if not domain or "." not in domain:
        return False
    return domain == from_domain or domain.endswith("." + from_domain) or from_domain.endswith("." + domain)


def parse_results(header: str) -> list[tuple[str, str, dict[str, str]]]:
    """(method, result, properties) for each result in one header value."""
    unquoted = _unquote(" ".join(str(header).split()))
    if unquoted is None:
        return []
    parts = _strip_comments(unquoted).split(";")
    results = []
    for part in parts[1:]:  # the first part is the server's own name
        match = _RESULT.match(part)
        if not match:
            continue
        props = {k.lower(): v for k, v in _PROPERTY.findall(match.group(3))}
        results.append((match.group(1).lower(), match.group(2).lower(), props))
    return results


def verify(message: Message | None, from_domain: str) -> Verification:
    """Check the topmost Authentication-Results header against the From domain."""
    from_domain = (from_domain or "").strip().lower()
    if not from_domain:
        return Verification(False, "no_from_domain")
    headers = message.get_all("Authentication-Results") if message is not None else None
    if not headers:
        return Verification(False, "no_header")
    for method, result, props in parse_results(headers[0]):
        if result != "pass":
            continue
        if method == "dmarc" and _aligned(props.get("header.from", ""), from_domain):
            return Verification(True, "dmarc")
        if method == "dkim" and _aligned(props.get("header.d") or props.get("header.i", ""), from_domain):
            return Verification(True, "dkim")
        if method == "spf" and _aligned(props.get("smtp.mailfrom", ""), from_domain):
            return Verification(True, "spf")
    return Verification(False, "failed")
