# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Fetching a message's remote images for the mailbox panel, when the user allows it.

The panel runs in a sandbox that may not load anything from the network,
so images the user has chosen to see are fetched here and handed to the
panel inline, as data: URIs. Nothing is written to disk.

Fetching an image tells its sender that the message was opened, which is
why it only happens on the user's request or for senders and domains the
user trusts. It also means the server makes requests to addresses chosen
by whoever wrote the mail, so every request is constrained:

  * http and https only, no credentials in the URL, no cookies;
  * the connection must end up at a public address: the peer address is
    checked after connecting, on every redirect too, so a name that
    resolves to the local network (or changes its answer between lookup
    and connect) is refused;
  * only PNG, JPEG, GIF and WebP, checked by content type and by the file
    signature; SVG is never accepted;
  * size, count, total and time limits per message.

Entry point:
    fetch_images(urls) -> dict[url, data_uri]
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import os
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

MAX_IMAGE_BYTES = int(os.getenv("IMAP_IMAGE_MAX_KB", "5120")) * 1024
MAX_IMAGES = int(os.getenv("IMAP_IMAGE_MAX_COUNT", "40"))
MAX_TOTAL_BYTES = int(os.getenv("IMAP_IMAGE_MAX_TOTAL_MB", "15")) * 1024 * 1024
TIMEOUT_SECONDS = float(os.getenv("IMAP_IMAGE_TIMEOUT", "10"))
# A plain browser-like identity: identifying the connector would tell
# senders which tool the reader uses.
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"

_SIGNATURES = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": (b"RIFF",),
}


class BlockedAddress(Exception):
    """The connection would reach a non-public address."""


def _check_peer(sock: socket.socket) -> None:
    address = ipaddress.ip_address(sock.getpeername()[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not address.is_global or address.is_multicast:
        sock.close()
        raise BlockedAddress(f"{address} is not a public address")


class _CheckedHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        _check_peer(self.sock)


class _CheckedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # The plain TCP connection is checked before TLS is negotiated.
        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        _check_peer(self.sock)
        if self._tunnel_host:
            self._tunnel()
        server_hostname = self._tunnel_host or self.host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_CheckedHTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_CheckedHTTPSConnection, req, context=self._context)


class _RedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme not in ("http", "https"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# No cookie processor and no proxy handler: images are fetched anonymously.
_OPENER = urllib.request.OpenerDirector()
for handler in (_HTTPHandler(), _HTTPSHandler(), _RedirectHandler(),
                urllib.request.HTTPErrorProcessor(), urllib.request.HTTPDefaultErrorHandler(),
                urllib.request.UnknownHandler()):
    _OPENER.add_handler(handler)


def _acceptable_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.hostname) and not parts.username and not parts.password


def _fetch_one(url: str) -> tuple[str, str | None]:
    if not _acceptable_url(url):
        return url, None
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "image/*"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            ctype = (response.headers.get_content_type() or "").lower()
            if ctype not in _SIGNATURES:
                return url, None
            data = response.read(MAX_IMAGE_BYTES + 1)
    except (urllib.error.URLError, OSError, BlockedAddress, http.client.HTTPException, ValueError):
        return url, None
    if len(data) > MAX_IMAGE_BYTES or not data.startswith(_SIGNATURES[ctype]):
        return url, None
    if ctype == "image/webp" and data[8:12] != b"WEBP":
        return url, None
    return url, f"data:{ctype};base64,{base64.b64encode(data).decode('ascii')}"


def fetch_images(urls: list[str]) -> dict[str, str]:
    """Fetch up to MAX_IMAGES distinct images; returns url -> data URI for those that passed."""
    unique = list(dict.fromkeys(u for u in urls if _acceptable_url(u)))[:MAX_IMAGES]
    results: dict[str, str] = {}
    total = 0
    with ThreadPoolExecutor(max_workers=6) as pool:
        for url, data_uri in pool.map(_fetch_one, unique):
            if data_uri is None:
                continue
            total += len(data_uri)
            if total > MAX_TOTAL_BYTES * 4 // 3:  # base64 inflates by a third
                break
            results[url] = data_uri
    return results
