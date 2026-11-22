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
  * size, count and total limits per message, a time limit per network
    operation and one deadline for all of a message's images together, so
    a server that answers one byte at a time cannot hold the panel up.

Entry point:
    fetch_images(urls) -> dict[url, data_uri]
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

MAX_IMAGE_BYTES = int(os.getenv("IMAP_IMAGE_MAX_KB", "5120")) * 1024
MAX_IMAGES = int(os.getenv("IMAP_IMAGE_MAX_COUNT", "40"))
MAX_TOTAL_BYTES = int(os.getenv("IMAP_IMAGE_MAX_TOTAL_MB", "15")) * 1024 * 1024
TIMEOUT_SECONDS = float(os.getenv("IMAP_IMAGE_TIMEOUT", "10"))
# All images of one message together. TIMEOUT_SECONDS alone bounds each
# network operation, not how many of them a slow server can string together.
TOTAL_TIMEOUT_SECONDS = float(os.getenv("IMAP_IMAGE_TOTAL_TIMEOUT", "30"))
_CHUNK_BYTES = 64 * 1024
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


class _Budget:
    """Bytes left for one message's images, shared by the fetching threads."""

    def __init__(self, total: int) -> None:
        self.left = total
        self.lock = threading.Lock()

    def take(self, amount: int) -> bool:
        with self.lock:
            if amount > self.left:
                self.left = 0
                return False
            self.left -= amount
            return True

    def spent(self) -> bool:
        with self.lock:
            return self.left <= 0


def _fetch_one(url: str, budget: _Budget | None = None, deadline: float | None = None) -> tuple[str, str | None]:
    """Fetch one image; `deadline` is a time.monotonic() value after which nothing more is read."""
    if deadline is None:
        deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    remaining = deadline - time.monotonic()
    if not _acceptable_url(url) or (budget and budget.spent()) or remaining <= 0:
        return url, None
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "image/*"})
    try:
        with _OPENER.open(request, timeout=min(TIMEOUT_SECONDS, remaining)) as response:
            ctype = (response.headers.get_content_type() or "").lower()
            if ctype not in _SIGNATURES:
                return url, None
            # read1() returns after one read from the socket, so the deadline
            # is checked between reads however slowly the data arrives.
            chunks, size = [], 0
            while size <= MAX_IMAGE_BYTES:
                if time.monotonic() >= deadline:
                    return url, None
                chunk = response.read1(min(_CHUNK_BYTES, MAX_IMAGE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            data = b"".join(chunks)
    except (urllib.error.URLError, OSError, BlockedAddress, http.client.HTTPException, ValueError):
        return url, None
    if len(data) > MAX_IMAGE_BYTES or not data.startswith(_SIGNATURES[ctype]):
        return url, None
    if ctype == "image/webp" and data[8:12] != b"WEBP":
        return url, None
    if budget and not budget.take(len(data)):
        return url, None
    return url, f"data:{ctype};base64,{base64.b64encode(data).decode('ascii')}"


def fetch_images(urls: list[str]) -> dict[str, str]:
    """Fetch up to MAX_IMAGES distinct images; returns url -> data URI for those that passed."""
    unique = list(dict.fromkeys(u for u in urls if _acceptable_url(u)))[:MAX_IMAGES]
    # The budget is checked inside each fetch, so once it is spent no more
    # images are downloaded or kept: memory stays near MAX_TOTAL_BYTES plus
    # what the six threads are reading at that moment.
    budget = _Budget(MAX_TOTAL_BYTES)
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    with ThreadPoolExecutor(max_workers=6) as pool:
        pairs = list(pool.map(lambda u: _fetch_one(u, budget, deadline), unique))
    return {url: data_uri for url, data_uri in pairs if data_uri}
