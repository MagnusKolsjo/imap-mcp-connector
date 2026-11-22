# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Remote images and layout in HTML mail: proxy limits, trust lists, inline images."""

from __future__ import annotations

import asyncio
import base64
import http.server
import threading

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import image_proxy
import mcp_server

PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


class Handler(http.server.BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        status, ctype, body, extra = self.routes.get(self.path, (404, "text/plain", b"no", {}))
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def web():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    Handler.routes = {
        "/ok.png": (200, "image/png", PNG, {}),
        "/fake.png": (200, "image/png", b"<svg onload=x>", {}),
        "/x.svg": (200, "image/svg+xml", b"<svg/>", {}),
        "/big.png": (200, "image/png", PNG + b"0" * 4096, {}),
        "/to-file": (302, "text/plain", b"", {"Location": "file:///etc/passwd"}),
    }
    yield base
    server.shutdown()


def test_local_addresses_are_blocked(web):
    assert image_proxy.fetch_images([f"{web}/ok.png"]) == {}


@pytest.fixture
def allow_local(monkeypatch):
    monkeypatch.setattr(image_proxy, "_check_peer", lambda sock: None)


def test_valid_png_is_inlined(web, allow_local):
    result = image_proxy.fetch_images([f"{web}/ok.png"])
    assert result[f"{web}/ok.png"].startswith("data:image/png;base64,")


@pytest.mark.parametrize("path", ["/fake.png", "/x.svg", "/to-file", "/missing"])
def test_bad_images_are_refused(web, allow_local, path):
    assert image_proxy.fetch_images([f"{web}{path}"]) == {}


def test_size_limit(web, allow_local, monkeypatch):
    monkeypatch.setattr(image_proxy, "MAX_IMAGE_BYTES", len(PNG) + 10)
    assert image_proxy.fetch_images([f"{web}/big.png"]) == {}


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y.png", "http://user:pw@example.com/a.png",
                                 "javascript:alert(1)", "data:image/png;base64,AAAA"])
def test_unacceptable_urls_are_not_fetched(url):
    assert image_proxy.fetch_images([url]) == {}


def test_count_limit(web, allow_local, monkeypatch):
    monkeypatch.setattr(image_proxy, "MAX_IMAGES", 2)
    urls = [f"{web}/ok.png?{i}" for i in range(5)]
    Handler.routes.update({f"/ok.png?{i}": (200, "image/png", PNG, {}) for i in range(5)})
    assert len(image_proxy.fetch_images(urls)) == 2


# -----------------------------------------------------------------------------
# Reading in the panel
# -----------------------------------------------------------------------------

NEWSLETTER = (
    b"From: Nyheter <news@shop.example>\r\nTo: test@example.com\r\nSubject: Rea\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: multipart/related; boundary=r\r\n\r\n"
    b"--r\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    b'<p style="color:#c00">Rea</p><img src="cid:logo@shop" alt="Logo">'
    b'<img src="https://cdn.shop.example/hero.png" alt="Bild">\r\n'
    b"--r\r\nContent-Type: image/png\r\nContent-ID: <logo@shop>\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    + base64.b64encode(PNG) + b"\r\n--r--\r\n"
)


VERIFIED = b"Authentication-Results: mx.example.com; dkim=pass header.d=shop.example; spf=pass smtp.mailfrom=bounce.shop.example\r\n"


def open_in_panel(fake_server, raw=NEWSLETTER, **extra):
    uid = fake_server.store.add_message("INBOX", raw, ())
    validity = fake_server.store.folder("INBOX").uidvalidity
    result = asyncio.run(mcp_server.mcp.call_tool("imap_panel_open", {
        "account": "test", "folder": "INBOX", "uid": uid, "uidvalidity": validity, **extra}))
    return result.structured_content


@pytest.fixture
def fetched(monkeypatch):
    calls = []

    def fake(urls):
        calls.append(list(urls))
        return {u: "data:image/png;base64,REMOTE" for u in urls}

    monkeypatch.setattr(image_proxy, "fetch_images", fake)
    return calls


def test_inline_images_always_shown_remote_blocked(account, fake_server, fetched):
    data = open_in_panel(fake_server)
    assert "data:image/png;base64," in data["body_html"] and "REMOTE" not in data["body_html"]
    assert data["external"]["loaded"] is False and data["external"]["images_left_out"] == 1
    assert data["external"]["has_remote_content"] is True and "style=" not in data["body_html"]
    assert fetched == []                                    # nothing contacted the sender


def test_load_for_this_message(account, fake_server, fetched):
    data = open_in_panel(fake_server, load_external=True)
    assert "REMOTE" in data["body_html"] and 'style="color:#c00"' in data["body_html"]
    assert fetched == [["https://cdn.shop.example/hero.png"]]


@pytest.mark.parametrize("kind,value", [("sender", "news@shop.example"), ("domain", "shop.example")])
def test_trusted_sender_or_domain_loads_automatically(account, fake_server, fetched, kind, value):
    asyncio.run(mcp_server.mcp.call_tool("imap_panel_trust", {"account": "test", "kind": kind, "value": value}))
    data = open_in_panel(fake_server, VERIFIED + NEWSLETTER)
    assert data["external"]["trusted"] is True and "REMOTE" in data["body_html"]
    assert data["external"]["sender_verified"] is True
    asyncio.run(mcp_server.mcp.call_tool("imap_panel_trust",
                                         {"account": "test", "kind": kind, "value": value, "remove": True}))
    assert open_in_panel(fake_server, VERIFIED + NEWSLETTER)["external"]["trusted"] is False


def test_trusted_but_unverified_sender_loads_nothing(account, fake_server, fetched):
    asyncio.run(mcp_server.mcp.call_tool("imap_panel_trust", {"account": "test", "kind": "domain", "value": "shop.example"}))
    data = open_in_panel(fake_server)                       # no Authentication-Results at all
    ext = data["external"]
    assert ext["trusted"] is False and ext["listed_via"] == "domain" and ext["sender_verified"] is False
    assert fetched == [] and "REMOTE" not in data["body_html"]
    # A header further down (written by the sender) does not count.
    forged = (b"Authentication-Results: mx.example.com; dkim=fail header.d=shop.example\r\n"
              + VERIFIED + NEWSLETTER)
    assert open_in_panel(fake_server, forged)["external"]["trusted"] is False
    assert fetched == []


@pytest.mark.parametrize("kind,value", [("sender", "not an address"), ("domain", "localhost"), ("domain", "a b.se"),
                                        ("other", "x")])
def test_trust_rejects_invalid_values(account, kind, value):
    with pytest.raises(ToolError):
        asyncio.run(mcp_server.mcp.call_tool("imap_panel_trust", {"account": "test", "kind": kind, "value": value}))


def test_trust_list_persists_lowercased(account):
    asyncio.run(mcp_server.mcp.call_tool("imap_panel_trust", {"account": "test", "kind": "domain", "value": "Shop.Example"}))
    assert accounts.get_account("test").trusted_domains == ["shop.example"]


def test_hidden_images_are_never_fetched():
    html = ('<img src="https://a.example/seen.png"><div style="display:none"><img src="https://a.example/beacon.gif"></div>'
            '<img src="cid:x"><span hidden><img src="https://a.example/also-hidden.gif"></span>')
    import html_mail
    assert html_mail.remote_image_sources(html) == ["https://a.example/seen.png"]


def test_total_budget_stops_further_downloads(web, allow_local, monkeypatch):
    monkeypatch.setattr(image_proxy, "MAX_TOTAL_BYTES", len(PNG) * 2)
    Handler.routes.update({f"/ok.png?b{i}": (200, "image/png", PNG, {}) for i in range(6)})
    result = image_proxy.fetch_images([f"{web}/ok.png?b{i}" for i in range(6)])
    assert len(result) == 2


# -----------------------------------------------------------------------------
# Sender verification (Authentication-Results)
# -----------------------------------------------------------------------------

from email import message_from_bytes  # noqa: E402

import sender_auth  # noqa: E402


def check(headers: str, domain: str = "shop.example") -> sender_auth.Verification:
    return sender_auth.verify(message_from_bytes((headers + "From: a@shop.example\r\n\r\nx").encode()), domain)


@pytest.mark.parametrize("header,how", [
    ("mx.example.com; dmarc=pass (p=reject) header.from=shop.example", "dmarc"),
    ("mx.example.com; dkim=pass (2048-bit key) header.d=shop.example header.s=k1", "dkim"),
    ("mx.example.com; dkim=pass header.i=@mail.shop.example", "dkim"),
    ("mx.example.com;\r\n spf=pass (sender ok) smtp.mailfrom=bounces@em.shop.example", "spf"),
    ("mx.example.com 1; dkim=fail header.d=shop.example; spf=pass smtp.mailfrom=x@shop.example", "spf"),
])
def test_verified(header, how):
    assert check(f"Authentication-Results: {header}\r\n") == sender_auth.Verification(True, how)


@pytest.mark.parametrize("header", [
    "mx.example.com; dkim=pass header.d=attacker.example",            # signed, but by someone else
    "mx.example.com; spf=pass smtp.mailfrom=x@attacker.example",
    "mx.example.com; dmarc=fail header.from=shop.example",
    "mx.example.com; dmarc=pass header.from=attacker.example",
    "mx.example.com; dkim=pass header.d=example",                     # a bare top-level name
    "mx.example.com; dkim=pass header.d=notshop.example",
    "mx.example.com; none",
])
def test_not_verified(header):
    assert check(f"Authentication-Results: {header}\r\n").verified is False


def test_without_header_or_domain():
    assert check("").how == "no_header"
    assert check("Authentication-Results: mx; dkim=pass header.d=shop.example\r\n", domain="").how == "no_from_domain"


def test_only_the_topmost_header_counts():
    top = "Authentication-Results: mx.example.com; dkim=none\r\n"
    lower = "Authentication-Results: mx.example.com; dkim=pass header.d=shop.example\r\n"
    assert check(top + lower).verified is False
    assert check(lower + top).verified is True
