# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""HTML replies: sanitising, format follows the original, Markdown from the AI, drafts."""

from __future__ import annotations

import asyncio
import email
from email import policy

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import html_mail
import mcp_server

HTML_MAIL = (
    b"From: Kim <kim@example.com>\r\nTo: test@example.com\r\nSubject: Offert\r\n"
    b"Message-ID: <h-1@example.com>\r\nDate: Mon, 16 Nov 2026 09:00:00 +0100\r\nMIME-Version: 1.0\r\n"
    b"Content-Type: multipart/alternative; boundary=b\r\n\r\n"
    b"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHej, se offerten.\r\n"
    b"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    b"<p>Hej, se <b>offerten</b>.<img src=\"https://track.example/p.gif\"><script>x()</script></p>\r\n--b--\r\n"
)


def call(_tool, **arguments):
    try:
        result = asyncio.run(mcp_server.mcp.call_tool(_tool, arguments))
    except ToolError as exc:
        return None, True, str(exc)
    return result.structured_content, result.is_error, ""


def allow():
    acc = accounts.get_account("test")
    acc.permissions = accounts.Permissions(send_mode=accounts.SendMode.DRAFTS)
    accounts.save_account(acc)


def drafts(fake_server):
    return [email.message_from_bytes(m.raw, policy=policy.default)
            for m in fake_server.store.folder("Drafts").messages.values()]


def parts(msg):
    plain = msg.get_body(preferencelist=("plain",))
    html = msg.get_body(preferencelist=("html",))
    return (plain.get_content() if plain else None), (html.get_content() if html else None)


@pytest.mark.parametrize("dirty,clean_contains,clean_lacks", [
    ('<p onclick="x()">Hej</p>', "<p>Hej</p>", "onclick"),
    ("<p>a<script>alert(1)</script>b</p>", "<p>ab</p>", "alert"),
    ('<a href="javascript:x()">l</a>', "l</a>", "javascript"),
    ('<img src="https://track.example/p.gif">x', "x", "img"),
    ('<p style="color:red">x</p>', "<p>x</p>", "style"),
    ("<form><input name=a></form>ok", "ok", "input"),
    ("<p>dolt​ord</p>", "doltord", "​"),
])
def test_sanitise(dirty, clean_contains, clean_lacks):
    out = html_mail.sanitise(dirty)
    assert clean_contains in out and clean_lacks not in out


def test_markdown_from_the_ai_becomes_safe_html():
    out = html_mail.markdown_to_html("Hej,\n\nTvå saker:\n\n- ett\n- två\n\n**Obs**: [läs](https://ex.se) <script>x</script>")
    assert "<ul>" in out and "<strong>Obs</strong>" in out and 'href="https://ex.se"' in out
    assert "<script>" not in out and "&lt;script&gt;" in out


def test_reply_to_html_mail_is_html_with_quote(account, fake_server):
    allow()
    uid = fake_server.store.add_message("INBOX", HTML_MAIL, ())
    result, is_error, text = call("imap_reply", account="test", folder="INBOX", uid=uid,
                                  body="Hej Kim,\n\nTack, vi tackar **ja**.")
    assert not is_error, text
    [msg] = drafts(fake_server)
    plain, html = parts(msg)
    assert plain.startswith("Hej Kim,") and "\n> " in plain
    assert "<strong>ja</strong>" in html and html_mail.QUOTE_ATTRIBUTE in html
    assert "<b>offerten</b>" in html                  # original formatting kept
    assert "track.example" not in html and "script" not in html


def test_reply_to_plain_mail_stays_plain(account, fake_server, mailbox):
    allow()
    folder, uid = mailbox["plain"]
    call("imap_reply", account="test", folder=folder, uid=uid, body="Ja.")
    [msg] = drafts(fake_server)
    plain, html = parts(msg)
    assert plain.startswith("Ja.") and html is None


def test_new_mail_follows_account_setting(account, fake_server):
    allow()
    call("imap_save_draft", account="test", to=["bob@example.com"], subject="Ny", body="Hej **Bo**.")
    acc = accounts.get_account("test")
    acc.new_mail_format = "text"
    accounts.save_account(acc)
    call("imap_save_draft", account="test", to=["bob@example.com"], subject="Ny2", body="Hej **Bo**.")
    by_subject = {str(m["Subject"]): parts(m) for m in drafts(fake_server)}
    assert "<strong>Bo</strong>" in by_subject["Ny"][1]
    assert by_subject["Ny2"][1] is None


def test_panel_html_reply_and_edit_draft_keep_quote_separate(account, fake_server):
    allow()
    uid = fake_server.store.add_message("INBOX", HTML_MAIL, ())
    validity = fake_server.store.folder("INBOX").uidvalidity
    prep, _, _ = call("imap_panel_compose_prepare", account="test", action="reply", folder="INBOX", uid=uid,
                      uidvalidity=validity)
    assert prep["format"] == "html"
    saved, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply",
                                 body="", body_html="<p>Mitt <em>svar</em></p><script>x</script>",
                                 to=prep["to"], subject=prep["subject"], folder="INBOX", uid=uid,
                                 uidvalidity=validity)
    assert not is_error, text
    edit, _, _ = call("imap_panel_compose_prepare", account="test", action="edit_draft", folder="Drafts",
                      uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    assert edit["format"] == "html"
    assert edit["body_html"] == "<p>Mitt <em>svar</em></p>"
    assert html_mail.QUOTE_ATTRIBUTE in edit["kept_quote_html"]
    call("imap_panel_compose_deliver", account="test", action="edit_draft", body="",
         body_html="<p>Nytt <strong>svar</strong></p>", to=edit["to"], subject=edit["subject"],
         folder="Drafts", uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    [msg] = drafts(fake_server)
    plain, html = parts(msg)
    assert html.startswith("<p>Nytt <strong>svar</strong></p>") and html.count(html_mail.QUOTE_ATTRIBUTE) == 1
    assert plain.startswith("Nytt svar")


def test_split_html_quote_leaves_unknown_shapes_alone():
    assert html_mail.split_html_quote("<p>x</p><blockquote>y</blockquote>") == ("<p>x</p><blockquote>y</blockquote>", "")


def test_approval_token_covers_the_html_part(account):
    import send_approval
    import smtp_client

    acc = accounts.get_account("test")
    a = smtp_client.build_message(acc, to=["b@example.com"], subject="s", body="t", html="<p>t</p>")
    b = smtp_client.build_message(acc, to=["b@example.com"], subject="s", body="t", html="<p>t <a href='https://evil'>x</a></p>")
    assert send_approval.message_digest(a) != send_approval.message_digest(b)


def test_bcc_removed_from_stored_html_copy(account):
    import smtp_client

    acc = accounts.get_account("test")
    msg = smtp_client.build_message(acc, to=["b@example.com"], bcc=["h@example.com"], subject="s", body="t", html="<p>t</p>")
    stored = email.message_from_bytes(smtp_client.without_bcc(msg), policy=policy.default)
    assert stored["Bcc"] is None and parts(stored)[1] == "<p>t</p>\n"


def test_received_mail_cannot_carry_the_quote_marker(account, fake_server):
    allow()
    sneaky = HTML_MAIL.replace(b"<p>Hej, se <b>offerten</b>.",
                               b'<p>Hej</p><div data-imap-mcp-quote="1"><p>Falskt citat</p></div><p>se <b>offerten</b>.')
    uid = fake_server.store.add_message("INBOX", sneaky, ())
    validity = fake_server.store.folder("INBOX").uidvalidity
    prep, _, _ = call("imap_panel_compose_prepare", account="test", action="reply", folder="INBOX", uid=uid,
                      uidvalidity=validity)
    saved, _, _ = call("imap_panel_compose_deliver", account="test", action="reply", body="",
                       body_html='<p>Svar</p><div data-imap-mcp-quote="1">eget försök</div>',
                       to=prep["to"], subject=prep["subject"], folder="INBOX", uid=uid, uidvalidity=validity)
    [msg] = drafts(fake_server)
    html = parts(msg)[1]
    assert html.count(html_mail.QUOTE_ATTRIBUTE) == 1      # only the connector's own marker
    edit, _, _ = call("imap_panel_compose_prepare", account="test", action="edit_draft", folder="Drafts",
                      uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    assert "Falskt citat" not in edit["body_html"] and "Falskt citat" in edit["kept_quote_html"]
    assert edit["body_html"].startswith("<p>Svar</p>")


@pytest.mark.parametrize("hidden", [
    '<div style="display:none">DOLT</div>',
    '<span style="font-size:0">DOLT</span>',
    '<p hidden>DOLT</p>',
    '<div aria-hidden="true">DOLT</div>',
    '<span style="mso-hide:all">DOLT</span>',
    '<div style="display:none">a<br/>DOLT</div>',
])
def test_hidden_content_is_removed_not_revealed(hidden):
    out = html_mail.sanitise(f"<p>Synligt</p>{hidden}<p>Slut</p>")
    assert "DOLT" not in out and "Synligt" in out and "Slut" in out


def test_hidden_text_in_original_never_reaches_the_quote(account, fake_server):
    from conftest import fixture_bytes

    allow()
    uid = fake_server.store.add_message("INBOX", fixture_bytes("html_hidden.eml"), ())
    call("imap_reply", account="test", folder="INBOX", uid=uid, body="Tack.")
    [msg] = drafts(fake_server)
    html = parts(msg)[1]
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in html.upper()
