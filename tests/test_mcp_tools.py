# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""End-to-end tests of the MCP tools against the fake IMAP server and a local SMTP server.

Tools are called through the MCP server object, so argument validation,
permission checks and error mapping are exercised as a client sees them.
Sending goes to an aiosmtpd server on 127.0.0.1 that records every message.
"""

from __future__ import annotations

import asyncio
import email
import json
import smtplib
from email import policy

import socket

import pytest
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import mcp_server
import smtp_client

from conftest import PASSWORD, USER


def call(_tool: str, **arguments):
    """Call a tool and return (result, is_error, text).

    Called directly on the server object, a failing tool raises ToolError;
    over the wire the same error reaches the client as an isError result.
    """
    try:
        result = asyncio.run(mcp_server.mcp.call_tool(_tool, arguments))
    except ToolError as exc:
        return None, True, str(exc)
    text = " ".join(getattr(c, "text", "") for c in result.content)
    return result, result.is_error, text


def data(_tool: str, **arguments) -> dict:
    result, is_error, text = call(_tool, **arguments)
    assert not is_error, text
    if result.structured_content is None:
        # Tools without structured output return their dict as JSON text.
        return json.loads(text)
    return result.structured_content


def set_permissions(organise=False, send_mode="off", save_sent="auto"):
    acc = accounts.get_account("test")
    acc.permissions = accounts.Permissions(organise=organise, send_mode=accounts.SendMode(send_mode))
    acc.save_sent = accounts.SaveSent(save_sent)
    acc.smtp_host = "127.0.0.1"
    acc.smtp_port = 2525
    acc.smtp_security = "starttls"
    accounts.save_account(acc)


# -----------------------------------------------------------------------------
# Local SMTP server
# -----------------------------------------------------------------------------

class _Recorder:
    def __init__(self):
        self.messages: list[tuple[str, list[str], bytes]] = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.original_content))
        return "250 OK"


def _authenticator(server, session, envelope, mechanism, auth_data):
    ok = auth_data.login.decode() == USER and auth_data.password.decode() == PASSWORD
    return AuthResult(success=ok)


@pytest.fixture
def smtp_server(monkeypatch):
    recorder = _Recorder()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    controller = Controller(
        recorder, hostname="127.0.0.1", port=port,
        authenticator=_authenticator, auth_require_tls=False,
    )
    controller.start()

    def connect(account):
        server = smtplib.SMTP("127.0.0.1", port, timeout=10)
        server.ehlo()
        return server

    monkeypatch.setattr(smtp_client, "_connect", connect)
    yield recorder
    controller.stop()


# -----------------------------------------------------------------------------
# Reading through the tools
# -----------------------------------------------------------------------------

def test_list_accounts(account):
    result = data("imap_list_accounts")
    [entry] = result["accounts"]
    assert entry["id"] == "test"
    assert entry["send_mode"] == "off" and entry["organise"] is False
    assert entry["password_stored"] is True
    assert result["config_problems"] == []


def test_get_message_tool_keeps_unread(account, fake_server, mailbox):
    folder, uid = mailbox["html"]
    assert "\\Seen" not in fake_server.store.flags(folder, uid)
    result = data("imap_get_message", account="test", folder=folder, uid=uid)
    assert result["seen"] is False
    assert "\\Seen" not in fake_server.store.flags(folder, uid)
    body = result["body"]
    assert "untrusted" not in body["content"].lower() or body["notice"]
    assert body["content"].startswith("<<<MAIL-")


def test_search_tool_maps_sender(account, mailbox):
    result = data("imap_search", account="test", sender="alice@example.com")
    assert result["total"] >= 1
    assert all("alice@example.com" in [a["email"] for a in m["from"]] for m in result["messages"])


def test_get_attachment_pdf_and_image(account, mailbox):
    folder, uid = mailbox["multipart"]
    message = data("imap_get_message", account="test", folder=folder, uid=uid)
    parts = {a["content_type"]: a["part_id"] for a in message["attachments"]}
    pdf = data("imap_get_attachment", account="test", folder=folder, uid=uid, part_id=parts["application/pdf"])
    # The fixture PDF is a blank page without a text layer, which is the
    # case of a scanned document: the tool must say so, not return nothing.
    assert "no extractable text" in pdf["note"]
    assert pdf["content_type"] == "application/pdf"
    result, is_error, _ = call("imap_get_attachment", account="test", folder=folder, uid=uid, part_id=parts["image/png"])
    assert not is_error
    assert result.content[0].type == "image"


def test_unknown_account_is_tool_error(account):
    _result, is_error, text = call("imap_list_folders", account="nope")
    assert is_error and "Unknown account" in text


# -----------------------------------------------------------------------------
# Permissions
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("tool,args", [
    ("imap_set_flags", {"folder": "INBOX", "uids": [1], "uidvalidity": 1, "add": ["seen"]}),
    ("imap_move_messages", {"folder": "INBOX", "uids": [1], "uidvalidity": 1, "destination": "Archive"}),
    ("imap_trash_messages", {"folder": "INBOX", "uids": [1], "uidvalidity": 1}),
    ("imap_create_folder", {"name": "New"}),
])
def test_organise_tools_need_permission(account, fake_server, mailbox, tool, args):
    before = fake_server.store.all_flags("INBOX")
    _result, is_error, text = call(tool, account="test", **args)
    assert is_error and "does not allow organising" in text
    assert fake_server.store.all_flags("INBOX") == before


def test_set_flags_with_permission(account, fake_server, mailbox):
    set_permissions(organise=True)
    folder, uid = mailbox["plain"]
    validity = data("imap_get_message", account="test", folder=folder, uid=uid)["uidvalidity"]
    data("imap_set_flags", account="test", folder=folder, uids=[uid], uidvalidity=validity, add=["seen", "flagged"])
    assert {"\\Seen", "\\Flagged"} <= fake_server.store.flags(folder, uid)


@pytest.mark.parametrize("uidvalidity", [0, -1])
def test_write_tools_require_uidvalidity(account, fake_server, mailbox, uidvalidity):
    set_permissions(organise=True)
    folder, uid = mailbox["plain"]
    before = fake_server.store.flags(folder, uid)
    _result, is_error, text = call("imap_set_flags", account="test", folder=folder, uids=[uid],
                                   uidvalidity=uidvalidity, add=["seen"])
    assert is_error and "uidvalidity is required" in text
    assert fake_server.store.flags(folder, uid) == before


def test_write_tools_reject_stale_uidvalidity(account, fake_server, mailbox):
    set_permissions(organise=True)
    folder, uid = mailbox["plain"]
    validity = data("imap_get_message", account="test", folder=folder, uid=uid)["uidvalidity"]
    _result, is_error, text = call("imap_trash_messages", account="test", folder=folder,
                                   uids=[uid], uidvalidity=validity + 1)
    assert is_error and "renumbered" in text
    assert uid in fake_server.store.folder(folder).messages


def test_responses_list_untrusted_fields(account, mailbox):
    folder, uid = mailbox["plain"]
    message = data("imap_get_message", account="test", folder=folder, uid=uid)
    assert "headers.subject" in message["untrusted_fields"]
    found = data("imap_search", account="test")
    assert "messages[].subject" in found["untrusted_fields"]


@pytest.mark.parametrize("tool,args", [
    ("imap_save_draft", {"to": ["x@example.com"], "subject": "s", "body": "b"}),
    ("imap_send_message", {"to": ["x@example.com"], "subject": "s", "body": "b"}),
    ("imap_reply", {"folder": "INBOX", "uid": 1, "body": "b"}),
    ("imap_forward", {"folder": "INBOX", "uid": 1, "to": ["x@example.com"]}),
])
def test_compose_tools_refused_when_off(account, tool, args):
    _result, is_error, text = call(tool, account="test", **args)
    assert is_error and "read-only for composing" in text


def test_drafts_mode_refuses_sending(account, smtp_server, mailbox):
    set_permissions(send_mode="drafts")
    folder, uid = mailbox["plain"]
    for tool, args in [
        ("imap_send_message", {"to": ["x@example.com"], "subject": "s", "body": "b"}),
        ("imap_reply", {"folder": folder, "uid": uid, "body": "b", "mode": "send"}),
    ]:
        _result, is_error, text = call(tool, account="test", **args)
        assert is_error and "only allows saving drafts" in text
    assert smtp_server.messages == []


# -----------------------------------------------------------------------------
# Drafts and sending
# -----------------------------------------------------------------------------

def _messages_in(fake_server, folder):
    store_folder = fake_server.store.folder(folder)
    return [(m.flags, email.message_from_bytes(m.raw, policy=policy.default)) for m in store_folder.messages.values()]


def test_save_draft(account, fake_server, mailbox):
    set_permissions(send_mode="drafts")
    result = data("imap_save_draft", account="test", to=["Bob <bob@example.com>"],
                  bcc=["hidden@example.com"], subject="Hej då", body="Text med å, ä och ö.")
    assert result["status"] == "draft_saved" and result["folder"] == "Drafts"
    [(flags, msg)] = _messages_in(fake_server, "Drafts")
    assert "\\Draft" in flags
    assert msg["Subject"] == "Hej då"
    assert "hidden@example.com" in msg["Bcc"]  # kept so the user sees it when sending
    assert "å, ä och ö" in msg.get_content()


def test_reply_draft_threads_and_quotes(account, fake_server, mailbox):
    set_permissions(send_mode="drafts")
    folder, uid = mailbox["thread_original"]
    data("imap_reply", account="test", folder=folder, uid=uid, body="Thanks, sounds good.", reply_all=True)
    [(_flags, msg)] = _messages_in(fake_server, "Drafts")
    assert msg["Subject"].startswith("Re:")
    assert msg["In-Reply-To"] == "<thread-1@example.org>"
    assert "<thread-1@example.org>" in msg["References"]
    assert USER not in (msg["To"] or "") + (msg["Cc"] or "")
    content = msg.get_content()
    assert content.startswith("Thanks, sounds good.")
    assert "\n> " in content


def test_forward_lists_attachments(account, fake_server, mailbox):
    set_permissions(send_mode="drafts")
    folder, uid = mailbox["multipart"]
    data("imap_forward", account="test", folder=folder, uid=uid, to=["dave@example.com"], note="FYI")
    [(_flags, msg)] = _messages_in(fake_server, "Drafts")
    assert msg["Subject"].startswith("Fwd:")
    assert "Attachments (not included):" in msg.get_content()


def test_send_message_and_sent_copy(account, fake_server, smtp_server, mailbox):
    set_permissions(send_mode="send")
    result = data("imap_send_message", account="test", to=["bob@example.com"],
                  bcc=["hidden@example.com"], subject="Report", body="See below.")
    assert result["status"] == "sent"
    [(sender, rcpts, raw)] = smtp_server.messages
    assert sender == USER and set(rcpts) == {"bob@example.com", "hidden@example.com"}
    assert result["saved_to"] == "Sent"
    stored = [msg for _f, msg in _messages_in(fake_server, "Sent") if msg["Subject"] == "Report"]
    assert len(stored) == 1 and stored[0]["Bcc"] is None


def test_send_without_sent_copy(account, fake_server, smtp_server, mailbox):
    set_permissions(send_mode="send", save_sent="never")
    before = len(fake_server.store.folder("Sent").messages)
    result = data("imap_send_message", account="test", to=["bob@example.com"], subject="s", body="b")
    assert "saved_to" not in result
    assert len(fake_server.store.folder("Sent").messages) == before


def test_reply_send_marks_original_answered(account, fake_server, smtp_server, mailbox):
    set_permissions(organise=True, send_mode="send")
    folder, uid = mailbox["plain"]
    result = data("imap_reply", account="test", folder=folder, uid=uid, body="Yes.", mode="send")
    assert result["status"] == "sent" and result["original_marked_answered"] is True
    assert "\\Answered" in fake_server.store.flags(folder, uid)
    assert len(smtp_server.messages) == 1


def test_sent_copy_failure_is_a_warning_not_an_error(account, fake_server, smtp_server, mailbox, monkeypatch):
    set_permissions(send_mode="send", save_sent="always")
    import imap_client

    def broken_append(*_args, **_kwargs):
        raise imap_client.ImapError("append failed")

    monkeypatch.setattr(imap_client, "append_message", broken_append)
    result = data("imap_send_message", account="test", to=["bob@example.com"], subject="s", body="b")
    assert result["status"] == "sent" and "sent_copy_warning" in result
    assert len(smtp_server.messages) == 1


@pytest.mark.parametrize("args,expected", [
    ({"subject": "two\nlines"}, "single line"),
    ({"to": ["not-an-address"]}, "Could not read the recipient"),
    ({"to": ["a@example.com;b@example.com"]}, "Could not read the recipient"),
    ({"to": ["Bo <bo@nodot>"]}, "Invalid e-mail address"),
    ({"to": [f"r{i}@example.com" for i in range(25)]}, "recipients per message"),
])
def test_send_input_validation(account, smtp_server, args, expected):
    set_permissions(send_mode="send")
    payload = {"to": ["bob@example.com"], "subject": "s", "body": "b", **args}
    _result, is_error, text = call("imap_send_message", account="test", **payload)
    assert is_error and expected in text
    assert smtp_server.messages == []


def test_smtp_wrong_password(account, monkeypatch):
    # aiosmtpd stalls rather than answering 535 on a failed login, so the
    # server's rejection is simulated at the connection seam instead.
    set_permissions(send_mode="send")

    class Rejecting:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"Authentication failed")

    monkeypatch.setattr(smtp_client, "_connect", lambda account: Rejecting())
    _result, is_error, text = call("imap_send_message", account="test", to=["bob@example.com"], subject="s", body="b")
    assert is_error and "SMTP login" in text


def test_open_settings_refused_over_http(account, monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    _result, is_error, text = call("imap_open_settings")
    assert is_error and "locally" in text


# -----------------------------------------------------------------------------
# Reply-To redirection
# -----------------------------------------------------------------------------

FOREIGN_REPLY_TO = (
    b"From: Erik Eriksson <erik@partner.example>\r\n"
    b"Reply-To: collect@elsewhere.example\r\n"
    b"To: test@example.com\r\n"
    b"Subject: Invoice\r\n"
    b"Message-ID: <rt-1@partner.example>\r\n"
    b"Date: Mon, 16 Nov 2026 09:00:00 +0100\r\n"
    b"\r\n"
    b"Please reply with the account details.\r\n"
)


def test_reply_send_refuses_foreign_reply_to(account, fake_server, smtp_server, mailbox):
    set_permissions(send_mode="send")
    uid = fake_server.store.add_message("INBOX", FOREIGN_REPLY_TO, ())
    _result, is_error, text = call("imap_reply", account="test", folder="INBOX", uid=uid, body="Sure.", mode="send")
    assert is_error and "collect@elsewhere.example" in text and "Not sent" in text
    assert smtp_server.messages == []


def test_reply_draft_warns_on_foreign_reply_to(account, fake_server, mailbox):
    set_permissions(send_mode="drafts")
    uid = fake_server.store.add_message("INBOX", FOREIGN_REPLY_TO, ())
    result = data("imap_reply", account="test", folder="INBOX", uid=uid, body="Sure.")
    assert result["status"] == "draft_saved"
    assert "collect@elsewhere.example" in result["reply_to_warning"]


def test_reply_to_same_domain_is_fine(account, fake_server, smtp_server, mailbox):
    set_permissions(send_mode="send")
    raw = FOREIGN_REPLY_TO.replace(b"collect@elsewhere.example", b"billing@partner.example")
    uid = fake_server.store.add_message("INBOX", raw, ())
    result = data("imap_reply", account="test", folder="INBOX", uid=uid, body="Sure.", mode="send")
    assert result["status"] == "sent" and "reply_to_warning" not in result
    assert smtp_server.messages[0][1] == ["billing@partner.example"]
