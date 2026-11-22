# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Writing from the mailbox panel, drafts that can be reopened, and the writing rules."""

from __future__ import annotations

import asyncio
import email
from email import policy

import pytest
from mcp.server.mcpserver.exceptions import ToolError

import accounts
import imap_client
import mcp_server


def call(_tool: str, **arguments):
    try:
        result = asyncio.run(mcp_server.mcp.call_tool(_tool, arguments))
    except ToolError as exc:
        return None, True, str(exc)
    return result.structured_content, result.is_error, ""


def allow(send_mode="drafts", organise=False):
    acc = accounts.get_account("test")
    acc.permissions = accounts.Permissions(organise=organise, send_mode=accounts.SendMode(send_mode),
                                           send_approval=accounts.SendApproval.NEVER)
    accounts.save_account(acc)


def drafts(fake_server):
    return {uid: (m.flags, email.message_from_bytes(m.raw, policy=policy.default))
            for uid, m in fake_server.store.folder("Drafts").messages.items()}


def test_instructions_put_language_and_style_first():
    text = mcp_server.mcp.instructions
    assert text.startswith("LANGUAGE FIRST")
    assert "never switch to English" in text
    assert "flowing prose" in text and "plain-language" in text


def test_knowledge_guidance_requires_prose():
    assert "flowing prose" in mcp_server._KNOWLEDGE_GUIDANCE
    assert "bullet-point source material" in mcp_server._KNOWLEDGE_GUIDANCE


def test_saved_draft_reports_where_it_is(account, fake_server):
    allow()
    result, is_error, _ = call("imap_save_draft", account="test", to=["bob@example.com"], subject="Hej", body="Text.")
    assert not is_error
    assert result["folder"] == "Drafts" and result["uid"] in fake_server.store.folder("Drafts").messages
    assert "imap_open_mailbox" in result["next_step"]


def test_open_mailbox_can_point_at_a_message(account):
    result, _, _ = call("imap_open_mailbox", account="test", folder="Drafts", open_uid=7, open_uidvalidity=99)
    assert result["open"] == {"uid": 7, "uidvalidity": 99} and result["folder"] == "Drafts"


def test_prepare_reply_computes_recipients(account, mailbox):
    allow()
    folder, uid = mailbox["thread_original"]
    result, _, _ = call("imap_panel_compose_prepare", account="test", action="reply_all", folder=folder, uid=uid)
    assert result["allowed"] and result["subject"].startswith("Re:")
    assert "bob@example.org" in " ".join(result["to"])
    assert result["body"] == "" and result["quoted_from"] == "bob@example.org"


def test_prepare_refused_when_composing_is_off(account, mailbox):
    folder, uid = mailbox["plain"]
    result, _, _ = call("imap_panel_compose_prepare", account="test", action="reply", folder=folder, uid=uid)
    assert result["allowed"] is False


def test_deliver_reply_as_draft_quotes_original(account, fake_server, mailbox):
    allow()
    folder, uid = mailbox["plain"]
    validity = fake_server.store.folder(folder).uidvalidity
    result, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply",
                                  body="Fredag passar bra.", to=["alice@example.com"],
                                  subject="Re: Lunch on Friday", folder=folder, uid=uid, uidvalidity=validity)
    assert not is_error, text
    [(flags, msg)] = drafts(fake_server).values()
    assert "\\Draft" in flags and msg["In-Reply-To"]
    content = msg.get_content()
    assert content.startswith("Fredag passar bra.") and "\n> " in content


def test_edit_draft_replaces_the_old_one(account, fake_server, mailbox):
    allow()
    saved, _, _ = call("imap_save_draft", account="test", to=["bob@example.com"], subject="Utkast", body="Första versionen.")
    prepared, _, _ = call("imap_panel_compose_prepare", account="test", action="edit_draft",
                          folder="Drafts", uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    assert prepared["is_draft"] and prepared["body"].startswith("Första versionen.")
    result, is_error, text = call("imap_panel_compose_deliver", account="test", action="edit_draft",
                                  body="Andra versionen.", to=prepared["to"], subject=prepared["subject"],
                                  folder="Drafts", uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    assert not is_error, text
    assert result["old_draft_moved_to_trash"] is True
    bodies = [m.get_content().strip() for _f, m in drafts(fake_server).values()]
    assert bodies == ["Andra versionen."]
    # The old version can still be recovered from Trash.
    trashed = [email.message_from_bytes(m.raw, policy=policy.default).get_content().strip()
               for m in fake_server.store.folder("Trash").messages.values()]
    assert "Första versionen." in trashed


def test_retire_own_draft_refuses_other_messages(account, mailbox, fake_server):
    folder, uid = mailbox["plain"]
    validity = call("imap_search", account="test")[0]["uidvalidity"]
    # Not the Drafts folder: nothing is moved.
    assert imap_client.retire_own_draft(accounts.get_account("test"), folder, uid, validity) is False
    assert uid in fake_server.store.folder(folder).messages
    # A message in Drafts without the \Draft flag is not removed either.
    raw = b"From: a@example.com\r\nSubject: x\r\n\r\ny\r\n"
    other = fake_server.store.add_message("Drafts", raw, ())
    d_validity = fake_server.store.folder("Drafts").uidvalidity
    assert imap_client.retire_own_draft(accounts.get_account("test"), "Drafts", other, d_validity) is False
    assert other in fake_server.store.folder("Drafts").messages


def test_deliver_send_needs_send_mode(account, mailbox):
    allow(send_mode="drafts")
    folder, uid = mailbox["plain"]
    _r, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply", body="Ja.",
                              to=["alice@example.com"], folder=folder, uid=uid, uidvalidity=1, deliver="send")
    assert is_error and "only allows saving drafts" in text


FOREIGN = (b"From: Erik <erik@partner.example>\r\nReply-To: collect@elsewhere.example\r\n"
           b"To: test@example.com\r\nSubject: Faktura\r\nMessage-ID: <f-1@partner.example>\r\n\r\nSvara hit.\r\n")


def test_panel_reply_to_foreign_reply_to_is_refused_when_sending(account, fake_server):
    allow(send_mode="send")
    uid = fake_server.store.add_message("INBOX", FOREIGN, ())
    validity = fake_server.store.folder("INBOX").uidvalidity
    _r, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply", body="Ok.",
                              to=["collect@elsewhere.example"], folder="INBOX", uid=uid,
                              uidvalidity=validity, deliver="send")
    assert is_error and "Not sent" in text


def test_panel_reply_to_the_sender_is_fine(account, fake_server):
    allow(send_mode="drafts")
    uid = fake_server.store.add_message("INBOX", FOREIGN, ())
    validity = fake_server.store.folder("INBOX").uidvalidity
    result, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply", body="Ok.",
                                  to=["erik@partner.example"], folder="INBOX", uid=uid, uidvalidity=validity)
    assert not is_error, text
    assert result["status"] == "draft_saved" and "reply_to_warning" not in result


def test_panel_deliver_requires_uidvalidity(account, mailbox):
    allow()
    folder, uid = mailbox["plain"]
    _r, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply", body="Ok.",
                              to=["alice@example.com"], folder=folder, uid=uid)
    assert is_error and "uidvalidity is required" in text


def test_addresses_are_readable_not_encoded():
    names = mcp_server._addr_list([{"name": "Åsa Öberg", "email": "asa@example.se"},
                                   {"name": "Berg, Bo", "email": "bo@example.se"},
                                   {"name": "", "email": "x@example.se"}])
    assert names == ["Åsa Öberg <asa@example.se>", '"Berg, Bo" <bo@example.se>', "x@example.se"]


def test_quote_line_in_swedish_with_readable_date():
    import mail_parse

    text = mail_parse.quote_for_reply("Hej.", "Åsa Öberg <asa@example.se>", "2026-11-14T12:00:00+01:00", "sv")
    assert text.splitlines()[0] == "Den 14 november 2026 kl. 12:00 skrev Åsa Öberg <asa@example.se>:"
    assert mail_parse.quote_for_reply("Hi.", "A <a@x.se>", None, "en").startswith("A <a@x.se> wrote:")


def test_reply_with_non_ascii_sender_round_trips(account, fake_server, mailbox):
    allow()
    folder, uid = mailbox["swedish"]
    validity = fake_server.store.folder(folder).uidvalidity
    prepared, _, _ = call("imap_panel_compose_prepare", account="test", action="reply",
                          folder=folder, uid=uid, uidvalidity=validity)
    assert "=?" not in " ".join(prepared["to"]) and "Åsa" in " ".join(prepared["to"])
    result, is_error, text = call("imap_panel_compose_deliver", account="test", action="reply", body="Tack.",
                                  to=prepared["to"], subject=prepared["subject"], folder=folder, uid=uid,
                                  uidvalidity=validity)
    assert not is_error, text
    [(_f, msg)] = drafts(fake_server).values()
    assert "Åsa" in str(msg["To"]) and "=?" not in msg.get_content()


def test_split_quote_shapes():
    import mail_parse

    reply = "Hej Åsa,\n\nFredag passar.\n\nDen 14 november 2026 kl. 12:00 skrev Åsa <a@x.se>:\n> Lunch?\n>\n> /Å"
    own, kept = mail_parse.split_quote(reply)
    assert own == "Hej Åsa,\n\nFredag passar." and kept.startswith("Den 14 november") and kept.endswith("> /Å")
    english = "Fine.\n\nOn 14 November 2026 at 12:00, A <a@x.se> wrote:\n> Hi"
    assert mail_parse.split_quote(english) == ("Fine.", "On 14 November 2026 at 12:00, A <a@x.se> wrote:\n> Hi")
    forward = "FYI\n\n---------- Forwarded message ----------\nFrom: a@x.se\n\nText"
    own, kept = mail_parse.split_quote(forward)
    assert own == "FYI" and kept.startswith("---------- Forwarded")
    # Not our shape: everything stays editable.
    other = "Text\n\nÅsa skrev:\nhon svarade utan citattecken"
    assert mail_parse.split_quote(other) == (other, "")


def test_edit_reply_draft_keeps_quote_separate(account, fake_server, mailbox):
    allow()
    folder, uid = mailbox["plain"]
    validity = fake_server.store.folder(folder).uidvalidity
    saved, _, _ = call("imap_panel_compose_deliver", account="test", action="reply", body="Första.",
                       to=["alice@example.com"], subject="Re: Lunch", folder=folder, uid=uid, uidvalidity=validity)
    prepared, _, _ = call("imap_panel_compose_prepare", account="test", action="edit_draft",
                          folder="Drafts", uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    assert prepared["body"] == "Första." and prepared["kept_quote"].splitlines()[1].startswith(">")
    call("imap_panel_compose_deliver", account="test", action="edit_draft", body="Andra.",
         to=prepared["to"], subject=prepared["subject"], folder="Drafts",
         uid=saved["uid"], uidvalidity=saved["uidvalidity"])
    [(_f, msg)] = drafts(fake_server).values()
    content = msg.get_content()
    assert content.startswith("Andra.") and content.count(prepared["kept_quote"].splitlines()[0]) == 1
    assert "\n> " in content
