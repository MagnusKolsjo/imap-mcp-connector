# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Tests for imap_client against the in-process fake IMAP server.

The central promise is that reading never marks mail as read. Those tests
assert on the fake server's store directly, and first prove that the fake
does mark mail as read when a client fetches carelessly, so a passing test
means something.
"""

from __future__ import annotations

import re
import ssl
from datetime import date, timedelta

import pytest
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError

import imap_client
from conftest import PASSWORD, USER
from imap_client import ImapError, StaleUidError, build_criteria

REAL_CONNECT = imap_client._connect          # the fixture replaces it with a local one

SEEN = "\\Seen"


def unread_inbox_uids(store) -> list[int]:
    return [uid for uid, flags in store.all_flags("INBOX").items() if SEEN not in flags]


def snapshot(store) -> dict[str, dict[int, set[str]]]:
    return {name: store.all_flags(name) for name in store.folders}


# -----------------------------------------------------------------------------
# The fake behaves like a real server (otherwise the read-only tests are void)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("item", ["BODY[]", "BODY[TEXT]", "RFC822", "RFC822.TEXT", "BODY[HEADER]"])
def test_fake_marks_seen_on_naive_fetch_in_select_mode(raw_client, fake_server, mailbox, item):
    _, uid = mailbox["plain"]
    assert SEEN not in fake_server.store.flags("INBOX", uid)
    raw_client.select_folder("INBOX")
    response = raw_client.fetch([uid], [item])
    assert SEEN in fake_server.store.flags("INBOX", uid)
    # Like real servers, the new flags are reported in the same response.
    assert b"\\Seen" in response[uid][b"FLAGS"]


@pytest.mark.parametrize("item", ["BODY.PEEK[]", "BODY.PEEK[TEXT]", "RFC822.HEADER", "RFC822.SIZE", "FLAGS"])
def test_fake_peek_never_marks_seen(raw_client, fake_server, mailbox, item):
    _, uid = mailbox["plain"]
    raw_client.select_folder("INBOX")
    raw_client.fetch([uid], [item])
    assert SEEN not in fake_server.store.flags("INBOX", uid)


def test_fake_examine_never_marks_seen(raw_client, fake_server, mailbox):
    _, uid = mailbox["plain"]
    raw_client.select_folder("INBOX", readonly=True)
    data = raw_client.fetch([uid], ["BODY[]", "RFC822"])
    assert data[uid][b"BODY[]"].startswith(b"From: Alice")
    assert SEEN not in fake_server.store.flags("INBOX", uid)


def test_fake_examine_refuses_changes(raw_client, fake_server, mailbox):
    _, uid = mailbox["plain"]
    before = snapshot(fake_server.store)
    raw_client.select_folder("INBOX", readonly=True)
    with pytest.raises(IMAPClientError, match="READ-ONLY"):
        raw_client.add_flags([uid], [b"\\Seen"])
    with pytest.raises(IMAPClientError, match="READ-ONLY"):
        raw_client.move([uid], "Archive")
    with pytest.raises(IMAPClientError, match="READ-ONLY"):
        raw_client.uid_expunge([uid])
    assert snapshot(fake_server.store) == before


def test_fake_header_fields_returns_only_requested_lines(raw_client, mailbox):
    _, uid = mailbox["thread_reply"]
    raw_client.select_folder("Sent", readonly=True)
    data = raw_client.fetch([uid], ["BODY.PEEK[HEADER.FIELDS (SUBJECT IN-REPLY-TO)]"])
    block = data[uid][b"BODY[HEADER.FIELDS (SUBJECT IN-REPLY-TO)]"]
    assert block == b"Subject: Re: Project plan\r\nIn-Reply-To: <thread-1@example.org>\r\n\r\n"


def test_fake_plain_expunge_removes_every_deleted_message(raw_client, fake_server, mailbox):
    # This is the hazard the UIDPLUS fallback in move_messages must avoid.
    store = fake_server.store
    raw_client.select_folder("INBOX")
    raw_client.add_flags([mailbox["plain"][1], mailbox["html"][1]], [b"\\Deleted"])
    raw_client.expunge()
    assert mailbox["plain"][1] not in store.uids("INBOX")
    assert mailbox["html"][1] not in store.uids("INBOX")


# -----------------------------------------------------------------------------
# Reading never changes flags (mandatory)
# -----------------------------------------------------------------------------

READ_OPERATIONS = {
    "get_message": lambda acc, ids: [imap_client.get_message(acc, f, uid) for f, uid in ids.values()],
    "get_raw_message": lambda acc, ids: [imap_client.get_raw_message(acc, f, uid) for f, uid in ids.values()],
    "search": lambda acc, ids: [
        imap_client.search(acc, "INBOX", build_criteria(unseen=True)),
        imap_client.search(acc, "INBOX", build_criteria(text="smörgås")),
        imap_client.search(acc, "INBOX", build_criteria(body="invoice", larger_than_kb=1)),
    ],
    "find_thread": lambda acc, ids: [imap_client.find_thread(acc, "INBOX", uid) for f, uid in ids.values()
                                     if f == "INBOX"],
    "mailbox_stats": lambda acc, ids: imap_client.mailbox_stats(acc, "INBOX", days=365),
    "list_folders": lambda acc, ids: imap_client.list_folders(acc, with_counts=True),
    "test_connection": lambda acc, ids: imap_client.test_connection(acc),
}


@pytest.mark.parametrize("operation", sorted(READ_OPERATIONS))
def test_reading_never_changes_flags(account, fake_server, mailbox, raw_client, operation):
    store = fake_server.store
    unread = unread_inbox_uids(store)
    assert len(unread) == 4, "the seed must contain unread mail for this test to mean anything"
    before_flags = snapshot(store)
    before_status = raw_client.folder_status("INBOX", ["MESSAGES", "UNSEEN"])
    fake_server.log.clear()

    READ_OPERATIONS[operation](account, mailbox)

    assert snapshot(store) == before_flags
    assert unread_inbox_uids(store) == unread
    assert raw_client.folder_status("INBOX", ["MESSAGES", "UNSEEN"]) == before_status
    assert store.unseen("INBOX") == before_status[b"UNSEEN"] == 4

    # Both safety mechanisms, checked independently of each other on the wire:
    # every folder was opened with EXAMINE, and every fetch used PEEK.
    assert not fake_server.commands("SELECT"), fake_server.commands("SELECT")
    for line in fake_server.commands("FETCH"):
        items = line.split(" ", 4)[-1]
        assert not re.search(r"BODY\[|RFC822(\.TEXT)?(?=[ )])", items), line


def test_get_message_returns_unread_flags_and_content(account, fake_server, mailbox):
    _, uid = mailbox["html"]
    parsed, flags, validity = imap_client.get_message(account, "INBOX", uid)
    assert SEEN not in flags
    assert validity == fake_server.store.folder("INBOX").uidvalidity
    assert parsed.headers["subject"] == "Your order has shipped"
    assert "IGNORE PREVIOUS" not in parsed.text
    assert SEEN not in fake_server.store.flags("INBOX", uid)


def test_get_message_with_attachments(account, mailbox):
    _, uid = mailbox["multipart"]
    parsed, _, _ = imap_client.get_message(account, "INBOX", uid)
    assert [(a.part_id, a.content_type) for a in parsed.attachments] == [("1.2", "image/png"), ("2", "application/pdf")]


def test_get_raw_message_is_byte_identical(account, fake_server, mailbox):
    _, uid = mailbox["swedish"]
    raw, flags, _ = imap_client.get_raw_message(account, "INBOX", uid)
    assert raw == fake_server.store.folder("INBOX").messages[uid].raw
    assert flags == []


def test_missing_uid(account):
    with pytest.raises(ImapError, match="No message with uid 999"):
        imap_client.get_message(account, "INBOX", 999)


def test_missing_folder(account):
    with pytest.raises(ImapError, match="Cannot open folder 'Nope'"):
        imap_client.search(account, "Nope")


def test_max_message_bytes_refused(account, fake_server, mailbox, monkeypatch):
    monkeypatch.setattr(imap_client, "MAX_MESSAGE_BYTES", 1024 * 1024)
    big = b"From: a@example.com\r\nSubject: big\r\n\r\n" + b"x" * (2 * 1024 * 1024)
    uid = fake_server.store.add_message("INBOX", big)
    fake_server.log.clear()
    with pytest.raises(ImapError, match="2.0 MB, above the limit of 1.0 MB"):
        imap_client.get_message(account, "INBOX", uid)
    assert not any("BODY.PEEK[]" in line for line in fake_server.log)


# -----------------------------------------------------------------------------
# Folders
# -----------------------------------------------------------------------------

def test_list_folders_special_use_and_counts(account):
    folders = {f["name"]: f for f in imap_client.list_folders(account, with_counts=True)}
    assert set(folders) == {"INBOX", "Sent", "Drafts", "Trash", "Archive"}
    assert {n: f["special_use"] for n, f in folders.items()} == {
        "INBOX": None, "Sent": "sent", "Drafts": "drafts", "Trash": "trash", "Archive": "archive",
    }
    assert (folders["INBOX"]["messages"], folders["INBOX"]["unseen"]) == (6, 4)
    assert (folders["Sent"]["messages"], folders["Sent"]["unseen"]) == (1, 0)
    assert all(f["selectable"] and f["delimiter"] == "/" for f in folders.values())


def test_list_folders_without_counts(account):
    assert all("messages" not in f for f in imap_client.list_folders(account))


def test_list_folders_without_special_use_falls_back_to_names(account, fake_server):
    fake_server.set_capabilities(remove=["SPECIAL-USE"])
    folders = {f["name"]: f["special_use"] for f in imap_client.list_folders(account)}
    assert folders["Sent"] == "sent" and folders["Trash"] == "trash" and folders["Drafts"] == "drafts"


def test_special_use_attribute_beats_name(account, fake_server):
    fake_server.store.add_folder("Skickat", "\\Sent")
    fake_server.store.folders["Sent"].special_use = None
    folders = {f["name"]: f["special_use"] for f in imap_client.list_folders(account)}
    assert folders["Skickat"] == "sent"


def test_account_folder_override(account, fake_server):
    fake_server.store.add_folder("Papperskorg")
    account.trash_folder = "Papperskorg"
    folders = {f["name"]: f["special_use"] for f in imap_client.list_folders(account)}
    assert folders["Papperskorg"] == "trash"


def test_create_folder_idempotent(account, fake_server):
    assert imap_client.create_folder(account, " Projects ") == {"name": "Projects", "created": True}
    box = fake_server.store.get("Projects")
    assert box is not None and box.subscribed
    again = imap_client.create_folder(account, "Projects")
    assert again["created"] is False
    with pytest.raises(ImapError, match="empty"):
        imap_client.create_folder(account, "  ")


def test_test_connection(account):
    info = imap_client.test_connection(account)
    assert info["ok"] and info["folder_count"] == 5 and info["gmail"] is False
    assert "MOVE" in info["capabilities"]
    assert info["special_folders"] == {"sent": "Sent", "drafts": "Drafts", "trash": "Trash"}


# -----------------------------------------------------------------------------
# Search
# -----------------------------------------------------------------------------

def _uids(result) -> list[int]:
    return [m["uid"] for m in result["messages"]]


def test_search_unseen(account, mailbox):
    result = imap_client.search(account, "INBOX", build_criteria(unseen=True))
    expected = sorted((mailbox[k][1] for k in ("plain", "html", "multipart", "swedish")), reverse=True)
    assert _uids(result) == expected
    assert all(not m["seen"] for m in result["messages"])
    seen = imap_client.search(account, "INBOX", build_criteria(unseen=False))
    assert set(_uids(seen)) == {mailbox["thread_original"][1], mailbox["newsletter"][1]}


def test_search_from_and_subject(account, mailbox):
    assert _uids(imap_client.search(account, "INBOX", build_criteria(from_="ALICE"))) == [mailbox["plain"][1]]
    assert _uids(imap_client.search(account, "INBOX", build_criteria(subject="project"))) == [mailbox["thread_original"][1]]
    both = build_criteria(from_="alice", subject="project")
    assert imap_client.search(account, "INBOX", both)["total"] == 0


def test_search_since_and_before(account, mailbox):
    since = (date.today() - timedelta(days=5)).isoformat()
    result = imap_client.search(account, "INBOX", build_criteria(since=since))
    assert set(_uids(result)) == {mailbox[k][1] for k in ("plain", "html", "multipart", "swedish")}
    before = imap_client.search(account, "INBOX", build_criteria(before=(date.today() - timedelta(days=30)).isoformat()))
    assert _uids(before) == [mailbox["newsletter"][1]]
    with pytest.raises(ImapError, match="Invalid date"):
        build_criteria(since="last week")


@pytest.mark.parametrize("kwargs, key", [
    ({"subject": "smörgås"}, "swedish"),
    ({"from_": "Åsa Öberg"}, "swedish"),
    ({"text": "blåbärssylt"}, "swedish"),
    ({"body": "räkmacka i köket"}, "swedish"),
])
def test_search_swedish_terms(account, fake_server, mailbox, kwargs, key):
    fake_server.log.clear()
    result = imap_client.search(account, "INBOX", build_criteria(**kwargs))
    assert _uids(result) == [mailbox[key][1]]
    assert result["messages"][0]["subject"] == "Räkmacka och smörgås på fredag"
    assert any("CHARSET UTF-8" in line for line in fake_server.commands("SEARCH"))


def _reject_charset(monkeypatch):
    real = IMAPClient.search

    def search(self, criteria="ALL", charset=None):
        if charset:
            raise IMAPClientError("SEARCH command error: NO [BADCHARSET (US-ASCII)]")
        return real(self, criteria, charset)

    monkeypatch.setattr(IMAPClient, "search", search)


def test_search_rejected_charset_falls_back_for_headers(account, mailbox, fake_server, monkeypatch):
    _reject_charset(monkeypatch)
    before = fake_server.store.all_flags("INBOX")
    result = imap_client.search(account, "INBOX", build_criteria(subject="räkmacka", unseen=True))
    assert result["search_note"] and "locally" in result["search_note"]
    assert [m["uid"] for m in result["messages"]] == [mailbox["swedish"][1]]
    # The local fallback reads headers with PEEK too.
    assert fake_server.store.all_flags("INBOX") == before


def test_search_rejected_charset_body_text_gives_readable_error(account, monkeypatch):
    _reject_charset(monkeypatch)
    with pytest.raises(ImapError, match="non-ASCII"):
        imap_client.search(account, "INBOX", build_criteria(body="smörgås"))


def test_search_paging_newest_first(account, mailbox):
    first = imap_client.search(account, "INBOX", limit=4)
    assert first["total"] == 6 and first["returned"] == 4 and first["next_offset"] == 4
    assert _uids(first) == [6, 5, 4, 3]
    second = imap_client.search(account, "INBOX", limit=4, offset=first["next_offset"])
    assert _uids(second) == [2, 1] and second["next_offset"] is None
    assert imap_client.search(account, "INBOX", limit=0)["returned"] == 1  # limit is clamped to >= 1


def test_search_summary_fields(account, mailbox):
    rows = {m["uid"]: m for m in imap_client.search(account, "INBOX")["messages"]}
    news = rows[mailbox["newsletter"][1]]
    assert news["has_unsubscribe"] and not news["is_reply"]
    assert news["from"] == [{"name": "Weekly News", "email": "news@newsletter.example"}]
    assert news["message_id"] == "<news-1@newsletter.example>"
    assert rows[mailbox["swedish"][1]]["from"][0]["name"] == "Åsa Öberg"
    sent = imap_client.search(account, "Sent")["messages"][0]
    assert sent["is_reply"]


def test_search_larger_and_flagged(account, fake_server, mailbox):
    large = imap_client.search(account, "INBOX", build_criteria(larger_than_kb=1))
    assert _uids(large) == [mailbox["multipart"][1]]
    fake_server.store.folder("INBOX").messages[mailbox["plain"][1]].flags.add("\\Flagged")
    assert _uids(imap_client.search(account, "INBOX", build_criteria(flagged=True))) == [mailbox["plain"][1]]
    assert imap_client.search(account, "INBOX", build_criteria(flagged=False))["total"] == 5
    assert imap_client.search(account, "INBOX", build_criteria(answered=True))["total"] == 0


# -----------------------------------------------------------------------------
# Threads and statistics
# -----------------------------------------------------------------------------

def test_find_thread_finds_reply_in_sent(account, mailbox):
    _, uid = mailbox["thread_original"]
    result = imap_client.find_thread(account, "INBOX", uid)
    assert result["method"] == "message_id_references"
    assert result["folders_searched"] == ["INBOX", "Sent"]
    assert [(m["folder"], m["message_id"]) for m in result["messages"]] == [
        ("INBOX", "<thread-1@example.org>"), ("Sent", "<thread-2@example.com>"),
    ]


def test_find_thread_from_the_reply(account, mailbox):
    folder, uid = mailbox["thread_reply"]
    result = imap_client.find_thread(account, folder, uid)
    assert result["folders_searched"] == ["Sent", "INBOX"]
    # Starting from the reply in Sent still finds the original in INBOX.
    # Both fixtures share a timestamp, so compare without order.
    assert sorted(m["message_id"] for m in result["messages"]) == [
        "<thread-1@example.org>", "<thread-2@example.com>"]


def test_find_thread_gmail(account, fake_server, mailbox):
    store = fake_server.store
    fake_server.set_capabilities(add=["X-GM-EXT-1"])
    store.add_folder("[Gmail]/All Mail", "\\All")
    inbox_msg = store.folder("INBOX").messages[mailbox["thread_original"][1]]
    thread = inbox_msg.gm_thrid
    for key in ("thread_original", "thread_reply"):
        folder, uid = mailbox[key]
        src = store.folder(folder).messages[uid]
        store.add_message("[Gmail]/All Mail", src.raw, src.flags, src.internaldate, gm_thrid=thread)
    store.add_message("[Gmail]/All Mail", store.folder("INBOX").messages[mailbox["plain"][1]].raw)
    before = snapshot(store)

    result = imap_client.find_thread(account, "INBOX", mailbox["thread_original"][1])
    assert result["method"] == "gmail_thread_id"
    assert [m["message_id"] for m in result["messages"]] == ["<thread-1@example.org>", "<thread-2@example.com>"]
    assert all(m["gmail_thread_id"] == thread for m in result["messages"])
    assert snapshot(store) == before


def test_mailbox_stats(account, mailbox):
    stats = imap_client.mailbox_stats(account, "INBOX", days=30)
    assert stats["messages_in_window"] == 5 and stats["messages_analysed"] == 5
    assert stats["unread"] == 4 and stats["flagged"] == 0
    assert stats["with_list_unsubscribe"] == 0  # the newsletter is 40 days old
    assert stats["sample_note"] == "All messages in the window were analysed."
    assert {s["email"] for s in stats["top_senders"]} == {
        "alice@example.com", "promo@shop.example", "carol@example.com", "asa@example.se", "bob@example.org",
    }
    assert stats["top_domains"][0] == {"domain": "example.com", "count": 2}
    assert stats["largest"][0]["uid"] == mailbox["multipart"][1]
    assert sum(stats["per_day"].values()) == 5


def test_mailbox_stats_window_and_sample(account, mailbox):
    wide = imap_client.mailbox_stats(account, "INBOX", days=60)
    assert wide["messages_in_window"] == 6 and wide["with_list_unsubscribe"] == 1
    sample = imap_client.mailbox_stats(account, "INBOX", days=60, max_messages=2)
    assert sample["messages_analysed"] == 2
    assert sample["sample_note"] == "Only the 2 most recent messages were analysed."
    assert len(imap_client.mailbox_stats(account, "INBOX", days=60, top=1)["top_senders"]) == 1


# -----------------------------------------------------------------------------
# Organising
# -----------------------------------------------------------------------------

def test_set_flags_add_and_remove(account, fake_server, mailbox):
    store = fake_server.store
    uid = mailbox["plain"][1]
    result = imap_client.set_flags(account, "INBOX", [uid], add=["seen", "\\Flagged", "$Label1"])
    assert store.flags("INBOX", uid) == {"\\Seen", "\\Flagged", "$Label1"}
    assert set(result["updated"][0]["flags"]) == {"\\Seen", "\\Flagged", "$Label1"}
    imap_client.set_flags(account, "INBOX", [uid], remove=["Seen", "$Label1"])
    assert store.flags("INBOX", uid) == {"\\Flagged"}
    assert store.flags("INBOX", mailbox["html"][1]) == set()  # untouched neighbour
    assert fake_server.commands("SELECT")  # writes need read-write access


@pytest.mark.parametrize("bad", ["not a flag", "\\Deleted", "\\Recent", "bad(flag)", "", "\\"])
def test_set_flags_invalid_rejected(account, fake_server, mailbox, bad):
    before = snapshot(fake_server.store)
    with pytest.raises(ImapError):
        imap_client.set_flags(account, "INBOX", [mailbox["plain"][1]], add=[bad])
    assert snapshot(fake_server.store) == before


def test_set_flags_needs_something_to_do(account, mailbox):
    with pytest.raises(ImapError, match="Nothing to change"):
        imap_client.set_flags(account, "INBOX", [mailbox["plain"][1]])
    with pytest.raises(ImapError, match="No UIDs"):
        imap_client.set_flags(account, "INBOX", [], add=["seen"])


def test_bulk_cap(account, fake_server, mailbox, monkeypatch):
    monkeypatch.setattr(imap_client, "MAX_BULK", 2)
    before = snapshot(fake_server.store)
    fake_server.log.clear()
    with pytest.raises(ImapError, match="At most 2 messages"):
        imap_client.set_flags(account, "INBOX", [1, 2, 3], add=["seen"])
    with pytest.raises(ImapError, match="At most 2 messages"):
        imap_client.move_messages(account, "INBOX", [1, 2, 3], "Archive")
    assert fake_server.log == []  # refused before connecting
    assert snapshot(fake_server.store) == before
    imap_client.set_flags(account, "INBOX", [1, 2, 2, 1], add=["flagged"])  # duplicates collapse


def test_move_with_move_capability(account, fake_server, mailbox):
    store = fake_server.store
    uid = mailbox["plain"][1]
    raw = store.folder("INBOX").messages[uid].raw
    result = imap_client.move_messages(account, "INBOX", [uid, 999], "Archive")
    assert result["count"] == 1 and result["not_found"] == [999] and result["operation"] == "move"
    assert uid not in store.uids("INBOX")
    assert [m.raw for m in store.folder("Archive").messages.values()] == [raw]
    assert fake_server.commands("MOVE")


def test_move_with_uidplus_fallback_spares_other_deleted_mail(account, fake_server, mailbox):
    store = fake_server.store
    fake_server.set_capabilities(remove=["MOVE"])
    bystander = mailbox["html"][1]
    store.folder("INBOX").messages[bystander].flags.add("\\Deleted")
    target = mailbox["plain"][1]

    imap_client.move_messages(account, "INBOX", [target], "Archive")

    assert target not in store.uids("INBOX")
    assert bystander in store.uids("INBOX"), "UID EXPUNGE must not remove other \\Deleted mail"
    assert len(store.folder("Archive").messages) == 1
    assert not fake_server.commands("MOVE")
    assert any(line.split()[1:3] == ["UID", "EXPUNGE"] for line in fake_server.log)
    assert not any(line.split()[1:] == ["EXPUNGE"] for line in fake_server.log)


def test_move_refused_without_move_or_uidplus(account, fake_server, mailbox):
    fake_server.set_capabilities(remove=["MOVE", "UIDPLUS"])
    before = snapshot(fake_server.store)
    with pytest.raises(ImapError, match="neither MOVE nor UIDPLUS"):
        imap_client.move_messages(account, "INBOX", [mailbox["plain"][1]], "Archive")
    assert snapshot(fake_server.store) == before
    # Copying is still possible on such a server.
    imap_client.move_messages(account, "INBOX", [mailbox["plain"][1]], "Archive", copy=True)
    assert len(fake_server.store.folder("Archive").messages) == 1


def test_copy(account, fake_server, mailbox):
    store = fake_server.store
    uid = mailbox["swedish"][1]
    result = imap_client.move_messages(account, "INBOX", [uid], "Archive", copy=True)
    assert result["operation"] == "copy" and result["count"] == 1
    assert uid in store.uids("INBOX")
    copied = list(store.folder("Archive").messages.values())
    assert len(copied) == 1 and SEEN not in copied[0].flags  # copying keeps the message unread


def test_move_errors(account, mailbox):
    with pytest.raises(ImapError, match="same"):
        imap_client.move_messages(account, "INBOX", [1], "INBOX")
    with pytest.raises(ImapError, match="does not exist"):
        imap_client.move_messages(account, "INBOX", [1], "Nowhere")


def test_trash_messages(account, fake_server, mailbox):
    store = fake_server.store
    uid = mailbox["newsletter"][1]
    result = imap_client.trash_messages(account, "INBOX", [uid])
    assert result["operation"] == "trash" and result["destination"] == "Trash"
    assert uid not in store.uids("INBOX")
    trashed = list(store.folder("Trash").messages)
    assert len(trashed) == 1
    with pytest.raises(ImapError, match="already in Trash"):
        imap_client.trash_messages(account, "Trash", trashed)
    assert store.uids("Trash") == trashed


def test_trash_without_trash_folder(account, fake_server, mailbox):
    del fake_server.store.folders["Trash"]
    with pytest.raises(ImapError, match="No Trash folder"):
        imap_client.trash_messages(account, "INBOX", [mailbox["plain"][1]])


def test_stale_uidvalidity_on_reads(account, fake_server, mailbox):
    result = imap_client.search(account, "INBOX")
    old = result["uidvalidity"]
    uid = mailbox["plain"][1]
    imap_client.get_message(account, "INBOX", uid, uidvalidity=old)  # still valid
    fake_server.store.renumber("INBOX")
    with pytest.raises(StaleUidError, match="renumbered"):
        imap_client.get_message(account, "INBOX", uid, uidvalidity=old)
    with pytest.raises(StaleUidError):
        imap_client.get_raw_message(account, "INBOX", uid, uidvalidity=old)
    with pytest.raises(StaleUidError):
        imap_client.find_thread(account, "INBOX", uid, uidvalidity=old)


def test_stale_uidvalidity_on_writes(account, fake_server, mailbox):
    old = fake_server.store.folder("INBOX").uidvalidity
    fake_server.store.renumber("INBOX")
    before = snapshot(fake_server.store)
    uid = mailbox["plain"][1]
    with pytest.raises(StaleUidError):
        imap_client.set_flags(account, "INBOX", [uid], add=["seen"], uidvalidity=old)
    with pytest.raises(StaleUidError):
        imap_client.move_messages(account, "INBOX", [uid], "Archive", uidvalidity=old)
    with pytest.raises(StaleUidError):
        imap_client.trash_messages(account, "INBOX", [uid], uidvalidity=old)
    assert snapshot(fake_server.store) == before


def test_append_message_to_drafts(account, fake_server, mailbox):
    raw = b"From: test@example.com\r\nTo: bob@example.org\r\nSubject: Draft reply\r\n\r\nHello Bob\r\n"
    folder = imap_client.append_message(account, "drafts", raw, [b"\\Draft", b"\\Seen"])
    assert folder == "Drafts"
    drafts = list(fake_server.store.folder("Drafts").messages.values())
    assert len(drafts) == 1
    assert drafts[0].raw == raw and drafts[0].flags == {"\\Draft", "\\Seen"}


def test_append_message_lf_is_normalised(account, fake_server, mailbox):
    imap_client.append_message(account, "sent", b"Subject: x\n\nbody\n", [b"\\Seen"])
    stored = list(fake_server.store.folder("Sent").messages.values())[-1]
    assert stored.raw == b"Subject: x\r\n\r\nbody\r\n"


def test_append_without_folder(account, fake_server, mailbox):
    del fake_server.store.folders["Drafts"]
    with pytest.raises(ImapError, match="No Drafts folder"):
        imap_client.append_message(account, "drafts", b"Subject: x\r\n\r\n", [])


def test_server_files_sent_mail(account, fake_server):
    assert imap_client.server_files_sent_mail(account) is False
    fake_server.set_capabilities(add=["X-GM-EXT-1"])
    assert imap_client.server_files_sent_mail(account) is True


# -----------------------------------------------------------------------------
# Connection errors
# -----------------------------------------------------------------------------

def test_wrong_password(account, fake_server, monkeypatch):
    monkeypatch.setenv("IMAP_SECRET_TEST", "wrong")
    with pytest.raises(ImapError) as info:
        imap_client.list_folders(account)
    message = str(info.value)
    assert "Login to 127.0.0.1 failed for test@example.com" in message
    assert "app password" in message
    assert "wrong" not in message
    assert fake_server.login_attempts[-1] == USER


def test_missing_secret(account, monkeypatch):
    monkeypatch.delenv("IMAP_SECRET_TEST")
    with pytest.raises(ImapError, match="No password stored"):
        imap_client.list_folders(account)


def test_unreachable_server(account, monkeypatch):
    def refuse(acc):
        raise ConnectionRefusedError("connection refused")

    monkeypatch.setattr(imap_client, "_connect", refuse)
    with pytest.raises(imap_client.ServerUnreachable, match="Cannot reach the mail server 127.0.0.1:.*VPN"):
        imap_client.list_folders(account)


def test_certificate_problem_is_not_called_unreachable(account, monkeypatch):
    def bad_cert(acc):
        raise ssl.SSLCertVerificationError("certificate verify failed")

    monkeypatch.setattr(imap_client, "_connect", bad_cert)
    with pytest.raises(ImapError, match="Cannot connect to") as info:
        imap_client.list_folders(account)
    assert not isinstance(info.value, imap_client.ServerUnreachable)


def test_connect_budget_is_shared_by_all_addresses(monkeypatch):
    monkeypatch.setattr(imap_client, "IMAP_CONNECT_TIMEOUT", 16.0)
    four = [(None, None, None, "", (f"93.188.3.{i}", 993)) for i in range(4)]
    monkeypatch.setattr(imap_client.socket, "getaddrinfo", lambda *a, **k: four)
    assert imap_client._connect_timeout("mail.example", 993) == pytest.approx(4.0, abs=0.05)
    many = [(None, None, None, "", (f"10.0.0.{i}", 993)) for i in range(40)]
    monkeypatch.setattr(imap_client.socket, "getaddrinfo", lambda *a, **k: many)
    assert imap_client._connect_timeout("mail.example", 993) == 2.0       # never below two seconds


def test_blocked_server_fails_within_the_budget(account, monkeypatch):
    """A silently dropped connection (as behind a blocking VPN) ends in time with a clear error."""
    import time

    monkeypatch.setattr(imap_client, "_connect", REAL_CONNECT)
    monkeypatch.setattr(imap_client, "IMAP_CONNECT_TIMEOUT", 2.0)
    account.imap_host = "10.255.255.1"                                     # not routed: packets are dropped
    started = time.monotonic()
    with pytest.raises(imap_client.ServerUnreachable):
        imap_client.list_folders(account)
    assert time.monotonic() - started < 5


def test_raw_client_login_check(fake_server):
    client = IMAPClient("127.0.0.1", port=fake_server.port, ssl=False, timeout=10)
    with pytest.raises(IMAPClientError):
        client.login(USER, PASSWORD + "x")
    client.login(USER, PASSWORD)
    client.logout()


def test_slow_name_lookup_counts_against_the_budget(monkeypatch):
    import time

    monkeypatch.setattr(imap_client, "IMAP_CONNECT_TIMEOUT", 1.5)
    monkeypatch.setattr(imap_client.socket, "getaddrinfo", lambda *a, **k: time.sleep(5))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        imap_client._connect_timeout("slow.example", 993)
    assert time.monotonic() - started < 1


def test_failed_starttls_is_not_called_a_network_problem(account, monkeypatch):
    def fake_client(*args, **kwargs):
        class Client:
            def starttls(self, context):
                raise ConnectionResetError("reset during handshake")

            def shutdown(self):
                pass
        return Client()

    monkeypatch.setattr(imap_client, "_connect", REAL_CONNECT)
    monkeypatch.setattr(imap_client, "IMAPClient", fake_client)
    monkeypatch.setattr(imap_client, "_connect_timeout", lambda host, port: 5.0)
    with pytest.raises(ImapError, match="STARTTLS.*password was not sent") as info:
        imap_client.list_folders(account)
    assert not isinstance(info.value, imap_client.ServerUnreachable)


def test_hung_lookups_never_block_later_ones(monkeypatch):
    """Lookups that never finish fill no shared queue; past the cap the call fails at once."""
    import threading as th

    release = th.Event()
    monkeypatch.setattr(imap_client, "IMAP_CONNECT_TIMEOUT", 0.3)
    # Lookups from earlier tests may still be running; count from there.
    monkeypatch.setattr(imap_client, "_MAX_OPEN_LOOKUPS", imap_client._open_lookups + 3)
    monkeypatch.setattr(imap_client.socket, "getaddrinfo", lambda *a, **k: release.wait())
    for _ in range(3):
        with pytest.raises(TimeoutError):
            imap_client._connect_timeout("hung.example", 993)
    with pytest.raises(TimeoutError, match="not answering"):          # cap reached: fail at once
        imap_client._connect_timeout("hung.example", 993)
    release.set()
    import time
    time.sleep(0.2)
    four = [(None, None, None, "", (f"93.188.3.{i}", 993)) for i in range(4)]
    monkeypatch.setattr(imap_client.socket, "getaddrinfo", lambda *a, **k: four)
    monkeypatch.setattr(imap_client, "IMAP_CONNECT_TIMEOUT", 16.0)
    assert imap_client._connect_timeout("mail.example", 993) == pytest.approx(4.0, abs=0.05)


def test_unexpected_lookup_error_becomes_oserror(monkeypatch):
    def broken(*args, **kwargs):
        raise UnicodeError("label too long")

    monkeypatch.setattr(imap_client.socket, "getaddrinfo", broken)
    before = imap_client._open_lookups
    with pytest.raises(OSError, match="name lookup for x.example failed"):
        imap_client._connect_timeout("x.example", 993)
    assert imap_client._open_lookups == before


def test_thread_start_failure_releases_its_place(monkeypatch):
    class NoThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(imap_client.threading, "Thread", NoThread)
    before = imap_client._open_lookups
    with pytest.raises(RuntimeError):
        imap_client._connect_timeout("x.example", 993)
    assert imap_client._open_lookups == before
