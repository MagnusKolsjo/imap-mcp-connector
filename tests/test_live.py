# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Optional, strictly read-only check against a real mail account.

The fake server proves the logic; this proves that a real provider agrees.
It reads the newest unread message (or the newest message when nothing is
unread) the way the MCP tools do, and asserts that the message's flags and
the INBOX unread count are unchanged afterwards.

It never writes: no flag changes, no moves, no appends. It uses the normal
configuration (accounts.json and the system keychain or IMAP_SECRET_<ID>),
so it tests exactly what the MCP server would do.

Run it with:

    IMAP_LIVE_TEST_ACCOUNT=<id> .venv/bin/python -m pytest tests/test_live.py -v

Without IMAP_LIVE_TEST_ACCOUNT every test here is skipped.
"""

from __future__ import annotations

import os

import pytest

import accounts
import imap_client

ACCOUNT_ID = os.getenv("IMAP_LIVE_TEST_ACCOUNT", "").strip()

pytestmark = pytest.mark.skipif(not ACCOUNT_ID, reason="set IMAP_LIVE_TEST_ACCOUNT=<account id> to run")


@pytest.fixture(scope="module")
def live_account() -> accounts.Account:
    return accounts.get_account(ACCOUNT_ID)


def _inbox_status(account: accounts.Account) -> dict[bytes, int]:
    with imap_client.open_imap(account) as client:
        # STATUS neither selects the folder nor touches flags.
        return client.folder_status("INBOX", [b"MESSAGES", b"UNSEEN", b"UIDNEXT"])


def _flags(account: accounts.Account, uid: int, uidvalidity: int) -> list[str]:
    with imap_client.open_imap(account) as client:
        imap_client._examine(client, "INBOX", uidvalidity)
        data = client.fetch([uid], [b"FLAGS"])
        return sorted(imap_client._flags_list(data[uid][b"FLAGS"]))


def test_reading_live_mail_leaves_it_unread(live_account):
    folders = imap_client.list_folders(live_account, with_counts=True)
    assert any(f["name"].upper() == "INBOX" for f in folders)

    before = _inbox_status(live_account)

    unread = imap_client.search(live_account, "INBOX", ["UNSEEN"], limit=1)
    latest = imap_client.search(live_account, "INBOX", ["ALL"], limit=5)
    assert latest["returned"] <= 5
    candidates = unread["messages"] or latest["messages"]
    if not candidates:
        pytest.skip("INBOX is empty")
    target = candidates[0]
    uid, validity = target["uid"], target["uidvalidity"]
    flags_before = _flags(live_account, uid, validity)

    parsed, flags_reported, _ = imap_client.get_message(live_account, "INBOX", uid, uidvalidity=validity)
    assert sorted(flags_reported) == flags_before
    assert isinstance(parsed.text, str)

    assert _flags(live_account, uid, validity) == flags_before
    after = _inbox_status(live_account)
    if after[b"UIDNEXT"] == before[b"UIDNEXT"]:
        assert after[b"UNSEEN"] == before[b"UNSEEN"]
    else:
        # New mail arrived during the test; reading may still not have
        # lowered the count.
        assert after[b"UNSEEN"] >= before[b"UNSEEN"]
