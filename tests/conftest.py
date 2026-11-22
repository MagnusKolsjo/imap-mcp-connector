# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Shared fixtures: a fake IMAP server, a temporary account config and a seeded mailbox.

The fake server runs once per test session; every test gets a freshly
seeded store and the default capabilities, so tests that change
capabilities or move mail cannot leak into each other.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import keyring
import pytest
from imapclient import IMAPClient
from keyring.backend import KeyringBackend

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import accounts  # noqa: E402
import imap_client  # noqa: E402
from fake_imap import DEFAULT_CAPABILITIES, FakeImapServer  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
USER = "test@example.com"
PASSWORD = "correct horse battery staple"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class MemoryKeyring(KeyringBackend):
    """A secure-looking keyring that lives in a dict for the duration of a test."""

    priority = 1

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


@pytest.fixture(autouse=True)
def isolated_keyring(request):
    """Keep every test away from the developer's real keychain.

    The live test is the exception: it must resolve the real account's
    password exactly as the MCP server would.
    """
    if request.module.__name__.endswith("test_live"):
        yield None
        return
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture(autouse=True)
def no_native_dialogs(monkeypatch):
    """Never pop up real macOS dialogs during tests.

    Tests that exercise dialogs replace these functions with fakes of their
    own; everything else behaves as on a system without native dialogs.
    """
    import native_dialog
    import send_approval

    def refuse(*_args, **_kwargs):
        raise AssertionError("A test tried to open a real native dialog.")

    monkeypatch.setattr(native_dialog, "available", lambda: False)
    monkeypatch.setattr(native_dialog, "_run", refuse)
    send_approval._windows.clear()


@pytest.fixture(scope="session")
def fake_server():
    server = FakeImapServer(user=USER, password=PASSWORD).start()
    yield server
    server.stop()


def _days_ago(days: int) -> datetime:
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0)


@pytest.fixture
def mailbox(fake_server):
    """Seed the store and return {name: (folder, uid)} for each fixture message.

    Dates are relative to today so that SINCE searches and the 30-day
    statistics window behave the same whenever the suite runs.
    """
    store = fake_server.store
    store.reset()
    fake_server.capabilities = list(DEFAULT_CAPABILITIES)
    fake_server.log.clear()
    store.add_folder("INBOX")
    store.add_folder("Sent", "\\Sent")
    store.add_folder("Drafts", "\\Drafts")
    store.add_folder("Trash", "\\Trash")
    store.add_folder("Archive")
    seeds = [
        ("plain", "INBOX", "plain.eml", (), 1),
        ("html", "INBOX", "html_hidden.eml", (), 2),
        ("multipart", "INBOX", "multipart_attachments.eml", (), 3),
        ("swedish", "INBOX", "swedish.eml", (), 4),
        ("thread_original", "INBOX", "thread_original.eml", ("\\Seen",), 10),
        ("newsletter", "INBOX", "newsletter.eml", ("\\Seen",), 40),
        ("thread_reply", "Sent", "thread_reply.eml", ("\\Seen",), 10),
    ]
    ids = {}
    for key, folder, filename, flags, age in seeds:
        uid = store.add_message(folder, fixture_bytes(filename), flags, _days_ago(age))
        ids[key] = (folder, uid)
    return ids


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "config" / "accounts.json"
    monkeypatch.setenv("IMAP_CONNECTOR_CONFIG", str(path))
    # The module caches by path and mtime; a fresh path per test is enough,
    # but clearing it keeps tests independent of execution order.
    monkeypatch.setattr(accounts, "_cache", None)
    return path


@pytest.fixture
def account(config_file, fake_server, mailbox, monkeypatch) -> accounts.Account:
    acc = accounts.Account(
        id="test",
        display_name="Test account",
        email=USER,
        imap_host="127.0.0.1",
        imap_port=fake_server.port,
        imap_security="starttls",
    )
    accounts.save_account(acc)
    monkeypatch.setenv("IMAP_SECRET_TEST", PASSWORD)

    def connect(account: accounts.Account) -> IMAPClient:
        return IMAPClient("127.0.0.1", port=fake_server.port, ssl=False, timeout=10)

    monkeypatch.setattr(imap_client, "_connect", connect)
    return accounts.get_account("test")


@pytest.fixture
def raw_client(fake_server, mailbox):
    """A logged-in IMAPClient for poking the fake server directly."""
    client = IMAPClient("127.0.0.1", port=fake_server.port, ssl=False, timeout=10)
    client.login(USER, PASSWORD)
    yield client
    try:
        client.logout()
    except Exception:  # noqa: BLE001
        pass


@pytest.fixture(autouse=True)
def apps_client(monkeypatch):
    """Tests call tools in-process, without a client that negotiated MCP Apps.

    The panel's send path requires one; tests pretend to be such a client
    unless they set `apps_client.supported = False`.
    """
    import mcp_panels

    class Flag:
        supported = True

    flag = Flag()
    monkeypatch.setattr(mcp_panels, "_apps_client", lambda ctx: flag.supported)
    return flag
