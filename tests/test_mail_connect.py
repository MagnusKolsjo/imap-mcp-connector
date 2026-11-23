# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""The shared connection code: one name lookup and one deadline for the whole attempt.

Local sockets stand in for mail servers; the name lookup is replaced, so
nothing here needs a network.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import accounts
import mail_connect
import smtp_client


def _infos(*addresses):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", address) for address in addresses]


@pytest.fixture
def listener():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        yield server.getsockname()


@pytest.fixture
def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()


def _wait_until(condition, seconds=2.0):
    end = time.monotonic() + seconds
    while not condition() and time.monotonic() < end:
        time.sleep(0.01)
    return condition()


class _SilentSocket:
    """A socket whose connect gets no answer, as when a firewall drops the packets."""

    tried: list[float] = []

    def __init__(self, *args):
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        _SilentSocket.tried.append(self.timeout)
        time.sleep(self.timeout)
        raise TimeoutError("timed out")

    def close(self):
        pass


def test_the_next_address_is_tried_when_one_refuses(monkeypatch, listener, closed_port):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _infos(closed_port, listener))
    sock = mail_connect.open_socket("mail.example", 993, 5.0)
    try:
        assert sock.getpeername() == listener
        assert 5.0 / 3 <= sock.gettimeout() <= 5.0          # the handshake and greeting are bounded too
    finally:
        sock.close()


def test_all_addresses_share_one_deadline(monkeypatch):
    """Many silent addresses take the budget together, not the budget each."""
    _SilentSocket.tried = []
    monkeypatch.setattr(mail_connect, "_MIN_PER_ADDRESS", 0.01)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _infos(*[(f"192.0.2.{i}", 993) for i in range(12)]))
    monkeypatch.setattr(mail_connect.socket, "socket", _SilentSocket)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        mail_connect.open_socket("mail.example", 993, 0.6)
    assert time.monotonic() - started < 0.9
    assert len(_SilentSocket.tried) == 12                    # every address got its turn
    assert max(_SilentSocket.tried) < 0.2


def test_slow_name_lookup_counts_against_the_budget(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: time.sleep(3))
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="looking up slow.example"):
        mail_connect.open_socket("slow.example", 993, 1.5)
    assert time.monotonic() - started < 1


def test_hung_lookups_never_block_later_ones(monkeypatch, listener):
    """Lookups that never finish fill no shared queue; past the cap the call fails at once."""
    release = threading.Event()
    before = mail_connect._open_lookups                      # lookups from earlier tests may still run
    monkeypatch.setattr(mail_connect, "_MAX_OPEN_LOOKUPS", before + 3)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: release.wait())
    for _ in range(3):
        with pytest.raises(TimeoutError):
            mail_connect.open_socket("hung.example", 993, 0.3)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="not answering"):
        mail_connect.open_socket("hung.example", 993, 5.0)
    assert time.monotonic() - started < 0.5                  # cap reached: no waiting at all
    release.set()
    assert _wait_until(lambda: mail_connect._open_lookups <= before)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _infos(listener))
    mail_connect.open_socket("mail.example", 993, 5.0).close()


def test_no_such_name_is_told_apart_from_other_lookup_errors(monkeypatch):
    def fail_with(code):
        def lookup(*args, **kwargs):
            raise socket.gaierror(code, "lookup failed")
        return lookup

    monkeypatch.setattr(socket, "getaddrinfo", fail_with(socket.EAI_NONAME))
    with pytest.raises(mail_connect.NameNotFound):
        mail_connect.open_socket("no-such.example", 993, 5.0)
    monkeypatch.setattr(socket, "getaddrinfo", fail_with(socket.EAI_AGAIN))
    with pytest.raises(socket.gaierror) as info:
        mail_connect.open_socket("later.example", 993, 5.0)
    assert not isinstance(info.value, mail_connect.NameNotFound)


def test_unexpected_lookup_error_becomes_oserror(monkeypatch):
    def broken(*args, **kwargs):
        raise UnicodeError("label too long")

    monkeypatch.setattr(socket, "getaddrinfo", broken)
    before = mail_connect._open_lookups
    with pytest.raises(OSError, match="name lookup for x.example failed"):
        mail_connect.open_socket("x.example", 993, 5.0)
    assert mail_connect._open_lookups == before


def test_thread_start_failure_is_an_oserror_and_releases_its_place(monkeypatch):
    class NoThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(mail_connect.threading, "Thread", NoThread)
    before = mail_connect._open_lookups
    with pytest.raises(OSError, match="could not be started"):
        mail_connect.open_socket("x.example", 993, 5.0)
    assert mail_connect._open_lookups == before


@pytest.mark.parametrize("value", ["0", "-3", "soon", ""])
def test_unusable_budget_counts_as_the_default(monkeypatch, value):
    monkeypatch.setenv("IMAP_CONNECT_TIMEOUT", value)
    assert mail_connect.budget_from_env("IMAP_CONNECT_TIMEOUT") == 15.0
    monkeypatch.setenv("IMAP_CONNECT_TIMEOUT", "4.5")
    assert mail_connect.budget_from_env("IMAP_CONNECT_TIMEOUT") == 4.5


# -----------------------------------------------------------------------------
# SMTP goes the same way
# -----------------------------------------------------------------------------

@pytest.fixture
def sender(monkeypatch):
    monkeypatch.setattr(accounts, "get_secret", lambda account_id, kind: "secret")
    return accounts.Account(
        id="send", display_name="Send", email="me@example.org",
        imap_host="imap.example.org", smtp_host="smtp.example.org", smtp_port=465, smtp_security="ssl",
    )


def _message():
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "me@example.org", "you@example.org", "Hello"
    msg.set_content("Hello")
    return msg


def test_blocked_smtp_server_is_reported_like_a_blocked_imap_server(sender, monkeypatch, closed_port):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _infos(closed_port))
    with pytest.raises(smtp_client.SmtpError, match=r"^Cannot reach the mail server smtp.example.org:465 .*VPN"):
        smtp_client.send_message(sender, _message())


def test_misspelt_smtp_server_name(sender, monkeypatch):
    def no_such_name(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "not known")

    monkeypatch.setattr(socket, "getaddrinfo", no_such_name)
    with pytest.raises(smtp_client.SmtpError, match=r"^Cannot find the mail server smtp.example.org: "):
        smtp_client.send_message(sender, _message())


def test_failed_smtp_starttls_says_the_password_was_not_sent(sender, monkeypatch, listener):
    """A server that answers but closes during STARTTLS was reached; only encryption failed."""
    sender.smtp_security, sender.smtp_port = "starttls", 587
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"220 ready\r\n")
        conn.recv(1024)
        conn.sendall(b"250-smtp.example.org\r\n250 STARTTLS\r\n")
        conn.recv(1024)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: _infos(server.getsockname()))
    try:
        with pytest.raises(smtp_client.SmtpError, match="STARTTLS.*password was not sent"):
            smtp_client.send_message(sender, _message())
    finally:
        server.close()
