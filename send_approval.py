# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Approval of each message before it is sent.

When an account may send directly (send_mode = send), its send_approval
setting decides who says yes to each message:

    ask            the user approves every message in the mailbox panel
    ask_or_window  the same, and the user may allow sending without asking
                   for a limited time (IMAP_SEND_ALLOW_MINUTES, 30 by default)
    never          no approval; the client's own tool prompt is all there is

When the AI sends, the user is asked with the client's own simple approval
prompt (MCP elicitation): recipients and subject, Send or Cancel, and for
ask_or_window a choice not to be asked again for a while. A client that
cannot ask gets the message saved as a draft and opened in the mailbox
panel instead, so nothing is sent unapproved.

When the user sends from the mailbox panel, the panel's "review and send"
view shows the complete message as it will be sent and enables Send only
once the user has scrolled to its end.

The panel's review step gets a one-time approval token bound to the exact
message (sender, recipients including Bcc, subject and complete text).
Sending is refused unless the token matches the message being sent, so
what goes out is exactly what was shown. The token cannot prove that a
person pressed the button; that rests on the client keeping the panel's
tools away from the model (`visibility: ["app"]`).

Tokens and time windows live only in this process's memory. Windows end
when they expire, when the server restarts, or when the account's settings
change; tokens expire after APPROVAL_TOKEN_MINUTES or on first use.

Entry points:
    approve(account) -> Decision
    issue_token(account, msg) -> str
    redeem_token(account, msg, token) -> bool
    open_window(account) -> float
    revoke(account_id)
    Quotation
"""

from __future__ import annotations

import hashlib
import hmac
import locale
import os
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses
from functools import lru_cache

from pydantic import BaseModel, Field

import accounts
import i18n

ALLOW_MINUTES = int(os.getenv("IMAP_SEND_ALLOW_MINUTES", "30"))
APPROVAL_TOKEN_MINUTES = 15

_lock = threading.Lock()
# account id -> (monotonic expiry, fingerprint of the settings it was granted under)
_windows: dict[str, tuple[float, tuple]] = {}
# token -> (monotonic expiry, account id, message digest)
_tokens: dict[str, tuple[float, str, str]] = {}
_SECRET = secrets.token_bytes(32)


@dataclass
class Decision:
    approved: bool
    how: str            # "asked" | "window" | "not_required" | "panel" | "declined"
    window_until: float | None = None


@dataclass
class Quotation:
    """What a reply or forward quotes (kept for callers; shown in the panel)."""

    address: str
    subject: str
    date: str | None
    excerpt: str = ""


def _fingerprint(account: accounts.Account) -> tuple:
    # A window granted for one configuration must not survive a change of
    # sender address, outgoing server or permissions.
    return (account.email, account.smtp_host, account.smtp_port, account.smtp_username,
            account.permissions.send_mode.value, account.permissions.send_approval.value)


def revoke(account_id: str) -> None:
    with _lock:
        _windows.pop(account_id, None)


def _window_open(account: accounts.Account) -> bool:
    with _lock:
        entry = _windows.get(account.id)
        if not entry:
            return False
        expiry, fingerprint = entry
        if time.monotonic() >= expiry or fingerprint != _fingerprint(account):
            _windows.pop(account.id, None)
            return False
        return True


def open_window(account: accounts.Account) -> float:
    """Allow sending without approval for ALLOW_MINUTES; returns the end as a Unix time."""
    expiry = time.monotonic() + ALLOW_MINUTES * 60
    with _lock:
        _windows[account.id] = (expiry, _fingerprint(account))
    return time.time() + ALLOW_MINUTES * 60


class _AskToSend(BaseModel):
    send: bool = Field(description="Send the message now?")


class _AskToSendOrAllow(BaseModel):
    send: bool = Field(description="Send the message now?")
    allow_window: bool = Field(default=False, description="Don't ask again for a while")


def _short_summary(account: accounts.Account, msg: EmailMessage, lang: str) -> str:
    """One short question, but never hiding where the mail goes.

    Every recipient is listed (the recipient cap keeps this short) and Bcc
    is named separately; the subject is shown without quote characters so
    it cannot pass for part of the question.
    """
    def addresses(*headers: str) -> str:
        values = [v for h in headers for v in msg.get_all(h, [])]
        return ", ".join(addr for _n, addr in getaddresses(values) if addr)

    subject = " ".join(str(msg["Subject"] or "").split())
    subject = subject.translate({ord(c): None for c in '"”“„«»\'’‘'})[:120]
    question = i18n.translate(lang, "send.ask", name=account.display_name,
                              to=addresses("To", "Cc"), subject=subject)
    bcc = addresses("Bcc")
    if bcc:
        question += " " + i18n.translate(lang, "send.ask_bcc", bcc=bcc)
    return question


async def approve(account: accounts.Account, msg: EmailMessage | None = None, ctx=None) -> Decision:
    """Whether a message may be sent now, asking the user if the setting says so.

    The question is the client's own simple approval prompt (MCP
    elicitation): who it goes to and the subject, Send or Cancel, and for
    ask_or_window a choice not to be asked again for a while. A client that
    cannot ask gets "panel": the message waits as a draft in the panel.
    """
    mode = account.permissions.send_approval
    if mode is accounts.SendApproval.NEVER:
        return Decision(True, "not_required")
    if mode is accounts.SendApproval.ASK_OR_WINDOW and _window_open(account):
        return Decision(True, "window")
    if msg is None or ctx is None:
        return Decision(False, "panel")
    lang = _system_language()
    schema = _AskToSendOrAllow if mode is accounts.SendApproval.ASK_OR_WINDOW else _AskToSend
    question = _short_summary(account, msg, lang)
    if mode is accounts.SendApproval.ASK_OR_WINDOW:
        question += " " + i18n.translate(lang, "send.ask_window", minutes=ALLOW_MINUTES)
    try:
        answer = await ctx.elicit(message=question, schema=schema)
    except Exception:  # noqa: BLE001 - the client does not support asking
        return Decision(False, "panel")
    if getattr(answer, "action", "") != "accept" or not getattr(answer.data, "send", False):
        return Decision(False, "declined")
    if getattr(answer.data, "allow_window", False):
        return Decision(True, "asked", window_until=open_window(account))
    return Decision(True, "asked")


def message_digest(msg: EmailMessage) -> str:
    """A digest of everything a reviewer approves: sender, recipients, subject, text."""
    def addresses(header: str) -> list[str]:
        return sorted(addr.lower() for _n, addr in getaddresses(msg.get_all(header, [])) if addr)

    parts = [
        "from:" + ",".join(addresses("From")),
        "to:" + ",".join(addresses("To")),
        "cc:" + ",".join(addresses("Cc")),
        "bcc:" + ",".join(addresses("Bcc")),
        "subject:" + str(msg["Subject"] or ""),
        "body:" + msg.get_content(),
    ]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def issue_token(account: accounts.Account, msg: EmailMessage) -> str:
    """A one-time token approving exactly this message for this account."""
    digest = message_digest(msg)
    token = hmac.new(_SECRET, f"{account.id}:{digest}:{secrets.token_hex(8)}".encode(), hashlib.sha256).hexdigest()
    now = time.monotonic()
    with _lock:
        for key in [k for k, (expiry, *_r) in _tokens.items() if expiry <= now]:
            del _tokens[key]
        _tokens[token] = (now + APPROVAL_TOKEN_MINUTES * 60, account.id, digest)
    return token


def redeem_token(account: accounts.Account, msg: EmailMessage, token: str) -> bool:
    """Use up a token; True only if it approves exactly this message, unexpired."""
    with _lock:
        entry = _tokens.pop(token or "", None)
    if not entry:
        return False
    expiry, account_id, digest = entry
    return (time.monotonic() < expiry and account_id == account.id
            and hmac.compare_digest(digest, message_digest(msg)))


@lru_cache(maxsize=1)
def _system_language() -> str:
    """The user's interface language, for text written outside any client (quote lines)."""
    candidates = [os.getenv("IMAP_UI_LANGUAGE", "")]
    if sys.platform == "darwin":
        try:
            out = subprocess.run(["defaults", "read", "-g", "AppleLanguages"],
                                 capture_output=True, text=True, timeout=3).stdout
            candidates += [part.strip(' "\n(),') for part in out.split(",")]
        except (OSError, subprocess.SubprocessError):
            pass
    candidates.append((locale.getlocale()[0] or "").replace("_", "-"))
    for code in candidates:
        for option in (code, code.split("-")[0].lower()):
            if option and i18n.is_supported(option):
                return option
    return "en"
