# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Approval of each message before it is sent.

When an account may send directly (send_mode = send), its send_approval
setting decides who says yes to each message:

    ask            the user approves every message
    ask_or_window  the user approves, and may allow sending without asking
                   for a limited time (IMAP_SEND_ALLOW_MINUTES, 30 by default)
    never          no approval; the client's own tool prompt is all there is

The question is asked outside the model's reach. On macOS a native dialog
shows the sender, all recipients including Bcc, the subject and the start
of the text, with Cancel as the default button: the user approves the
actual message, which the model can no longer change. Elsewhere the client
is asked to put the question to the user (MCP elicitation). A client that
supports neither cannot approve, and the message is saved as a draft
instead so nothing is lost and nothing is sent unseen.

A time window lives only in this process's memory. It ends when it
expires, when the server restarts, or when the account's settings change.

Entry points:
    approve(account, msg, ctx) -> Decision
    revoke(account_id)
"""

from __future__ import annotations

import locale
import os
import re
import subprocess
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses
from functools import lru_cache

import anyio
from pydantic import BaseModel, Field

import accounts
import i18n
import mail_parse
import native_dialog
import smtp_client

ALLOW_MINUTES = int(os.getenv("IMAP_SEND_ALLOW_MINUTES", "30"))
# The approval must show everything the AI wrote. A truncated preview would
# let text be sent that the user never saw, and macOS's `display dialog`
# clips long text without a scroll bar. The whole dialog text (intro,
# recipients, subject, body) is therefore kept within conservative bounds;
# anything larger is saved as a draft instead of being approved in a
# dialog that might not show all of it.
APPROVAL_MAX_CHARS = int(os.getenv("IMAP_APPROVAL_MAX_CHARS", "1500"))
DIALOG_MAX_CHARS = APPROVAL_MAX_CHARS + 700
DIALOG_MAX_LINES = 45

_lock = threading.Lock()
# account id -> (monotonic expiry, fingerprint of the settings it was granted under)
_windows: dict[str, tuple[float, tuple]] = {}


@dataclass
class Decision:
    approved: bool
    how: str            # "dialog" | "window" | "elicitation" | "not_required" | "declined" | "unavailable" | "too_long"
    window_until: float | None = None


class _SendConfirmation(BaseModel):
    """Schema for the client-side question when no native dialog exists."""

    send: bool = Field(description="Send this message now?")


def _fingerprint(account: accounts.Account) -> tuple:
    # A window granted for one configuration must not survive a change of
    # recipients' server, sender address or permissions.
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


def _open_window(account: accounts.Account) -> float:
    expiry = time.monotonic() + ALLOW_MINUTES * 60
    with _lock:
        _windows[account.id] = (expiry, _fingerprint(account))
    return time.time() + ALLOW_MINUTES * 60


@lru_cache(maxsize=1)
def _system_language() -> str:
    """The user's interface language, for dialogs shown outside any client."""
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


def _display_text(text: str) -> str:
    """The AI's text for the dialog: complete, but without room to hide anything.

    Runs of blank lines and long runs of spaces are shortened so that no
    part of the text can be pushed out of sight below or beside the rest.
    """
    text = re.sub(r"[ \t]{4,}", "   ", text.strip())
    return re.sub(r"\n\s*\n(\s*\n)+", "\n\n", text)


# Characters per visual line in the dialog, conservatively narrow. Lines are
# measured as they will wrap, not as logical lines, so a single long line
# cannot be taller than the limit suggests.
DIALOG_COLUMNS = 60


def _display_width(text: str) -> int:
    # Ambiguous-width characters are counted wide: overestimating height
    # only sends a message to drafts, underestimating could hide text.
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F", "A") else 1 for ch in text)


def _wrap_by_width(line: str, width: int) -> list[str]:
    """Greedy wrap on display width, breaking inside words when needed."""
    pieces, current, used = [], "", 0
    for ch in line:
        w = _display_width(ch)
        if used + w > width and current:
            pieces.append(current)
            current, used = "", 0
        current += ch
        used += w
    pieces.append(current)
    return pieces


def rendered_lines(message: str) -> int:
    """Lines the dialog text occupies once wrapped at DIALOG_COLUMNS."""
    return sum(max(1, -(-_display_width(line) // DIALOG_COLUMNS)) for line in message.splitlines() or [""])


def fits_dialog(message: str) -> bool:
    """Whether a dialog text is small enough to be shown in full."""
    return len(message) <= DIALOG_MAX_CHARS and rendered_lines(message) <= DIALOG_MAX_LINES


@dataclass
class Quotation:
    """What a reply or forward quotes, described for the approval dialog.

    Only the parsed address is shown, never the sender's display name:
    the name is written by the sender and could imitate the dialog's own
    wording. A forward also shows the start of the forwarded text, because
    passing a message on is where a manipulated model would leak data.
    """

    address: str
    subject: str
    date: str | None
    excerpt: str = ""


EXCERPT_CHARS = 300
# Plain addresses only. Quoted local parts ("Press Send"@example.com) are
# valid but would let a sender put words into the dialog.
_PLAIN_ADDRESS = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")


def _safe_address(address: str) -> str:
    return f"<{address}>" if _PLAIN_ADDRESS.match(address or "") else "<?>"


def _summary(msg: EmailMessage, lang: str, authored: str, quoted: Quotation | None) -> str:
    def line(key: str, header: str) -> str | None:
        # Addresses only: display names in a reply's recipients come from
        # the original sender and could imitate the dialog's own wording.
        addresses = [addr for _name, addr in getaddresses(msg.get_all(header, [])) if addr]
        return f"{i18n.translate(lang, key)}: {', '.join(addresses)}" if addresses else None

    parts = [
        line("send.from", "From"), line("send.to", "To"), line("send.cc", "Cc"),
        line("send.bcc", "Bcc"),
        f"{i18n.translate(lang, 'send.subject')}: {mail_parse.sanitise_line(str(msg['Subject']))[:200]}",
        "", _display_text(authored),
    ]
    if quoted:
        parts += ["", i18n.translate(lang, "send.quoted_from", sender=_safe_address(quoted.address)),
                  f"{i18n.translate(lang, 'send.subject')}: {smtp_client.clean_body(quoted.subject)[:200]}"]
        if quoted.date:
            parts.append(f"{i18n.translate(lang, 'send.date')}: {quoted.date}")
        if quoted.excerpt:
            excerpt = _display_text(smtp_client.clean_body(quoted.excerpt))
            cut = excerpt[:EXCERPT_CHARS] + (" …" if len(excerpt) > EXCERPT_CHARS else "")
            # Fenced line by line so remote text cannot pass for dialog text.
            # Wrapped here by display width, before fencing, so that no line
            # the dialog would wrap on its own can appear without the marker.
            wrapped = [piece for line in cut.expandtabs(8).splitlines()
                       for piece in _wrap_by_width(line, DIALOG_COLUMNS - _display_width("> "))]
            parts += [i18n.translate(lang, "send.excerpt")] + [f"> {piece}" for piece in wrapped]
    return "\n".join(p for p in parts if p is not None)


async def approve(
    account: accounts.Account,
    msg: EmailMessage,
    ctx,
    authored: str | None = None,
    quoted: Quotation | None = None,
) -> Decision:
    """Decide whether `msg` may be sent now. Never raises for a refusal.

    `authored` is the part of the body the AI wrote; for a reply or forward
    the rest is a quotation the server built from the original message and
    is described by `quoted` instead of shown in full. For a new
    message the whole body is the AI's.
    """
    mode = account.permissions.send_approval
    if mode is accounts.SendApproval.NEVER:
        return Decision(True, "not_required")
    if mode is accounts.SendApproval.ASK_OR_WINDOW and _window_open(account):
        return Decision(True, "window")

    authored = smtp_client.clean_body(authored if authored is not None else msg.get_content())
    if len(_display_text(authored)) > APPROVAL_MAX_CHARS:
        return Decision(False, "too_long")

    lang = _system_language()
    t = lambda key, **v: i18n.translate(lang, key, **v)  # noqa: E731
    message = t("send.dialog.intro", name=account.display_name) + "\n\n" + _summary(msg, lang, authored, quoted)
    # The exact string measured is the string shown: normalised once more as
    # a whole, so no header value can carry its own line separators.
    # Tabs are expanded so the width measured is the width shown.
    message = smtp_client.clean_body(message).expandtabs(8)
    fence_ok = all(_display_width(line) <= DIALOG_COLUMNS for line in message.splitlines() if line.startswith("> "))
    if not fits_dialog(message) or not fence_ok:
        return Decision(False, "too_long")

    if native_dialog.available():
        buttons = [t("dialog.cancel"), t("send.dialog.send")]
        if mode is accounts.SendApproval.ASK_OR_WINDOW:
            buttons.insert(1, t("send.dialog.send_and_allow", minutes=ALLOW_MINUTES))
        try:
            choice = await anyio.to_thread.run_sync(
                native_dialog.choose, t("send.dialog.title"), message, buttons
            )
        except native_dialog.DialogUnavailable:
            choice = None
            return Decision(False, "unavailable")
        if choice is None:
            return Decision(False, "declined")
        if len(buttons) == 3 and choice == buttons[1]:
            return Decision(True, "dialog", window_until=_open_window(account))
        return Decision(True, "dialog")

    # No native dialog: ask the client to put the question to the user.
    if ctx is None:
        return Decision(False, "unavailable")
    try:
        result = await ctx.elicit(message=message, schema=_SendConfirmation)
    except Exception:  # noqa: BLE001 - client without elicitation support
        return Decision(False, "unavailable")
    if getattr(result, "action", "") == "accept" and getattr(result.data, "send", False):
        return Decision(True, "elicitation")
    return Decision(False, "declined")
