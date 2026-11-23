# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""Composing and sending mail.

Messages are built in memory with the stdlib email package and either
handed to SMTP or appended to the Drafts folder by the caller. Nothing is
written to disk.

Every message has a plain-text body. An HTML alternative is added when the
caller passes one, already reduced to plain formatting by html_mail.sanitise.

Entry points:
    build_message(account, ...) -> EmailMessage
    reply_headers(original_headers) -> dict
    send_message(account, msg) -> list[str]   (accepted recipients)
"""

from __future__ import annotations

import os
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, getaddresses

import accounts
import mail_connect

SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "30"))
# The whole attempt to reach the server: the name lookup and all of the
# host's addresses. See mail_connect.
SMTP_CONNECT_TIMEOUT = mail_connect.budget_from_env("SMTP_CONNECT_TIMEOUT")
# A guard against a model being steered into mass mailing.
MAX_RECIPIENTS = int(os.getenv("SMTP_MAX_RECIPIENTS", "20"))

_ADDRESS = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


class SmtpError(Exception):
    """A readable error from composing or sending mail."""


def _clean_addresses(values: list[str] | None) -> list[str]:
    """Parse and validate recipients; never drop one silently.

    getaddresses() returns an empty pair for input it cannot parse (such as
    "a@x.se;b@y.se"), so the number of addresses found is compared with the
    number of "@" signs given, and any mismatch is an error.
    """
    out = []
    for value in values or []:
        value = (value or "").strip()
        if not value:
            continue
        _no_header_injection(value, "Recipient")
        parsed = [(n, a.strip()) for n, a in getaddresses([value]) if a.strip()]
        if not parsed or len(parsed) != value.count("@"):
            raise SmtpError(
                f"Could not read the recipient {value!r}. Give one address per "
                "list item, e.g. [\"anna@example.se\", \"Bo <bo@example.se>\"]."
            )
        for name, addr in parsed:
            if not _ADDRESS.match(addr):
                raise SmtpError(f"Invalid e-mail address: {addr!r}")
            out.append(formataddr((name, addr)) if name else addr)
    return out


def _no_header_injection(value: str, field: str) -> str:
    # Every character str.splitlines() treats as a line boundary, checked
    # directly so a trailing one is caught as well.
    if any(ch in _LINE_BOUNDARIES for ch in value):
        raise SmtpError(f"{field} must be a single line.")
    return value


_LINE_BOUNDARIES = set("\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")


def build_message(
    account: accounts.Account,
    *,
    to: list[str],
    subject: str,
    body: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    in_reply_to: str = "",
    references: list[str] | None = None,
    html: str | None = None,
) -> EmailMessage:
    to_list = _clean_addresses(to)
    cc_list = _clean_addresses(cc)
    bcc_list = _clean_addresses(bcc)
    if not (to_list or cc_list or bcc_list):
        raise SmtpError("At least one recipient is required.")
    if len(to_list) + len(cc_list) + len(bcc_list) > MAX_RECIPIENTS:
        raise SmtpError(f"At most {MAX_RECIPIENTS} recipients per message (SMTP_MAX_RECIPIENTS).")

    msg = EmailMessage()
    msg["From"] = formataddr((account.display_name, account.email))
    if to_list:
        msg["To"] = ", ".join(to_list)
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    if bcc_list:
        # Kept on the message object so SMTP can deliver to them; removed
        # before the copy is stored in Sent/Drafts by the caller.
        msg["Bcc"] = ", ".join(bcc_list)
    msg["Subject"] = _no_header_injection(subject, "Subject")
    msg["Date"] = formatdate(localtime=True)
    domain = account.email.rsplit("@", 1)[-1]
    msg["Message-ID"] = make_msgid(domain=domain)
    if in_reply_to:
        msg["In-Reply-To"] = _no_header_injection(in_reply_to, "In-Reply-To")
    if references:
        msg["References"] = _no_header_injection(" ".join(references), "References")
    # Invisible characters are removed so that what the user approved is
    # exactly what goes out.
    msg.set_content(clean_body(body), subtype="plain", charset="utf-8")
    if html is not None:
        # multipart/alternative: the plain text above, and the HTML, which
        # the caller has sanitised (html_mail.sanitise).
        msg.add_alternative(html, subtype="html", charset="utf-8")
    return msg


def plain_part(msg: EmailMessage) -> str:
    part = msg.get_body(preferencelist=("plain",))
    return part.get_content() if part is not None else ""


def html_part(msg: EmailMessage) -> str | None:
    part = msg.get_body(preferencelist=("html",))
    return part.get_content() if part is not None else None


def clean_body(text: str) -> str:
    """Drop invisible and control characters (keeping line breaks and tabs)."""
    import mail_parse

    import unicodedata

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Unicode line/paragraph separators and exotic spaces become plain ones,
    # so the approval dialog's blank-line and space folding sees them too.
    text = text.replace("\u2028", "\n").replace("\u2029", "\n\n")
    text = "".join(" " if unicodedata.category(ch) == "Zs" else ch for ch in text)
    return "".join(ch for ch in text if not mail_parse._is_invisible(ch))


def without_bcc(msg: EmailMessage) -> bytes:
    """Serialise a message for storing in Sent or Drafts, minus Bcc."""
    import copy

    clone = copy.deepcopy(msg)
    del clone["Bcc"]
    return clone.as_bytes()


def reply_subject(subject: str, prefix: str = "Re:") -> str:
    if re.match(rf"^\s*{re.escape(prefix)}", subject, re.IGNORECASE):
        return subject
    return f"{prefix} {subject}".strip()


class _Smtp(smtplib.SMTP):
    """smtplib's connection, opened through mail_connect so the whole attempt has one deadline."""

    def _get_socket(self, host, port, timeout):
        return mail_connect.open_socket(host, port, SMTP_CONNECT_TIMEOUT)


class _SmtpTls(smtplib.SMTP_SSL):
    """The same for implicit TLS; the certificate is checked against the host name."""

    def _get_socket(self, host, port, timeout):
        sock = mail_connect.open_socket(host, port, SMTP_CONNECT_TIMEOUT)
        try:
            return self.context.wrap_socket(sock, server_hostname=self._host)
        except BaseException:
            sock.close()
            raise


def _connect(account: accounts.Account) -> smtplib.SMTP:
    """Open an encrypted SMTP connection. Separate so tests can use a local server."""
    context = ssl.create_default_context()
    if account.smtp_security == "ssl":
        server = _SmtpTls(account.smtp_host, account.smtp_port, context=context, timeout=SMTP_TIMEOUT)
        server.sock.settimeout(SMTP_TIMEOUT)
        return server
    server = _Smtp(account.smtp_host, account.smtp_port, timeout=SMTP_TIMEOUT)
    try:
        server.sock.settimeout(SMTP_TIMEOUT)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
    except BaseException as exc:
        server.close()  # never leave a half-open socket behind
        if isinstance(exc, (OSError, smtplib.SMTPException)):
            # The server was reached; only encryption failed. That is not a
            # network problem, and the connection may be tampered with.
            raise SmtpError(
                f"An encrypted connection (STARTTLS) could not be set up with {account.smtp_host}: "
                f"{exc}. The password was not sent. Someone may be interfering with the "
                "connection, or the server does not support STARTTLS (try SSL/TLS on port 465)."
            ) from exc
        raise
    return server


def send_message(account: accounts.Account, msg: EmailMessage) -> list[str]:
    """Send through the account's SMTP server and return accepted recipients."""
    if not account.smtp_host:
        raise SmtpError("No SMTP server is configured for this account.")
    try:
        password = accounts.get_secret(account.id, "smtp")
    except accounts.SecretError as exc:
        raise SmtpError(str(exc)) from exc

    try:
        server = _connect(account)
    except mail_connect.NameNotFound as exc:
        raise SmtpError(mail_connect.not_found_text(account.smtp_host)) from exc
    except (smtplib.SMTPException, ssl.SSLError) as exc:
        raise SmtpError(f"Cannot connect to {account.smtp_host}:{account.smtp_port}: {exc}") from exc
    except OSError as exc:
        raise SmtpError(mail_connect.unreachable_text(account.smtp_host, account.smtp_port, exc)) from exc

    try:
        with server:
            server.login(account.smtp_login, password)
            refused = server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise SmtpError(
            f"SMTP login to {account.smtp_host} failed for {account.smtp_login}. "
            "Check the user name and password (many providers require an app password)."
        ) from exc
    except (smtplib.SMTPException, OSError) as exc:
        raise SmtpError(f"Sending failed via {account.smtp_host}: {exc}") from exc

    recipients = [a for _, a in getaddresses(msg.get_all("To", []) + msg.get_all("Cc", []) + msg.get_all("Bcc", []))]
    return [r for r in recipients if r not in refused]
