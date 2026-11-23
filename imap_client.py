# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Magnus Kolsjö
"""IMAP access for one account at a time, without storing mail on disk.

Reading never changes a message. Two independent mechanisms guarantee it:

  1. Every read opens the folder with EXAMINE (imapclient's readonly=True).
     A server must not change flags in a read-only folder.
  2. Every content fetch uses BODY.PEEK[...]. The fetch items RFC822,
     RFC822.TEXT and BODY[...] set \\Seen implicitly and are never used here.

Only the explicit organise functions (set_flags, move, trash) open a folder
read-write, and they check UIDVALIDITY first so that a stale UID can never
hit the wrong message after the server renumbered a folder.

A message is addressed as (folder, uid), optionally pinned with the
folder's uidvalidity as returned by every read.

Connections are opened per call and closed afterwards. Login costs a few
hundred milliseconds, which is small next to a model turn, and it avoids
stale sockets and the thread-safety problems of sharing an IMAPClient.

Nothing in this module logs subjects, addresses or bodies.

Entry points:
    open_imap(account)                 context manager -> IMAPClient
    test_connection(account)
    list_folders, search, get_message, get_raw_message, find_thread,
    mailbox_stats, set_flags, move_messages, trash_messages,
    create_folder, append_message, special_folder
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from email import policy
from email.parser import BytesHeaderParser
from typing import Any, Iterator

from imapclient import IMAPClient, SocketTimeout
from imapclient.exceptions import IMAPClientError, LoginError

import accounts
import mail_parse

logger = logging.getLogger(__name__)

IMAP_TIMEOUT = float(os.getenv("IMAP_TIMEOUT", "30"))
# The whole attempt to reach the server, over all of its addresses. A host
# often has several, and the operating system tries them one after another:
# with the read timeout for each, a server that a VPN or firewall silently
# blocks kept a call waiting for minutes, longer than MCP clients wait for
# an answer. Short enough that the error reaches the user.
IMAP_CONNECT_TIMEOUT = float(os.getenv("IMAP_CONNECT_TIMEOUT", "15"))
# Upper bound for a whole message fetched into memory. Larger messages are
# refused rather than paged, because MIME cannot be parsed from a fragment.
MAX_MESSAGE_BYTES = int(os.getenv("IMAP_MAX_MESSAGE_MB", "25")) * 1024 * 1024
# Cap on how many messages one organise call may touch.
MAX_BULK = int(os.getenv("IMAP_MAX_BULK", "500"))

_HEADER_FIELDS = b"BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID IN-REPLY-TO LIST-UNSUBSCRIBE)]"
_HEADER_KEY = b"BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID IN-REPLY-TO LIST-UNSUBSCRIBE)]"

_SPECIAL_USE = {
    "sent": b"\\Sent",
    "drafts": b"\\Drafts",
    "trash": b"\\Trash",
    "junk": b"\\Junk",
    "archive": b"\\Archive",
    "all": b"\\All",
    "flagged": b"\\Flagged",
}

_FLAG_NAMES = {
    "seen": b"\\Seen",
    "flagged": b"\\Flagged",
    "answered": b"\\Answered",
    "draft": b"\\Draft",
}


class ImapError(Exception):
    """A readable error from talking to the IMAP server."""


class ServerUnreachable(ImapError):
    """No connection to the server could be opened (network, VPN, firewall)."""


class StaleUidError(ImapError):
    """The folder's UIDVALIDITY changed, so the given UIDs are meaningless."""


# -----------------------------------------------------------------------------
# Connection
# -----------------------------------------------------------------------------

# Name lookups run here so that a resolver that does not answer cannot hold
# a call past the deadline (getaddrinfo has no timeout of its own).
_RESOLVER = ThreadPoolExecutor(max_workers=4, thread_name_prefix="imap-dns")


def _connect_timeout(host: str, port: int) -> float:
    """Seconds per address, so that the lookup and every address fit IMAP_CONNECT_TIMEOUT.

    Raises TimeoutError when the name cannot be looked up within a third of
    the budget; socket.gaierror when it does not exist.
    """
    started = time.monotonic()
    lookup = _RESOLVER.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    try:
        infos = lookup.result(timeout=IMAP_CONNECT_TIMEOUT / 3)
    except FuturesTimeout as exc:
        raise TimeoutError(f"looking up {host} took longer than {IMAP_CONNECT_TIMEOUT / 3:.0f} s") from exc
    addresses = {info[4][0] for info in infos}
    left = IMAP_CONNECT_TIMEOUT - (time.monotonic() - started)
    return max(2.0, left / max(1, len(addresses)))


def _connect(account: accounts.Account) -> IMAPClient:
    """Open the TCP/TLS connection. Separate so tests can point it at a local server."""
    use_ssl = account.imap_security == "ssl"
    context = ssl.create_default_context()
    client = IMAPClient(
        account.imap_host,
        port=account.imap_port,
        ssl=use_ssl,
        ssl_context=context if use_ssl else None,
        timeout=SocketTimeout(connect=_connect_timeout(account.imap_host, account.imap_port), read=IMAP_TIMEOUT),
    )
    if not use_ssl:
        try:
            client.starttls(context)
        except BaseException as exc:
            client.shutdown()  # never leave a half-open socket behind
            if isinstance(exc, (OSError, IMAPClientError)):
                # The server was reached; only encryption failed. That is not a
                # network problem, and the connection may be tampered with.
                raise ImapError(
                    f"An encrypted connection (STARTTLS) could not be set up with {account.imap_host}: "
                    f"{_short(exc)}. The password was not sent. Someone may be interfering with the "
                    "connection, or the server does not support STARTTLS (try SSL/TLS on port 993)."
                ) from exc
            raise
    return client


@contextmanager
def open_imap(account: accounts.Account) -> Iterator[IMAPClient]:
    """Connect, log in, yield the client, always log out."""
    # Resolve the password before opening a socket, so a missing password
    # is reported at once instead of after a network round trip.
    try:
        password = accounts.get_secret(account.id, "imap")
    except accounts.SecretError as exc:
        raise ImapError(str(exc)) from exc
    try:
        client = _connect(account)
    except (TimeoutError, ConnectionRefusedError, socket.gaierror, OSError) as exc:
        if isinstance(exc, ssl.SSLError):
            raise ImapError(f"Cannot connect to {account.imap_host}:{account.imap_port}: {_short(exc)}") from exc
        raise ServerUnreachable(
            f"Cannot reach the mail server {account.imap_host}:{account.imap_port} ({_short(exc) or 'no answer'}). "
            "The network may be down, or a VPN, firewall or security program may be blocking mail "
            f"(port {account.imap_port}). Mail programs on this computer are probably affected too."
        ) from exc
    except IMAPClientError as exc:
        raise ImapError(f"Cannot connect to {account.imap_host}:{account.imap_port}: {_short(exc)}") from exc
    # Keep server timestamps timezone-aware. imapclient's default converts
    # them to naive local time, which leaves the model guessing the zone.
    client.normalise_times = False
    try:
        try:
            client.login(account.login, password)
        except LoginError as exc:
            raise ImapError(
                f"Login to {account.imap_host} failed for {account.login}. "
                "Check the user name and password (many providers require an app password)."
            ) from exc
        yield client
    except (OSError, IMAPClientError) as exc:
        raise ImapError(f"IMAP error on {account.imap_host}: {_short(exc)}") from exc
    finally:
        try:
            client.logout()
        except Exception:  # noqa: BLE001 - connection may already be gone
            try:
                client.shutdown()
            except Exception:  # noqa: BLE001
                pass


def _short(exc: Exception) -> str:
    text = str(exc)
    return text if len(text) <= 300 else text[:300] + "…"


def _is_gmail(client: IMAPClient) -> bool:
    return b"X-GM-EXT-1" in client.capabilities()


def test_connection(account: accounts.Account) -> dict[str, Any]:
    """Log in, list folders and report capabilities. Changes nothing."""
    with open_imap(account) as client:
        caps = sorted(c.decode() for c in client.capabilities())
        folders = client.list_folders()
        return {
            "ok": True,
            "folder_count": len(folders),
            "gmail": _is_gmail(client),
            "capabilities": caps,
            "special_folders": {
                key: special_folder(client, account, key) for key in ("sent", "drafts", "trash")
            },
        }


# -----------------------------------------------------------------------------
# Folders
# -----------------------------------------------------------------------------

def special_folder(client: IMAPClient, account: accounts.Account, kind: str) -> str | None:
    """Find Sent/Drafts/Trash: account override, then SPECIAL-USE, then common names."""
    override = getattr(account, f"{kind}_folder", "") if kind in ("sent", "drafts", "trash") else ""
    if override:
        return override
    flag = _SPECIAL_USE.get(kind)
    if flag is None:
        return None
    # find_special_folder checks SPECIAL-USE first and then a list of common
    # (also localised) folder names, which covers most servers without
    # SPECIAL-USE support.
    found = client.find_special_folder(flag)
    return found


def list_folders(account: accounts.Account, with_counts: bool = False) -> list[dict[str, Any]]:
    with open_imap(account) as client:
        listing = client.list_folders()
        by_flag = {flag: kind for kind, flag in _SPECIAL_USE.items()}
        special: dict[str, str] = {}
        for flags, _delim, name in listing:
            for flag in flags:
                kind = by_flag.get(flag if isinstance(flag, bytes) else str(flag).encode())
                if kind:
                    special.setdefault(name, kind)
        # Name heuristics (extra LIST round trips) only for the common roles
        # and only when SPECIAL-USE did not announce them.
        for kind in ("sent", "drafts", "trash", "junk", "archive"):
            override = getattr(account, f"{kind}_folder", "")
            if override:
                special[override] = kind
            elif kind not in special.values():
                try:
                    found = client.find_special_folder(_SPECIAL_USE[kind])
                except IMAPClientError:
                    found = None
                if found:
                    special.setdefault(found, kind)

        result = []
        for flags, delimiter, name in listing:
            flag_names = [f.decode() if isinstance(f, bytes) else str(f) for f in flags]
            selectable = "\\Noselect" not in flag_names and "\\NonExistent" not in flag_names
            item: dict[str, Any] = {
                "name": name,
                "delimiter": delimiter.decode() if isinstance(delimiter, bytes) else delimiter,
                "special_use": special.get(name),
                "selectable": selectable,
            }
            if with_counts and selectable:
                # STATUS does not select the folder and never changes flags.
                try:
                    status = client.folder_status(name, [b"MESSAGES", b"UNSEEN"])
                    item["messages"] = status.get(b"MESSAGES")
                    item["unseen"] = status.get(b"UNSEEN")
                except IMAPClientError:
                    item["messages"] = item["unseen"] = None
            result.append(item)
        return result


def _examine(client: IMAPClient, folder: str, uidvalidity: int | None = None) -> int:
    """Open a folder read-only and return its UIDVALIDITY."""
    try:
        info = client.select_folder(folder, readonly=True)
    except IMAPClientError as exc:
        raise ImapError(f"Cannot open folder {folder!r}: {_short(exc)}") from exc
    current = int(info.get(b"UIDVALIDITY", 0))
    _check_uidvalidity(folder, uidvalidity, current)
    return current


def _select_rw(client: IMAPClient, folder: str, uidvalidity: int | None) -> int:
    try:
        info = client.select_folder(folder, readonly=False)
    except IMAPClientError as exc:
        raise ImapError(f"Cannot open folder {folder!r} for changes: {_short(exc)}") from exc
    current = int(info.get(b"UIDVALIDITY", 0))
    _check_uidvalidity(folder, uidvalidity, current)
    return current


def _check_uidvalidity(folder: str, expected: int | None, current: int) -> None:
    if expected and current and int(expected) != current:
        raise StaleUidError(
            f"Folder {folder!r} was renumbered by the server (uidvalidity "
            f"{expected} -> {current}). Search again to get current UIDs."
        )


# -----------------------------------------------------------------------------
# Search
# -----------------------------------------------------------------------------

def _imap_date(value: str) -> date:
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise ImapError(f"Invalid date {value!r}; use YYYY-MM-DD.") from exc


def build_criteria(
    *,
    text: str = "",
    from_: str = "",
    to: str = "",
    subject: str = "",
    body: str = "",
    since: str = "",
    before: str = "",
    unseen: bool | None = None,
    flagged: bool | None = None,
    answered: bool | None = None,
    larger_than_kb: int = 0,
) -> list[Any]:
    """Translate keyword arguments into an imapclient search criteria list.

    All terms are combined with AND. IMAP dates are whole days: `since` is
    inclusive and `before` is exclusive.
    """
    criteria: list[Any] = []
    if text:
        criteria += ["TEXT", text]
    if from_:
        criteria += ["FROM", from_]
    if to:
        criteria += ["TO", to]
    if subject:
        criteria += ["SUBJECT", subject]
    if body:
        criteria += ["BODY", body]
    if since:
        criteria += ["SINCE", _imap_date(since)]
    if before:
        criteria += ["BEFORE", _imap_date(before)]
    if unseen is True:
        criteria.append("UNSEEN")
    elif unseen is False:
        criteria.append("SEEN")
    if flagged is True:
        criteria.append("FLAGGED")
    elif flagged is False:
        criteria.append("UNFLAGGED")
    if answered is True:
        criteria.append("ANSWERED")
    elif answered is False:
        criteria.append("UNANSWERED")
    if larger_than_kb:
        criteria += ["LARGER", int(larger_than_kb) * 1024]
    return criteria or ["ALL"]


def _needs_utf8(criteria: list[Any]) -> bool:
    return any(isinstance(c, str) and not c.isascii() for c in criteria)


_ONE_ARG = {"TEXT", "FROM", "TO", "CC", "SUBJECT", "BODY", "SINCE", "BEFORE", "LARGER"}
_HEADER_KEYS = {"FROM": "From", "TO": "To", "CC": "Cc", "SUBJECT": "Subject"}
# How many candidate messages the local filter may inspect when the server
# cannot search non-ASCII text itself.
LOCAL_FILTER_MAX = 5000


def _split_criteria(criteria: list[Any]) -> list[list[Any]]:
    """Group a flat criteria list into terms, e.g. [["FROM", "x"], ["UNSEEN"]]."""
    terms, i = [], 0
    while i < len(criteria):
        key = criteria[i]
        width = 3 if key == "HEADER" else 2 if key in _ONE_ARG else 1
        terms.append(list(criteria[i: i + width]))
        i += width
    return terms


def _uid_search(client: IMAPClient, criteria: list[Any]) -> tuple[list[int], str | None]:
    """Search, returning (uids, note). The note explains a local fallback."""
    if not _needs_utf8(criteria):
        return client.search(criteria), None
    try:
        return client.search(criteria, charset="UTF-8"), None
    except IMAPClientError as exc:
        rejection = _short(exc)

    # Fallback: run the ASCII part on the server and match non-ASCII header
    # terms (from, to, subject) locally on the fetched headers. Body text
    # cannot be matched this way without downloading every message.
    terms = _split_criteria(criteria)
    local = [t for t in terms if any(isinstance(v, str) and not v.isascii() for v in t[1:])]
    if any(t[0] not in _HEADER_KEYS for t in local):
        raise ImapError(
            "The server cannot search for non-ASCII text (å, ä, ö etc.) in the "
            f"message body ({rejection}). Search by sender or subject instead, "
            "or use an ASCII-only word."
        )
    server_criteria = [v for t in terms if t not in local for v in t] or ["ALL"]
    candidates = sorted(client.search(server_criteria), reverse=True)[:LOCAL_FILTER_MAX]
    if not candidates:
        return [], None
    fields = " ".join(sorted({_HEADER_KEYS[t[0]].upper() for t in local}))
    item = f"BODY.PEEK[HEADER.FIELDS ({fields})]".encode()
    key = f"BODY[HEADER.FIELDS ({fields})]".encode()
    parser = BytesHeaderParser(policy=policy.default)
    matched = []
    for start in range(0, len(candidates), 500):
        chunk = candidates[start: start + 500]
        for uid, entry in client.fetch(chunk, [item]).items():
            hdr = parser.parsebytes(entry.get(key, b"") or b"")
            if all(
                str(t[1]).casefold() in mail_parse.decode_header_value(hdr[_HEADER_KEYS[t[0]]]).casefold()
                for t in local
            ):
                matched.append(uid)
    note = (
        "The server does not support non-ASCII search, so sender/subject terms "
        f"were matched locally among the {len(candidates)} most recent candidates."
    )
    return matched, note


def _sort_key(row: dict[str, Any]) -> datetime:
    """Chronological key; ISO strings with different offsets do not sort as text."""
    try:
        return datetime.fromisoformat(row.get("date") or "")
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _flags_list(flags) -> list[str]:
    return [f.decode() if isinstance(f, bytes) else str(f) for f in (flags or ())]


def _summaries(client: IMAPClient, folder: str, uidvalidity: int, uids: list[int]) -> list[dict[str, Any]]:
    """Fetch header summaries for UIDs, newest first. Read-only by construction."""
    if not uids:
        return []
    items = [b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE", _HEADER_FIELDS]
    gmail = _is_gmail(client)
    if gmail:
        items += [b"X-GM-MSGID", b"X-GM-THRID", b"X-GM-LABELS"]
    data = client.fetch(uids, items)
    parser = BytesHeaderParser(policy=policy.default)
    rows = []
    for uid in uids:
        entry = data.get(uid)
        if not entry:
            continue
        hdr = parser.parsebytes(entry.get(_HEADER_KEY, b"") or b"")
        internal = entry.get(b"INTERNALDATE")
        flags = _flags_list(entry.get(b"FLAGS"))
        row: dict[str, Any] = {
            "folder": folder,
            "uid": uid,
            "uidvalidity": uidvalidity,
            "subject": mail_parse.decode_header_value(hdr["Subject"]),
            "from": mail_parse.parse_addresses(hdr["From"]),
            "to": mail_parse.parse_addresses(hdr["To"]),
            "cc": mail_parse.parse_addresses(hdr["Cc"]),
            "date": internal.isoformat() if isinstance(internal, datetime) else None,
            "date_header": mail_parse.header_date_iso(hdr["Date"]),
            "size_bytes": entry.get(b"RFC822.SIZE"),
            "flags": flags,
            "seen": "\\Seen" in flags,
            "flagged": "\\Flagged" in flags,
            "message_id": str(hdr["Message-ID"] or "").strip(),
            "is_reply": bool(hdr["In-Reply-To"]),
            "has_unsubscribe": bool(hdr["List-Unsubscribe"]),
        }
        if gmail:
            row["gmail_msgid"] = entry.get(b"X-GM-MSGID")
            row["gmail_thread_id"] = entry.get(b"X-GM-THRID")
            row["gmail_labels"] = _flags_list(entry.get(b"X-GM-LABELS"))
        rows.append(row)
    return rows


def search(
    account: accounts.Account,
    folder: str = "INBOX",
    criteria: list[Any] | None = None,
    limit: int = 25,
    offset: int = 0,
) -> dict[str, Any]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    with open_imap(account) as client:
        uidvalidity = _examine(client, folder)
        found, note = _uid_search(client, criteria or ["ALL"])
        uids = sorted(found, reverse=True)
        page = uids[offset: offset + limit]
        return {
            "search_note": note,
            "folder": folder,
            "uidvalidity": uidvalidity,
            "total": len(uids),
            "offset": offset,
            "returned": len(page),
            "next_offset": offset + limit if offset + limit < len(uids) else None,
            "messages": _summaries(client, folder, uidvalidity, page),
        }


# -----------------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------------

def get_raw_message(
    account: accounts.Account, folder: str, uid: int, uidvalidity: int | None = None
) -> tuple[bytes, list[str], int]:
    """Return (raw bytes, flags, uidvalidity) without changing any flag."""
    with open_imap(account) as client:
        return _fetch_raw(client, folder, uid, uidvalidity)


def _fetch_raw(client: IMAPClient, folder: str, uid: int, uidvalidity: int | None) -> tuple[bytes, list[str], int]:
    current = _examine(client, folder, uidvalidity)
    size = client.fetch([uid], [b"RFC822.SIZE"]).get(uid, {}).get(b"RFC822.SIZE")
    if size is None:
        raise ImapError(f"No message with uid {uid} in {folder!r}.")
    if size > MAX_MESSAGE_BYTES:
        raise ImapError(
            f"The message is {size / (1024 * 1024):.1f} MB, above the limit of "
            f"{MAX_MESSAGE_BYTES / (1024 * 1024):.1f} MB (IMAP_MAX_MESSAGE_MB)."
        )
    data = client.fetch([uid], [b"BODY.PEEK[]", b"FLAGS"]).get(uid, {})
    raw = data.get(b"BODY[]")
    if raw is None:
        raise ImapError(f"The server returned no content for uid {uid}.")
    return raw, _flags_list(data.get(b"FLAGS")), current


def get_message(
    account: accounts.Account, folder: str, uid: int, uidvalidity: int | None = None
) -> tuple[mail_parse.ParsedMessage, list[str], int]:
    raw, flags, current = get_raw_message(account, folder, uid, uidvalidity)
    return mail_parse.parse_message(raw), flags, current


def find_thread(
    account: accounts.Account, folder: str, uid: int, uidvalidity: int | None = None, limit: int = 50
) -> dict[str, Any]:
    """Best-effort conversation lookup.

    Gmail exposes a real thread id (X-GM-THRID) that is searched in All Mail.
    Other servers are searched by Message-ID and References in the given
    folder and in Sent. THREAD (RFC 5256) is rarely implemented consistently
    enough to rely on.
    """
    limit = max(1, min(int(limit), 200))
    with open_imap(account) as client:
        current = _examine(client, folder, uidvalidity)
        data = client.fetch([uid], [_HEADER_FIELDS, b"BODY.PEEK[HEADER.FIELDS (REFERENCES)]"]).get(uid)
        if not data:
            raise ImapError(f"No message with uid {uid} in {folder!r}.")

        if _is_gmail(client):
            thrid = client.fetch([uid], [b"X-GM-THRID"]).get(uid, {}).get(b"X-GM-THRID")
            if thrid is None:
                raise ImapError("The server did not return a Gmail thread id for this message.")
            all_mail = client.find_special_folder(b"\\All") or folder
            all_validity = _examine(client, all_mail)
            uids = sorted(client.search(["X-GM-THRID", thrid]))[-limit:]
            messages = _summaries(client, all_mail, all_validity, uids)
            messages.sort(key=_sort_key)
            return {"method": "gmail_thread_id", "messages": messages}

        parser = BytesHeaderParser(policy=policy.default)
        hdr = parser.parsebytes(data.get(_HEADER_KEY, b"") or b"")
        refs_hdr = parser.parsebytes(data.get(b"BODY[HEADER.FIELDS (REFERENCES)]", b"") or b"")
        ids = set(str(refs_hdr["References"] or "").split())
        for value in (hdr["Message-ID"], hdr["In-Reply-To"]):
            if value:
                ids.add(str(value).strip())
        ids = {i for i in ids if i}

        # Search the message's own folder, the inbox and Sent, so a thread
        # is found whichever side of the conversation the call starts from.
        folders = [folder]
        for name in ("INBOX", special_folder(client, account, "sent")):
            if name and name not in folders:
                folders.append(name)

        found: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for name in folders:
            # Re-open the folder even when it is the original one: the
            # previous loop iteration may have examined Sent.
            validity = _examine(client, name)
            hits: set[int] = set()
            # Sorted so repeated calls search the same ids; non-ASCII ids are
            # invalid per RFC 5322 and cannot be sent as plain search atoms.
            for mid in sorted(i for i in ids if i.isascii())[:30]:
                hits.update(client.search(["HEADER", "Message-ID", mid]))
                hits.update(client.search(["HEADER", "References", mid]))
            for row in _summaries(client, name, validity, sorted(hits)[-limit:]):
                key = row["message_id"] or f"{name}:{row['uid']}"
                if key not in seen_ids:
                    seen_ids.add(key)
                    found.append(row)
        found.sort(key=_sort_key)
        return {"method": "message_id_references", "folders_searched": folders, "messages": found[-limit:]}


# -----------------------------------------------------------------------------
# Analysis
# -----------------------------------------------------------------------------

def mailbox_stats(
    account: accounts.Account, folder: str = "INBOX", days: int = 30, max_messages: int = 2000, top: int = 15
) -> dict[str, Any]:
    """Aggregate header-only statistics for a bounded window of a folder."""
    days = max(1, min(int(days), 3650))
    max_messages = max(1, min(int(max_messages), 10000))
    top = max(1, min(int(top), 100))
    since = (datetime.now(timezone.utc) - timedelta(days=days)).date()
    with open_imap(account) as client:
        uidvalidity = _examine(client, folder)
        all_uids = sorted(client.search(["SINCE", since]), reverse=True)
        uids = all_uids[:max_messages]
        senders: Counter[str] = Counter()
        domains: Counter[str] = Counter()
        per_day: Counter[str] = Counter()
        unread = flagged = newsletters = total_size = 0
        largest: list[tuple[int, int]] = []
        parser = BytesHeaderParser(policy=policy.default)
        for start in range(0, len(uids), 500):
            chunk = uids[start: start + 500]
            data = client.fetch(chunk, [b"FLAGS", b"INTERNALDATE", b"RFC822.SIZE",
                                        b"BODY.PEEK[HEADER.FIELDS (FROM LIST-UNSUBSCRIBE)]"])
            for uid, entry in data.items():
                hdr = parser.parsebytes(entry.get(b"BODY[HEADER.FIELDS (FROM LIST-UNSUBSCRIBE)]", b"") or b"")
                addrs = mail_parse.parse_addresses(hdr["From"])
                if addrs:
                    addr = addrs[0]["email"].lower()
                    senders[addr] += 1
                    domains[addr.rsplit("@", 1)[-1]] += 1
                flags = _flags_list(entry.get(b"FLAGS"))
                unread += "\\Seen" not in flags
                flagged += "\\Flagged" in flags
                newsletters += bool(hdr["List-Unsubscribe"])
                size = int(entry.get(b"RFC822.SIZE") or 0)
                total_size += size
                largest.append((size, uid))
                internal = entry.get(b"INTERNALDATE")
                if isinstance(internal, datetime):
                    per_day[internal.date().isoformat()] += 1
        largest.sort(reverse=True)
        return {
            "folder": folder,
            "uidvalidity": uidvalidity,
            "window_days": days,
            "since": since.isoformat(),
            "messages_in_window": len(all_uids),
            "messages_analysed": len(uids),
            "sample_note": (
                f"Only the {len(uids)} most recent messages were analysed."
                if len(uids) < len(all_uids) else "All messages in the window were analysed."
            ),
            "unread": unread,
            "flagged": flagged,
            "with_list_unsubscribe": newsletters,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "top_senders": [{"email": k, "count": v} for k, v in senders.most_common(top)],
            "top_domains": [{"domain": k, "count": v} for k, v in domains.most_common(top)],
            "per_day": dict(sorted(per_day.items())),
            "largest": [{"uid": u, "size_bytes": s} for s, u in largest[:10]],
        }


# -----------------------------------------------------------------------------
# Organising (the only functions that change anything)
# -----------------------------------------------------------------------------

def _check_bulk(uids: list[int]) -> list[int]:
    clean = sorted({int(u) for u in uids})
    if not clean:
        raise ImapError("No UIDs given.")
    if len(clean) > MAX_BULK:
        raise ImapError(f"At most {MAX_BULK} messages per call (IMAP_MAX_BULK); got {len(clean)}.")
    return clean


def set_flags(
    account: accounts.Account,
    folder: str,
    uids: list[int],
    add: list[str] | None = None,
    remove: list[str] | None = None,
    uidvalidity: int | None = None,
) -> dict[str, Any]:
    def to_flags(names: list[str] | None) -> list[bytes]:
        out = []
        for name in names or []:
            key = name.strip().lower().lstrip("\\")
            if key in _FLAG_NAMES:
                out.append(_FLAG_NAMES[key])
            elif name.strip().startswith("\\"):
                # A backslash marks a system flag; only the ones above are
                # allowed. \Deleted in particular would let any client's
                # EXPUNGE erase the message, which this tool never offers.
                raise ImapError(f"Invalid flag or keyword: {name!r}")
            elif key and all(ch.isalnum() or ch in "-_$" for ch in key):
                out.append(name.strip().encode())  # user keyword such as $Label1
            else:
                raise ImapError(f"Invalid flag or keyword: {name!r}")
        return out

    uids = _check_bulk(uids)
    add_flags, remove_flags = to_flags(add), to_flags(remove)
    if not add_flags and not remove_flags:
        raise ImapError("Nothing to change: give flags to add or remove.")
    with open_imap(account) as client:
        current = _select_rw(client, folder, uidvalidity)
        if add_flags:
            client.add_flags(uids, add_flags, silent=True)
        if remove_flags:
            client.remove_flags(uids, remove_flags, silent=True)
        flags = client.fetch(uids, [b"FLAGS"])
        return {
            "folder": folder,
            "uidvalidity": current,
            "updated": [{"uid": u, "flags": _flags_list(flags.get(u, {}).get(b"FLAGS"))} for u in uids],
        }


def move_messages(
    account: accounts.Account,
    folder: str,
    uids: list[int],
    destination: str,
    copy: bool = False,
    uidvalidity: int | None = None,
) -> dict[str, Any]:
    uids = _check_bulk(uids)
    if destination == folder:
        raise ImapError("Source and destination folder are the same.")
    with open_imap(account) as client:
        if not client.folder_exists(destination):
            raise ImapError(f"Destination folder {destination!r} does not exist.")
        current = _select_rw(client, folder, uidvalidity)
        existing = set(client.fetch(uids, [b"FLAGS"]).keys())
        missing = [u for u in uids if u not in existing]
        targets = [u for u in uids if u in existing]
        if targets:
            if copy:
                client.copy(targets, destination)
            else:
                # imapclient.move uses MOVE (RFC 6851) when advertised and
                # raises otherwise, so the COPY + \Deleted + UID EXPUNGE
                # fallback below stays limited to exactly these UIDs.
                if client.has_capability("MOVE"):
                    client.move(targets, destination)
                elif client.has_capability("UIDPLUS"):
                    client.copy(targets, destination)
                    client.add_flags(targets, [b"\\Deleted"], silent=True)
                    client.uid_expunge(targets)
                else:
                    raise ImapError(
                        "The server supports neither MOVE nor UIDPLUS, so moving "
                        "cannot be done without risking other deleted messages. "
                        "Use copy=true instead."
                    )
        return {
            "folder": folder,
            "uidvalidity": current,
            "destination": destination,
            "operation": "copy" if copy else "move",
            "count": len(targets),
            "not_found": missing,
        }


def trash_messages(
    account: accounts.Account, folder: str, uids: list[int], uidvalidity: int | None = None
) -> dict[str, Any]:
    """Move messages to Trash. Permanent deletion is deliberately not offered."""
    with open_imap(account) as client:
        trash = special_folder(client, account, "trash")
    if not trash:
        raise ImapError(
            "No Trash folder found. Set one for this account in the settings, "
            "or move the messages to a folder of your choice."
        )
    if trash == folder:
        raise ImapError(
            "The messages are already in Trash. Permanent deletion is not "
            "available through this tool; empty the trash in your mail client."
        )
    result = move_messages(account, folder, uids, trash, copy=False, uidvalidity=uidvalidity)
    result["operation"] = "trash"
    return result


def create_folder(account: accounts.Account, name: str) -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ImapError("Folder name is empty.")
    with open_imap(account) as client:
        if client.folder_exists(name):
            return {"name": name, "created": False, "note": "Folder already exists."}
        client.create_folder(name)
        try:
            client.subscribe_folder(name)
        except IMAPClientError:
            pass  # subscription is a convenience for other clients only
        return {"name": name, "created": True}


@contextmanager
def messages_for_saving(
    account: accounts.Account, folder: str, uids: list[int], uidvalidity: int
) -> Iterator[tuple[bool, Iterator[tuple[int, bytes, datetime | None]]]]:
    """Messages to save attachments from: (folder is junk, iterator of (uid, raw, arrival time)).

    Read-only like every other read: EXAMINE and BODY.PEEK. Messages above
    the size limit are left out; the caller reports which UIDs were missing.
    Each message is fetched when the iterator reaches it, so only one is
    held in memory at a time; the connection stays open until the block ends.
    """
    uids = _check_bulk(uids)
    with open_imap(account) as client:
        junk = folder == special_folder(client, account, "junk")
        _examine(client, folder, uidvalidity)
        sizes = client.fetch(uids, [b"RFC822.SIZE", b"INTERNALDATE"])
        wanted = [u for u in uids if u in sizes and (sizes[u].get(b"RFC822.SIZE") or 0) <= MAX_MESSAGE_BYTES]

        def rows() -> Iterator[tuple[int, bytes, datetime | None]]:
            for uid in wanted:
                raw = client.fetch([uid], [b"BODY.PEEK[]"]).get(uid, {}).get(b"BODY[]")
                if raw is not None:
                    internal = sizes[uid].get(b"INTERNALDATE")
                    yield uid, raw, internal if isinstance(internal, datetime) else None

        yield junk, rows()


def append_message(account: accounts.Account, kind: str, raw: bytes, flags: list[bytes]) -> str:
    """Append a message to the Sent or Drafts folder and return the folder name."""
    with open_imap(account) as client:
        folder = special_folder(client, account, kind)
        if not folder:
            raise ImapError(
                f"No {kind.capitalize()} folder found. Set one for this account in the settings."
            )
        client.append(folder, raw, flags=flags)
        return folder


def append_draft(account: accounts.Account, raw: bytes, message_id: str) -> dict[str, Any]:
    """Append a draft and return where it landed: {folder, uid, uidvalidity}.

    The new UID is found by searching for the draft's Message-ID, which
    works on every server; APPENDUID (UIDPLUS) is not universal. uid is
    None if the server does not find it straight away.
    """
    with open_imap(account) as client:
        folder = special_folder(client, account, "drafts")
        if not folder:
            raise ImapError("No Drafts folder found. Set one for this account in the settings.")
        client.append(folder, raw, flags=[b"\\Draft", b"\\Seen"])
        validity = _examine(client, folder)
        uid = None
        if message_id and message_id.isascii():
            hits = client.search(["HEADER", "Message-ID", message_id.strip()])
            uid = max(hits) if hits else None
        return {"folder": folder, "uid": uid, "uidvalidity": validity}


def retire_own_draft(account: accounts.Account, folder: str, uid: int, uidvalidity: int) -> bool:
    """Move a draft that has been replaced or sent to Trash. Returns whether it moved.

    Deliberately narrow: only from the account's Drafts folder, only a
    message flagged \\Draft, only that UID, pinned to the folder's
    uidvalidity. It goes to Trash rather than being deleted, so an edit can
    always be undone in any mail client. Without a Trash folder, or on a
    server that can move neither with MOVE nor with UIDPLUS, the old draft
    stays where it is and the caller says so.
    """
    with open_imap(account) as client:
        drafts = special_folder(client, account, "drafts")
        trash = special_folder(client, account, "trash")
        if folder != drafts or not trash or trash == drafts:
            return False
        _select_rw(client, folder, uidvalidity)
        flags = _flags_list(client.fetch([uid], [b"FLAGS"]).get(uid, {}).get(b"FLAGS"))
        if "\\Draft" not in flags:
            return False
        if client.has_capability("MOVE"):
            client.move([uid], trash)
        elif client.has_capability("UIDPLUS"):
            client.copy([uid], trash)
            client.add_flags([uid], [b"\\Deleted"], silent=True)
            client.uid_expunge([uid])
        else:
            return False
        return True


# Providers whose SMTP service files a copy in Sent on its own, so an
# IMAP APPEND would create a duplicate.
_SELF_FILING_HOSTS = ("outlook.office365.com", "imap-mail.outlook.com", "outlook.com")


def server_files_sent_mail(account: accounts.Account) -> bool:
    """True when the server stores sent mail itself (Gmail, Microsoft)."""
    host = account.imap_host.lower()
    if any(host == h or host.endswith("." + h) for h in _SELF_FILING_HOSTS):
        return True
    with open_imap(account) as client:
        return _is_gmail(client)
